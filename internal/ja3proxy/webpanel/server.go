package webpanel

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/lylemi/ja3proxy/internal/ja3proxy/audit"
	"github.com/lylemi/ja3proxy/internal/ja3proxy/device"
	"github.com/lylemi/ja3proxy/internal/ja3proxy/logutil"
	"github.com/lylemi/ja3proxy/internal/ja3proxy/recorder"
	"github.com/lylemi/ja3proxy/internal/ja3proxy/routing"
	"github.com/lylemi/ja3proxy/internal/ja3proxy/secrets"
	"github.com/lylemi/ja3proxy/internal/ja3proxy/tlsprofile"
	"github.com/lylemi/ja3proxy/internal/ja3proxy/traffic"
	"github.com/lylemi/ja3proxy/internal/ja3proxy/upstreamtls"
)

var ErrConfigVersionConflict = errors.New("runtime configuration version conflict")

//go:embed static
var staticFiles embed.FS

type RuntimeStatus struct {
	ConfigVersion                  uint64     `json:"configVersion"`
	ProxyListen                    string     `json:"proxyListen"`
	ProxyPort                      int        `json:"proxyPort"`
	ProxyProtocol                  string     `json:"proxyProtocol"`
	TLSClient                      string     `json:"tlsClient"`
	TLSVersion                     string     `json:"tlsVersion"`
	TLSFingerprints                []string   `json:"tlsFingerprints"`
	Upstream                       string     `json:"upstream"`
	UpstreamEnabled                bool       `json:"upstreamEnabled"`
	ProxyAuthEnabled               bool       `json:"proxyAuthEnabled"`
	ProxyUsername                  string     `json:"proxyUsername"`
	MITMCACertificateStatus        string     `json:"mitmCaCertificateStatus,omitempty"`
	MITMCACertificateSubject       string     `json:"mitmCaCertificateSubject,omitempty"`
	MITMCACertificateSHA256        string     `json:"mitmCaCertificateSHA256,omitempty"`
	MITMCACertificateNotBefore     *time.Time `json:"mitmCaCertificateNotBefore,omitempty"`
	MITMCACertificateNotAfter      *time.Time `json:"mitmCaCertificateNotAfter,omitempty"`
	MITMCACertificateDaysRemaining *int64     `json:"mitmCaCertificateDaysRemaining,omitempty"`
	PanelCertificateStatus         string     `json:"panelCertificateStatus,omitempty"`
	PanelCertificateNotBefore      *time.Time `json:"panelCertificateNotBefore,omitempty"`
	PanelCertificateNotAfter       *time.Time `json:"panelCertificateNotAfter,omitempty"`
	PanelCertificateDaysRemaining  *int64     `json:"panelCertificateDaysRemaining,omitempty"`
	ConfigurationMode              string     `json:"configurationMode"`
	Chain                          []ChainHop `json:"chain"`
}

type ChainHop struct {
	Role    string `json:"role"`
	Address string `json:"address"`
}

type ConfigUpdate struct {
	ExpectedVersion  *uint64 `json:"expected_version"`
	TLSFingerprint   *string `json:"tlsFingerprint"`
	Upstream         *string `json:"upstream"`
	ProxyPort        *int    `json:"proxyPort"`
	ProxyProtocol    *string `json:"proxyProtocol"`
	ProxyAuthEnabled *bool   `json:"proxyAuthEnabled"`
	ProxyUsername    *string `json:"proxyUsername"`
	ProxyPassword    *string `json:"proxyPassword"`
}

type RuntimeProvider func() RuntimeStatus
type ConfigUpdater func(ConfigUpdate) (RuntimeStatus, error)

type Server struct {
	Recorder        *recorder.Recorder
	Audit           *audit.Store
	AuthToken       string
	AuthScopes      []string
	AuthTokenExpiry time.Time
	AuthTokens      []AuthToken
	TokenRegistry   *TokenRegistry
	TLSCertFile     string
	TLSKeyFile      string
	SecretProvider  secrets.Provider
	Devices         *device.Store
	Profiles        *tlsprofile.Store
	Routes          *routing.Store
	UpstreamTLS     *upstreamtls.UpstreamTLSProfileStore
	Address         string
	Monitor         *traffic.TrafficMonitor
	Runtime         RuntimeProvider
	Update          ConfigUpdater
	ReloadCA        func() (RuntimeStatus, error)
	CACertificate   func() *x509.Certificate
}

type stateResponse struct {
	Runtime RuntimeStatus           `json:"runtime"`
	Traffic traffic.TrafficSnapshot `json:"traffic"`
}

const (
	panelSessionLimit = 40
	panelEventLimit   = 10
)

func (panel Server) Serve(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	listener, err := net.Listen("tcp", panel.Address)
	if err != nil {
		return fmt.Errorf("listen for web panel on %s: %w", panel.Address, err)
	}
	addr, ok := listener.Addr().(*net.TCPAddr)
	loopback := ok && addr.IP.IsLoopback()
	if !loopback {
		if len(panel.authTokens()) == 0 {
			listener.Close()
			return fmt.Errorf("non-loopback web panel requires bearer authentication")
		}
		if panel.TLSCertFile == "" || panel.TLSKeyFile == "" {
			listener.Close()
			return fmt.Errorf("non-loopback web panel requires HTTPS certificate and key")
		}
	}
	if (panel.TLSCertFile == "") != (panel.TLSKeyFile == "") {
		listener.Close()
		return fmt.Errorf("web panel HTTPS certificate and key must be configured together")
	}
	server := &http.Server{
		Handler:           panel.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       30 * time.Second,
	}
	logutil.Info("webpanel", "web panel listening", "addr", listener.Addr().String())

	stopClosingServer := context.AfterFunc(ctx, func() {
		_ = server.Close()
	})
	defer stopClosingServer()

	serve := server.Serve
	if panel.TLSCertFile != "" {
		server.TLSConfig = panel.tlsConfig()
		serve = func(listener net.Listener) error {
			return server.ServeTLS(listener, "", "")
		}
	}
	if err := serve(listener); err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil && (errors.Is(err, http.ErrServerClosed) || errors.Is(err, net.ErrClosed)) {
			return ctxErr
		}
		return fmt.Errorf("serve web panel: %w", err)
	}
	return nil
}

func (panel Server) tlsConfig() *tls.Config {
	return &tls.Config{GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
		certificate, err := secrets.LoadKeyPair(panel.SecretProvider, panel.TLSCertFile, panel.TLSKeyFile)
		if err != nil {
			return nil, err
		}
		return &certificate, nil
	}}
}

func (panel Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/state", panel.handleState)
	mux.HandleFunc("PUT /api/config", panel.handleConfigUpdate)
	mux.HandleFunc("GET /api/v1/admin/tokens", panel.handleTokenList)
	mux.HandleFunc("POST /api/v1/admin/tokens", panel.handleTokenIssue)
	mux.HandleFunc("PUT /api/v1/admin/tokens/{id}", panel.handleTokenUpdate)
	mux.HandleFunc("DELETE /api/v1/admin/tokens/{id}", panel.handleTokenRevoke)
	mux.HandleFunc("POST /api/v1/admin/tokens/{id}/rotate", panel.handleTokenRotate)
	mux.HandleFunc("POST /api/v1/admin/ca/reload", panel.handleCAReload)
	mux.HandleFunc("GET /api/v1/ca/certificate", panel.handleCACertificate)
	mux.HandleFunc("POST /api/v1/admin/spool/reload-key", panel.handleSpoolKeyReload)
	mux.Handle("GET /api/v1/export/config", recorderLocalOnly(http.HandlerFunc(panel.exportConfig)))
	mux.Handle("GET /api/v1/export/telemetry", recorderLocalOnly(http.HandlerFunc(panel.exportTelemetry)))
	mux.Handle("POST /api/v1/import/telemetry", recorderLocalOnly(http.HandlerFunc(panel.importTelemetry)))
	mux.Handle("GET /api/v1/audit", recorderLocalOnly(http.HandlerFunc(panel.auditEvents)))
	mux.Handle("POST /api/v1/import/config/validate", recorderLocalOnly(http.HandlerFunc(panel.validateConfigImport)))
	mux.Handle("POST /api/v1/import/config", recorderLocalOnly(http.HandlerFunc(panel.importConfig)))
	panel.registerRecorderRoutes(mux)
	panel.registerProfileRoutes(mux)

	staticRoot, err := fs.Sub(staticFiles, "static")
	if err != nil {
		panic(fmt.Sprintf("load embedded web panel: %v", err))
	}
	mux.Handle("GET /", http.FileServer(http.FS(staticRoot)))
	if panel.localOnly() {
		return securityHeaders(panel.tokenAuth(panel.auditRequests(recorderLocalOnly(mux))))
	}
	return securityHeaders(panel.tokenAuth(panel.auditRequests(mux)))
}

func (panel Server) requiresLocalAccess() bool {
	return panel.Recorder != nil || panel.Audit != nil || panel.Devices != nil || panel.Profiles != nil || panel.Routes != nil || panel.UpstreamTLS != nil
}

func (panel Server) localOnly() bool {
	return panel.requiresLocalAccess() && !panel.remoteAccessConfigured()
}

func (panel Server) remoteAccessConfigured() bool {
	return strings.TrimSpace(panel.Address) != "" && len(panel.authTokens()) > 0 && panel.TLSCertFile != "" && panel.TLSKeyFile != ""
}

func (panel Server) handleConfigUpdate(response http.ResponseWriter, request *http.Request) {
	response.Header().Set("Cache-Control", "no-store")
	response.Header().Set("Content-Type", "application/json; charset=utf-8")
	if panel.Update == nil {
		writeAPIError(response, http.StatusNotImplemented, "runtime configuration is unavailable")
		return
	}
	if contentType := request.Header.Get("Content-Type"); !strings.HasPrefix(strings.ToLower(contentType), "application/json") {
		writeAPIError(response, http.StatusUnsupportedMediaType, "Content-Type must be application/json")
		return
	}

	request.Body = http.MaxBytesReader(response, request.Body, 16<<10)
	decoder := json.NewDecoder(request.Body)
	decoder.DisallowUnknownFields()
	var update ConfigUpdate
	if err := decoder.Decode(&update); err != nil {
		writeAPIError(response, http.StatusBadRequest, fmt.Sprintf("invalid configuration: %v", err))
		return
	}
	if update.ExpectedVersion == nil {
		writeAPIError(response, http.StatusBadRequest, "expected_version is required")
		return
	}
	if update.TLSFingerprint == nil && update.Upstream == nil && update.ProxyPort == nil && update.ProxyProtocol == nil && update.ProxyAuthEnabled == nil && update.ProxyUsername == nil && update.ProxyPassword == nil {
		writeAPIError(response, http.StatusBadRequest, "no configuration fields were provided")
		return
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		writeAPIError(response, http.StatusBadRequest, "request must contain one JSON object")
		return
	}

	runtimeStatus, err := panel.Update(update)
	if err != nil {
		status := http.StatusBadRequest
		if errors.Is(err, ErrConfigVersionConflict) {
			status = http.StatusConflict
		}
		writeAPIError(response, status, err.Error())
		return
	}
	if err := json.NewEncoder(response).Encode(struct {
		Runtime RuntimeStatus `json:"runtime"`
	}{Runtime: runtimeStatus}); err != nil {
		logutil.Warn("webpanel", "failed writing config response", "error", err)
	}
}

func writeAPIError(response http.ResponseWriter, status int, message string) {
	response.WriteHeader(status)
	_ = json.NewEncoder(response).Encode(struct {
		Error string `json:"error"`
	}{Error: message})
}

func (panel Server) handleState(response http.ResponseWriter, _ *http.Request) {
	response.Header().Set("Cache-Control", "no-store")
	response.Header().Set("Content-Type", "application/json; charset=utf-8")

	runtimeStatus := RuntimeStatus{}
	if panel.Runtime != nil {
		runtimeStatus = panel.Runtime()
	}
	snapshot := panel.Monitor.Snapshot()
	compactPanelSnapshot(&snapshot)
	if err := json.NewEncoder(response).Encode(stateResponse{
		Runtime: runtimeStatus,
		Traffic: snapshot,
	}); err != nil {
		logutil.Warn("webpanel", "failed writing panel state", "error", err)
	}
}

func compactPanelSnapshot(snapshot *traffic.TrafficSnapshot) {
	if snapshot == nil {
		return
	}

	sessions := make([]traffic.TrafficSessionSnapshot, 0, panelSessionLimit*3)
	allCount := 0
	activeCount := 0
	failedCount := 0
	for _, session := range snapshot.Sessions {
		include := allCount < panelSessionLimit
		if allCount < panelSessionLimit {
			allCount++
		}
		if session.State == traffic.StateActive && activeCount < panelSessionLimit {
			activeCount++
			include = true
		}
		if session.State == traffic.StateFailed && failedCount < panelSessionLimit {
			failedCount++
			include = true
		}
		if include {
			sessions = append(sessions, session)
		}
		if allCount == panelSessionLimit && activeCount == panelSessionLimit && failedCount == panelSessionLimit {
			break
		}
	}
	snapshot.Sessions = sessions

	if len(snapshot.Events) > panelEventLimit {
		snapshot.Events = snapshot.Events[len(snapshot.Events)-panelEventLimit:]
	}
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("Content-Security-Policy", "default-src 'self'; connect-src 'self'; img-src 'self'; style-src 'self'; script-src 'self'; base-uri 'none'; frame-ancestors 'none'")
		response.Header().Set("Referrer-Policy", "no-referrer")
		response.Header().Set("X-Content-Type-Options", "nosniff")
		response.Header().Set("X-Frame-Options", "DENY")
		next.ServeHTTP(response, request)
	})
}
