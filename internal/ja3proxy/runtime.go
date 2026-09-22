package ja3proxy

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	cflog "github.com/cloudflare/cfssl/log"
	"github.com/lylemi/ja3proxy/internal/ja3proxy/certstore"
	"github.com/lylemi/ja3proxy/internal/ja3proxy/dialer"
	"github.com/lylemi/ja3proxy/internal/ja3proxy/fingerprint"
	"github.com/lylemi/ja3proxy/internal/ja3proxy/logutil"
	httpproxy "github.com/lylemi/ja3proxy/internal/ja3proxy/proxy"
	"github.com/lylemi/ja3proxy/internal/ja3proxy/recorder"
	"github.com/lylemi/ja3proxy/internal/ja3proxy/tlsprofile"
	"github.com/lylemi/ja3proxy/internal/ja3proxy/traffic"
	"github.com/lylemi/ja3proxy/internal/ja3proxy/tui"
	"github.com/lylemi/ja3proxy/internal/ja3proxy/tunnel"
	"github.com/lylemi/ja3proxy/internal/ja3proxy/upstreamtls"
	"github.com/lylemi/ja3proxy/internal/ja3proxy/webpanel"
)

type App struct {
	Recorder            *recorder.Recorder
	TLSProfiles         *tlsprofile.Store
	Config              *RunningConfig
	CA                  *certstore.CertificateAuthority
	SessionKey          *certstore.SessionKeyHelper
	TLSFingerprints     *fingerprint.TLSFingerprintStore
	UpstreamTLSProfiles *upstreamtls.UpstreamTLSProfileStore
	TrafficMonitor      *traffic.TrafficMonitor
	UpstreamDialer      *dialer.DynamicUpstreamDialer
	ProxyServer         *httpproxy.Proxy
	proxyListener       *rebindableListener
	protocolListener    *httpproxy.MixedProxyListener
	configMu            sync.Mutex

	watchFingerprintFile func(context.Context, string, time.Duration) error
}

// Run executes JA3Proxy using the current process arguments.
func Run() error {
	return newDefaultApp().run()
}

func newDefaultApp() *App {
	return &App{
		Config:              &RunningConfig{},
		CA:                  &certstore.CertificateAuthority{},
		SessionKey:          &certstore.SessionKeyHelper{},
		TLSFingerprints:     &fingerprint.TLSFingerprintStore{},
		UpstreamTLSProfiles: &upstreamtls.UpstreamTLSProfileStore{},
	}
}

func (app *App) run() error {
	return app.runWithContext(context.Background())
}

func (app *App) runWithContext(ctx context.Context) error {
	ctx = runtimeContext(ctx)
	if err := app.parseFlags(os.Args[1:]); err != nil {
		return err
	}
	if app.Config.ListFingerprints {
		fmt.Print(fingerprint.FormatCatalog())
		return nil
	}

	if err := app.configureRuntime(ctx); err != nil {
		return err
	}
	defer func() {
		if app.Recorder != nil {
			if err := app.Recorder.Close(); err != nil {
				logutil.Warn("recorder", "recording output incomplete")
			}
		}
	}()
	proxyServer, err := app.buildProxy()
	if err != nil {
		return err
	}
	return app.serveConfiguredProxy(ctx, proxyServer)
}

func (app *App) configureRuntime(ctx context.Context) error {
	app.configureLogging()
	if err := app.ensureCA(); err != nil {
		return err
	}
	if err := app.loadExistingCA(); err != nil {
		return fmt.Errorf("failed loading CA: %w", err)
	}
	if err := app.generateSessionKey(); err != nil {
		return fmt.Errorf("failed generating session key: %w", err)
	}
	if err := app.configureTLSFingerprint(ctx); err != nil {
		return err
	}
	if err := app.configureUpstreamTLSProfiles(); err != nil {
		return err
	}
	app.ensureTrafficMonitor()
	if app.TLSProfiles == nil {
		var err error
		app.TLSProfiles, err = tlsprofile.Open(app.Config.TLSTemplateFile)
		if err != nil {
			return fmt.Errorf("configure TLS profile library: %w", err)
		}
	}
	if app.Config.CaptureTLS && app.Recorder == nil {
		var err error
		app.Recorder, err = recorder.New(recorder.Options{Raw: app.Config.CaptureRaw, JSONLPath: app.Config.CaptureJSONL})
		if err != nil {
			return fmt.Errorf("configure recorder: %w", err)
		}
	}
	return nil
}

func (app *App) ensureTrafficMonitor() {
	if (app.Config.TUI || app.Config.WebPanel != "") && app.TrafficMonitor == nil {
		app.TrafficMonitor = traffic.NewTrafficMonitor()
	}
}

func (app *App) serveConfiguredProxy(ctx context.Context, proxyServer *httpproxy.Proxy) error {
	if app.Config.TUI {
		return app.serveWithTUI(ctx, proxyServer)
	}
	return app.serveProxyServices(ctx, proxyServer)
}

func (app *App) serveWithTUI(ctx context.Context, proxyServer *httpproxy.Proxy) error {
	return tui.Run(ctx, tui.Config{
		ListenAddress: app.Config.listenAddress(),
		TLSClient:     app.Config.TLSClient,
		TLSVersion:    app.Config.TLSVersion,
	}, app.TrafficMonitor, func(runCtx context.Context) error {
		return app.serveProxyServices(runCtx, proxyServer)
	})
}

func (app *App) serveProxyServices(ctx context.Context, proxyServer *httpproxy.Proxy) error {
	if app.Config.WebPanel == "" {
		return app.serve(ctx, proxyServer)
	}

	panel := webpanel.Server{
		Recorder: app.Recorder,
		Profiles: app.TLSProfiles,
		Address:  app.Config.WebPanel,
		Monitor:  app.TrafficMonitor,
		Runtime:  app.webPanelRuntimeStatus,
		Update:   app.updateProxyConfig,
	}
	return runServices(ctx, app.serveService(proxyServer), panel.Serve)
}

type runtimeService func(context.Context) error

func (app *App) serveService(proxyServer *httpproxy.Proxy) runtimeService {
	return func(ctx context.Context) error {
		return app.serve(ctx, proxyServer)
	}
}

func runServices(ctx context.Context, services ...runtimeService) error {
	ctx = runtimeContext(ctx)
	if err := ctx.Err(); err != nil {
		return err
	}

	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	errCh := make(chan error, len(services))
	for _, service := range services {
		go func(run runtimeService) {
			errCh <- run(runCtx)
		}(service)
	}

	firstErr := <-errCh
	cancel()
	for range len(services) - 1 {
		<-errCh
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return firstErr
}

func runtimeContext(ctx context.Context) context.Context {
	if ctx == nil {
		return context.Background()
	}
	return ctx
}

func (app *App) configureLogging() {
	level := logLevelFromName(app.Config.LogLevel)
	if app.Config.dumpTrafficEnabled() && level > slog.LevelDebug {
		level = slog.LevelDebug
	}
	cflog.Level = cflog.LevelWarning
	if level <= slog.LevelDebug {
		cflog.Level = cflog.LevelDebug
	}

	configureDefaultLogger(level)
}

func (app *App) ensureCA() error {
	if !fileExists(app.Config.Cert) || !fileExists(app.Config.Key) {
		if fileExists(app.Config.Cert) {
			return fmt.Errorf("found CA cert %q, but no corresponding key %q", app.Config.Cert, app.Config.Key)
		} else if fileExists(app.Config.Key) {
			return fmt.Errorf("found CA key %q, but no corresponding cert %q", app.Config.Key, app.Config.Cert)
		}

		logutil.Info(
			"runtime",
			"generating missing CA certificate and key",
			"cert", app.Config.Cert,
			"key", app.Config.Key,
		)
		if err := app.CA.Generate(app.Config.Cert, app.Config.Key); err != nil {
			return fmt.Errorf("failed generating CA: %w", err)
		}
	}
	return nil
}

func (app *App) loadExistingCA() error {
	return app.CA.Load(app.Config.Cert, app.Config.Key)
}

func (app *App) generateSessionKey() error {
	return app.SessionKey.Generate()
}

func (app *App) configureTLSFingerprint(ctx context.Context) error {
	if app.Config.FingerprintConfig != "" {
		if err := app.watchTLSFingerprintFile(runtimeContext(ctx), app.Config.FingerprintConfig, 2*time.Second); err != nil {
			return fmt.Errorf("failed loading fingerprint config: %w", err)
		}
	} else if err := app.TLSFingerprints.SetValidated(fingerprint.TLSFingerprint{
		Client:  app.Config.TLSClient,
		Version: app.Config.TLSVersion,
	}); err != nil {
		return fmt.Errorf("failed configuring TLS fingerprint: %w", err)
	}
	return nil
}

func (app *App) watchTLSFingerprintFile(ctx context.Context, path string, interval time.Duration) error {
	if app.watchFingerprintFile != nil {
		return app.watchFingerprintFile(ctx, path, interval)
	}
	return app.TLSFingerprints.WatchFile(ctx, path, interval)
}

func (app *App) configureUpstreamTLSProfiles() error {
	if app.Config.UpstreamTLSConfig == "" {
		return nil
	}
	if app.UpstreamTLSProfiles == nil {
		app.UpstreamTLSProfiles = &upstreamtls.UpstreamTLSProfileStore{}
	}
	if err := app.UpstreamTLSProfiles.ApplyFile(app.Config.UpstreamTLSConfig); err != nil {
		return fmt.Errorf("failed loading upstream TLS config: %w", err)
	}
	return nil
}

func (app *App) buildProxy() (*httpproxy.Proxy, error) {
	upstreamDialer, err := dialer.NewDynamicUpstreamDialer(app.Config.Upstream, time.Second*10)
	if err != nil {
		return nil, fmt.Errorf("configure upstream proxy: %w", err)
	}
	app.UpstreamDialer = upstreamDialer

	proxyServer := httpproxy.NewProxy(upstreamDialer.Dial, app.tunnelHandler().Connect, upstreamDialer).
		WithAuthentication(app.Config.ProxyUsername, app.Config.ProxyPassword).
		WithTLSInspection(app.Config.CaptureTLS || (app.Config.TLSMode != "" && app.Config.TLSMode != "MITM_REISSUE")).
		WithBlockedTunnels(app.Config.TLSMode == "BLOCK")
	app.ProxyServer = proxyServer
	if app.TrafficMonitor != nil {
		proxyServer.WithTrafficMonitor(app.TrafficMonitor)
	}
	return proxyServer, nil
}

func (app *App) updateProxyConfig(update webpanel.ConfigUpdate) (webpanel.RuntimeStatus, error) {
	app.configMu.Lock()
	defer app.configMu.Unlock()

	var nextFingerprint fingerprint.TLSFingerprint
	var nextListener net.Listener
	var nextListenAddress string
	nextProxyUsername, nextProxyPassword, updateProxyAuth, err := app.resolveProxyAuthUpdate(update)
	if err != nil {
		return webpanel.RuntimeStatus{}, err
	}
	if update.ProxyProtocol != nil {
		if app.protocolListener == nil {
			return webpanel.RuntimeStatus{}, fmt.Errorf("proxy protocol listener is unavailable")
		}
		if err := validateProxyProtocol(*update.ProxyProtocol); err != nil {
			return webpanel.RuntimeStatus{}, err
		}
	}
	if update.ProxyPort != nil {
		if *update.ProxyPort < 1 || *update.ProxyPort > 65535 {
			return webpanel.RuntimeStatus{}, fmt.Errorf("proxy port must be between 1 and 65535")
		}
		if app.proxyListener == nil {
			return webpanel.RuntimeStatus{}, fmt.Errorf("proxy listener is unavailable")
		}
		currentAddress := app.proxyListener.Addr().String()
		host, currentPort, err := net.SplitHostPort(currentAddress)
		if err != nil {
			return webpanel.RuntimeStatus{}, fmt.Errorf("read current proxy address: %w", err)
		}
		nextListenAddress = net.JoinHostPort(host, strconv.Itoa(*update.ProxyPort))
		if currentPort != strconv.Itoa(*update.ProxyPort) {
			nextListener, err = net.Listen("tcp", nextListenAddress)
			if err != nil {
				return webpanel.RuntimeStatus{}, fmt.Errorf("listen on %s: %w", nextListenAddress, err)
			}
			defer func() {
				if nextListener != nil {
					_ = nextListener.Close()
				}
			}()
		}
	}
	if update.TLSFingerprint != nil {
		if app.Config.FingerprintConfig != "" {
			return webpanel.RuntimeStatus{}, fmt.Errorf("TLS fingerprint is managed by --tls-fingerprint-file")
		}
		parsed, err := fingerprint.ParseSpec(strings.TrimSpace(*update.TLSFingerprint))
		if err != nil {
			return webpanel.RuntimeStatus{}, err
		}
		nextFingerprint = parsed
	}
	if update.Upstream != nil {
		if app.UpstreamDialer == nil {
			return webpanel.RuntimeStatus{}, fmt.Errorf("upstream dialer is unavailable")
		}
		if err := app.UpstreamDialer.Configure(*update.Upstream); err != nil {
			return webpanel.RuntimeStatus{}, fmt.Errorf("configure upstream proxy: %w", err)
		}
		app.Config.Upstream = app.UpstreamDialer.Upstream()
	}
	if updateProxyAuth {
		app.ProxyServer.SetAuthentication(nextProxyUsername, nextProxyPassword)
		app.Config.ProxyUsername = nextProxyUsername
		app.Config.ProxyPassword = nextProxyPassword
	}
	if update.TLSFingerprint != nil {
		app.TLSFingerprints.Set(nextFingerprint)
	}
	if update.ProxyProtocol != nil {
		protocol := strings.ToLower(strings.TrimSpace(*update.ProxyProtocol))
		if err := app.protocolListener.SetProtocol(protocol); err != nil {
			return webpanel.RuntimeStatus{}, err
		}
		app.Config.ProxyProtocol = protocol
	}
	if nextListener != nil {
		if err := app.proxyListener.Rebind(nextListener); err != nil {
			return webpanel.RuntimeStatus{}, fmt.Errorf("switch proxy listener: %w", err)
		}
		nextListener = nil
		app.Config.Listen = nextListenAddress
		app.Config.Port = strconv.Itoa(*update.ProxyPort)
	}

	status := app.webPanelRuntimeStatusLocked()
	logutil.Info("runtime", "proxy configuration updated", "proxy_listen", status.ProxyListen, "tls_fingerprint", status.TLSClient+"@"+status.TLSVersion, "upstream", status.Upstream)
	if app.TrafficMonitor != nil {
		app.TrafficMonitor.RecordEvent("info", "proxy configuration updated", traffic.TrafficSessionInfo{}, nil)
	}
	return status, nil
}

func (app *App) resolveProxyAuthUpdate(update webpanel.ConfigUpdate) (string, string, bool, error) {
	requested := update.ProxyAuthEnabled != nil || update.ProxyUsername != nil || update.ProxyPassword != nil
	if !requested {
		return "", "", false, nil
	}
	if app.ProxyServer == nil {
		return "", "", false, fmt.Errorf("proxy server is unavailable")
	}

	username := app.Config.ProxyUsername
	password := app.Config.ProxyPassword
	enabled := username != "" || password != ""
	if update.ProxyAuthEnabled != nil {
		enabled = *update.ProxyAuthEnabled
	} else if !enabled && (update.ProxyUsername != nil || update.ProxyPassword != nil) {
		enabled = true
	}
	if update.ProxyUsername != nil {
		username = *update.ProxyUsername
	}
	if update.ProxyPassword != nil {
		password = *update.ProxyPassword
	}
	if !enabled {
		return "", "", true, nil
	}
	if username == "" || password == "" {
		return "", "", false, fmt.Errorf("proxy authentication requires both a username and password")
	}
	if err := validateProxyCredentials(username, password); err != nil {
		return "", "", false, err
	}
	return username, password, true, nil
}

func validateProxyProtocol(protocol string) error {
	switch strings.ToLower(strings.TrimSpace(protocol)) {
	case httpproxy.ProtocolMixed, httpproxy.ProtocolHTTP, httpproxy.ProtocolSOCKS5:
		return nil
	default:
		return fmt.Errorf("proxy protocol must be mixed, http, or socks5")
	}
}

func (app *App) webPanelRuntimeStatus() webpanel.RuntimeStatus {
	app.configMu.Lock()
	defer app.configMu.Unlock()
	return app.webPanelRuntimeStatusLocked()
}

func (app *App) webPanelRuntimeStatusLocked() webpanel.RuntimeStatus {
	fp := app.configuredTLSFingerprint()
	fingerprintOptions := make([]string, 0)
	for _, preset := range fingerprint.Presets() {
		fingerprintOptions = append(fingerprintOptions, preset.Client+"@"+preset.Version)
	}
	upstream := ""
	if app.UpstreamDialer != nil {
		upstream = app.UpstreamDialer.Upstream()
	} else if app.Config != nil {
		upstream = app.Config.Upstream
	}
	displayUpstream := redactUpstream(upstream)
	route := "Прямое соединение"
	if displayUpstream != "" {
		route = displayUpstream
	}
	mode := "panel"
	if app.Config != nil && app.Config.FingerprintConfig != "" {
		mode = "fingerprint-file"
	}
	proxyListen := app.Config.listenAddress()
	if app.proxyListener != nil {
		proxyListen = app.proxyListener.Addr().String()
	}
	_, proxyPortText, _ := net.SplitHostPort(proxyListen)
	proxyPort, _ := strconv.Atoi(proxyPortText)
	proxyProtocol := httpproxy.ProtocolMixed
	if app.protocolListener != nil {
		proxyProtocol = app.protocolListener.Protocol()
	} else if app.Config != nil && app.Config.ProxyProtocol != "" {
		proxyProtocol = app.Config.ProxyProtocol
	}
	return webpanel.RuntimeStatus{
		ProxyListen:       proxyListen,
		ProxyPort:         proxyPort,
		ProxyProtocol:     proxyProtocol,
		TLSClient:         fp.Client,
		TLSVersion:        fp.Version,
		TLSFingerprints:   fingerprintOptions,
		Upstream:          displayUpstream,
		UpstreamEnabled:   upstream != "",
		ProxyAuthEnabled:  app.Config.ProxyUsername != "" || app.Config.ProxyPassword != "",
		ProxyUsername:     app.Config.ProxyUsername,
		ConfigurationMode: mode,
		Chain: []webpanel.ChainHop{
			{Role: "Клиент", Address: "Клиент прокси"},
			{Role: "JA3Proxy", Address: proxyListen},
			{Role: "Маршрут", Address: route},
			{Role: "Назначение", Address: "Запрошенный адрес"},
		},
	}
}

func redactUpstream(upstream string) string {
	upstream = strings.TrimSpace(upstream)
	if upstream == "" {
		return ""
	}
	if !strings.Contains(upstream, "://") {
		upstream = "socks5://" + upstream
	}
	parsed, err := url.Parse(upstream)
	if err != nil || parsed.Host == "" {
		return upstream
	}
	if parsed.User != nil {
		parsed.User = url.User(parsed.User.Username())
	}
	return parsed.String()
}

func (app *App) serve(ctx context.Context, proxyServer *httpproxy.Proxy) error {
	ctx = runtimeContext(ctx)
	if err := ctx.Err(); err != nil {
		return err
	}

	listenAddress := app.Config.listenAddress()
	listener, err := net.Listen("tcp", listenAddress)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", listenAddress, err)
	}
	rebindable := newRebindableListener(listener)
	app.configMu.Lock()
	app.proxyListener = rebindable
	app.configMu.Unlock()
	defer func() {
		app.configMu.Lock()
		if app.proxyListener == rebindable {
			app.proxyListener = nil
		}
		app.configMu.Unlock()
	}()
	server := &http.Server{
		Handler: proxyServer,
	}

	fingerprint := app.configuredTLSFingerprint()
	logutil.Info(
		"runtime",
		"proxy server listening",
		"protocols", "HTTP/SOCKS5",
		"addr", listenAddress,
		"tls_client", fingerprint.Client,
		"tls_version", fingerprint.Version,
	)
	stopClosingServer := context.AfterFunc(ctx, func() {
		_ = server.Close()
	})
	defer stopClosingServer()

	protocolListener := httpproxy.NewMixedProxyListener(rebindable, proxyServer)
	if app.Config.ProxyProtocol != "" {
		if err := protocolListener.SetProtocol(app.Config.ProxyProtocol); err != nil {
			return err
		}
	}
	app.configMu.Lock()
	app.protocolListener = protocolListener
	app.configMu.Unlock()
	defer func() {
		app.configMu.Lock()
		if app.protocolListener == protocolListener {
			app.protocolListener = nil
		}
		app.configMu.Unlock()
	}()
	if err := server.Serve(protocolListener); err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil && (errors.Is(err, http.ErrServerClosed) || errors.Is(err, net.ErrClosed)) {
			return ctxErr
		}
		return fmt.Errorf("serve proxy: %w", err)
	}
	return nil
}

func (app *App) configuredTLSFingerprint() fingerprint.TLSFingerprint {
	if app.TLSFingerprints != nil {
		if fp, ok := app.TLSFingerprints.Get(); ok {
			return fp
		}
	}

	return fingerprint.TLSFingerprint{
		Client:  app.Config.TLSClient,
		Version: app.Config.TLSVersion,
	}
}

func (app *App) tunnelHandler() *tunnel.TunnelHandler {
	return &tunnel.TunnelHandler{
		Recorder:            app.Recorder,
		TLSProfiles:         app.TLSProfiles,
		Mode:                app.Config.TLSMode,
		Debug:               app.Config.dumpTrafficEnabled(),
		CA:                  app.CA,
		SessionKey:          app.SessionKey,
		TLSFingerprints:     app.TLSFingerprints,
		UpstreamTLSProfiles: app.UpstreamTLSProfiles,
		DefaultTLSClient:    app.Config.TLSClient,
		DefaultTLSVersion:   app.Config.TLSVersion,
	}
}
