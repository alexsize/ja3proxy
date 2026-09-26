package webpanel

import (
	"bytes"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lylemi/ja3proxy/internal/ja3proxy/audit"
	"github.com/lylemi/ja3proxy/internal/ja3proxy/certstore"
)

func TestDownloadCAExportsOnlyActivePublicCertificate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "combined.pem")
	active := &certstore.CertificateAuthority{}
	if err := active.Generate(path, path); err != nil {
		t.Fatal(err)
	}
	first := append([]byte(nil), active.X509Certificate().Raw...)
	panel := Server{Address: "0.0.0.0:9090", CACertificate: active.X509Certificate,
		AuthTokens: []AuthToken{{ID: "viewer", Role: "viewer", Token: "viewer-secret"}},
	}
	handler := panel.Handler()
	download := func(token string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/ca/certificate", nil)
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, req)
		return response
	}
	if response := download(""); response.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous: %d", response.Code)
	}
	// Changing the source bundle alone must not change the active download.
	if err := (&certstore.CertificateAuthority{}).Generate(path, path); err != nil {
		t.Fatal(err)
	}
	for generation := 0; generation < 2; generation++ {
		response := download("viewer-secret")
		if response.Code != http.StatusOK {
			t.Fatalf("download: %d %s", response.Code, response.Body.String())
		}
		block, rest := pem.Decode(response.Body.Bytes())
		if block == nil || block.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) != 0 || bytes.Contains(response.Body.Bytes(), []byte("PRIVATE KEY")) {
			t.Fatal("download was not a single public certificate")
		}
		if !bytes.Equal(block.Bytes, active.X509Certificate().Raw) {
			t.Fatal("download differs from active CA")
		}
		if generation == 0 && !bytes.Equal(block.Bytes, first) {
			t.Fatal("unapplied bundle was exported")
		}
		if generation == 1 && bytes.Equal(block.Bytes, first) {
			t.Fatal("download remained stale after reload")
		}
		if response.Header().Get("Cache-Control") != "no-store" || response.Header().Get("Content-Disposition") != `attachment; filename="ja3proxy-ca.pem"` {
			t.Fatal("download headers missing")
		}
		if err := active.Load(path, path); err != nil {
			t.Fatal(err)
		}
	}
}

func TestCAReloadRequiresAdminRemotelyAndAllowsLoopback(t *testing.T) {
	auditLog, err := audit.OpenSQLite(filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer auditLog.Close()
	calls := 0
	reload := func() (RuntimeStatus, error) {
		calls++
		return RuntimeStatus{MITMCACertificateStatus: "VALID"}, nil
	}
	panel := Server{
		Address: "0.0.0.0:9090", TLSCertFile: "panel.pem", TLSKeyFile: "panel.pem",
		AuthTokens: []AuthToken{{ID: "viewer", Token: "viewer-secret", Role: "viewer"}, {ID: "admin", Token: "admin-secret", Role: "admin"}},
		Audit:      auditLog, ReloadCA: reload,
	}
	request := func(handler http.Handler, token string) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequest(http.MethodPost, "/api/v1/admin/ca/reload", nil)
		r.RemoteAddr = "192.0.2.1:1234"
		if token != "" {
			r.Header.Set("Authorization", "Bearer "+token)
		}
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, r)
		return response
	}
	handler := panel.Handler()
	if response := request(handler, ""); response.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous status = %d", response.Code)
	}
	if response := request(handler, "viewer-secret"); response.Code != http.StatusForbidden {
		t.Fatalf("viewer status = %d", response.Code)
	}
	if calls != 0 {
		t.Fatal("reload ran without admin authorization")
	}
	if response := request(handler, "admin-secret"); response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"mitmCaCertificateStatus":"VALID"`) {
		t.Fatalf("admin response = %d %s", response.Code, response.Body.String())
	}
	panel.Address = "127.0.0.1:9090"
	if response := request(panel.Handler(), ""); response.Code != http.StatusOK {
		t.Fatalf("loopback status = %d", response.Code)
	}
	if calls != 2 {
		t.Fatalf("reload calls = %d", calls)
	}
}

func TestCAReloadFailsClosedWithoutAuditAndPreservesErrorDetails(t *testing.T) {
	calls := 0
	panel := Server{Address: "127.0.0.1:9090", ReloadCA: func() (RuntimeStatus, error) {
		calls++
		return RuntimeStatus{}, errors.New("private key path and material")
	}}
	request := httptest.NewRequest(http.MethodPost, "/api/v1/admin/ca/reload", nil)
	request.RemoteAddr = "127.0.0.1:1234"
	request.Host = "127.0.0.1:9090"
	response := httptest.NewRecorder()
	panel.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusServiceUnavailable || calls != 0 {
		t.Fatalf("without audit = %d, calls=%d", response.Code, calls)
	}
	auditLog, err := audit.OpenSQLite(filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer auditLog.Close()
	panel.Audit = auditLog
	response = httptest.NewRecorder()
	panel.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusConflict || calls != 1 || strings.Contains(response.Body.String(), "private key") {
		t.Fatalf("failed reload = %d %s, calls=%d", response.Code, response.Body.String(), calls)
	}
}
