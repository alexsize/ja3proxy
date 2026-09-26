package webpanel

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lylemi/ja3proxy/internal/ja3proxy/audit"
)

func TestProxyAuthReloadAPIRequiresAdminAndAudit(t *testing.T) {
	auditLog, err := audit.OpenSQLite(filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer auditLog.Close()
	calls := 0
	panel := Server{
		Address: "0.0.0.0:9090", Audit: auditLog, TLSCertFile: "panel.pem", TLSKeyFile: "panel.pem",
		AuthTokens:      []AuthToken{{ID: "operator", Token: "operator-token", Role: "operator"}, {ID: "admin", Token: "admin-token", Role: "admin"}},
		ReloadProxyAuth: func() (RuntimeStatus, error) { calls++; return RuntimeStatus{}, nil },
	}
	request := func(token, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:9090/api/v1/admin/proxy-auth/reload", strings.NewReader(body))
		req.RemoteAddr = "127.0.0.1:1234"
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		response := httptest.NewRecorder()
		panel.Handler().ServeHTTP(response, req)
		return response
	}
	if response := request("operator-token", ""); response.Code != http.StatusForbidden {
		t.Fatalf("operator: %d %s", response.Code, response.Body.String())
	}
	if calls != 0 {
		t.Fatal("unauthorized request called credential reload")
	}
	if response := request("admin-token", "{}"); response.Code != http.StatusBadRequest {
		t.Fatalf("request body: %d %s", response.Code, response.Body.String())
	}
	if response := request("admin-token", ""); response.Code != http.StatusNoContent {
		t.Fatalf("admin: %d %s", response.Code, response.Body.String())
	}
	if calls != 1 {
		t.Fatalf("reload calls = %d, want 1", calls)
	}
	panel.Address = "127.0.0.1:9090"
	if response := request("", ""); response.Code != http.StatusNoContent {
		t.Fatalf("loopback: %d %s", response.Code, response.Body.String())
	}
	panel.Audit = nil
	if response := request("", ""); response.Code != http.StatusServiceUnavailable {
		t.Fatalf("missing audit: %d", response.Code)
	}
}

func TestUpstreamCredentialReloadAPIRequiresAdminAndAudit(t *testing.T) {
	auditLog, err := audit.OpenSQLite(filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer auditLog.Close()
	calls := 0
	panel := Server{
		Address: "0.0.0.0:9090", Audit: auditLog, TLSCertFile: "panel.pem", TLSKeyFile: "panel.pem",
		AuthTokens:                []AuthToken{{ID: "operator", Token: "operator-token", Role: "operator"}, {ID: "admin", Token: "admin-token", Role: "admin"}},
		ReloadUpstreamCredentials: func() (RuntimeStatus, error) { calls++; return RuntimeStatus{}, nil },
	}
	request := func(token string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:9090/api/v1/admin/upstream-credentials/reload", nil)
		req.RemoteAddr = "127.0.0.1:1234"
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		response := httptest.NewRecorder()
		panel.Handler().ServeHTTP(response, req)
		return response
	}
	if response := request("operator-token"); response.Code != http.StatusForbidden {
		t.Fatalf("operator: %d %s", response.Code, response.Body.String())
	}
	if response := request("admin-token"); response.Code != http.StatusNoContent {
		t.Fatalf("admin: %d %s", response.Code, response.Body.String())
	}
	if calls != 1 {
		t.Fatalf("reload calls = %d, want 1", calls)
	}
	panel.Address = "127.0.0.1:9090"
	panel.Audit = nil
	if response := request(""); response.Code != http.StatusServiceUnavailable {
		t.Fatalf("missing audit: %d", response.Code)
	}
	if calls != 1 {
		t.Fatal("reload was called without available audit")
	}
}
