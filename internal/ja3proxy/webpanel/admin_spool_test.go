package webpanel

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/lylemi/ja3proxy/internal/ja3proxy/audit"
	"github.com/lylemi/ja3proxy/internal/ja3proxy/recorder"
)

func TestSpoolKeyReloadAPIHonorsAdminAndAudit(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "key")
	if err := os.WriteFile(keyPath, bytes.Repeat([]byte{1}, 32), 0600); err != nil {
		t.Fatal(err)
	}
	r, err := recorder.New(recorder.Options{SpoolPath: filepath.Join(dir, "spool"), SpoolKeyPath: keyPath})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	auditLog, err := audit.OpenSQLite(filepath.Join(dir, "audit.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer auditLog.Close()
	markerPath := filepath.Join(dir, "spool", "key.id")
	oldMarker, err := os.ReadFile(markerPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, bytes.Repeat([]byte{2}, 32), 0600); err != nil {
		t.Fatal(err)
	}
	panel := Server{Address: "0.0.0.0:9090", Recorder: r, Audit: auditLog,
		TLSCertFile: "panel.pem", TLSKeyFile: "panel.pem",
		AuthTokens: []AuthToken{{ID: "operator", Token: "operator-token", Role: "operator"}, {ID: "admin", Token: "admin-token", Role: "admin"}},
	}
	request := func(token string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:9090/api/v1/admin/spool/reload-key", nil)
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
	marker, err := os.ReadFile(markerPath)
	if err != nil || !bytes.Equal(marker, oldMarker) {
		t.Fatal("unauthorized request changed key")
	}
	panel.Audit = nil
	if response := request("admin-token"); response.Code != http.StatusServiceUnavailable {
		t.Fatalf("missing audit: %d", response.Code)
	}
	panel.Audit = auditLog
	if response := request("admin-token"); response.Code != http.StatusNoContent {
		t.Fatalf("admin: %d %s", response.Code, response.Body.String())
	}
	marker, err = os.ReadFile(markerPath)
	if err != nil || bytes.Equal(marker, oldMarker) {
		t.Fatal("admin request did not change key")
	}
	panel.Address = "127.0.0.1:9090"
	if response := request(""); response.Code != http.StatusNoContent {
		t.Fatalf("loopback: %d", response.Code)
	}
	if err := auditLog.Close(); err != nil {
		t.Fatal(err)
	}
	if response := request(""); response.Code != http.StatusServiceUnavailable {
		t.Fatalf("closed audit: %d", response.Code)
	}
}
