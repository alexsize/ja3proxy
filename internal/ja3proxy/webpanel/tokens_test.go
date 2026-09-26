package webpanel

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lylemi/ja3proxy/internal/ja3proxy/audit"
	"github.com/lylemi/ja3proxy/internal/ja3proxy/state"
)

func TestTokenRegistryLifecyclePersistsHashesAndTakesEffectImmediately(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "state.db")
	database, err := state.OpenSQLite(databasePath)
	if err != nil {
		t.Fatal(err)
	}
	registry, err := OpenTokenRegistry(database, nil)
	if err != nil {
		t.Fatal(err)
	}
	admin, err := registry.Issue(TokenIssue{ID: "admin-main", Role: "admin"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := registry.Update("admin-main", TokenUpdate{Role: "admin", Scopes: []string{"read"}}); err == nil {
		t.Fatal("accepted an admin role without its full admin scopes")
	}
	document, found, err := database.Load(tokenRegistryEntity)
	if err != nil || !found {
		t.Fatalf("load token snapshot: found=%v err=%v", found, err)
	}
	if bytes.Contains(document.Payload, []byte(admin.Token)) {
		t.Fatal("SQLite token snapshot contains a plaintext bearer secret")
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}

	database, err = state.OpenSQLite(databasePath)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	registry, err = OpenTokenRegistry(database, nil)
	if err != nil {
		t.Fatal(err)
	}
	auditLog, err := audit.OpenSQLite(databasePath)
	if err != nil {
		t.Fatal(err)
	}
	defer auditLog.Close()
	handler := (Server{Address: "0.0.0.0:9090", TLSCertFile: "server.crt", TLSKeyFile: "server.key", TokenRegistry: registry, Audit: auditLog}).Handler()
	request := func(method, path, secret string, body []byte) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(method, path, bytes.NewReader(body))
		req.RemoteAddr = "192.0.2.10:1234"
		req.Header.Set("Content-Type", "application/json")
		if secret != "" {
			req.Header.Set("Authorization", "Bearer "+secret)
		}
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, req)
		return response
	}

	list := request(http.MethodGet, "/api/v1/admin/tokens", admin.Token, nil)
	if list.Code != http.StatusOK || strings.Contains(list.Body.String(), admin.Token) || strings.Contains(list.Body.String(), "0001-01-01") {
		t.Fatalf("admin list response: status=%d body=%s", list.Code, list.Body.String())
	}
	if strings.Contains(list.Body.String(), "token_hash") {
		t.Fatalf("token list leaked a digest: %s", list.Body.String())
	}
	created := request(http.MethodPost, "/api/v1/admin/tokens", admin.Token, []byte(`{"id":"viewer-one","role":"viewer"}`))
	if created.Code != http.StatusCreated {
		t.Fatalf("issue status=%d body=%s", created.Code, created.Body.String())
	}
	var issued IssuedToken
	if err := json.Unmarshal(created.Body.Bytes(), &issued); err != nil {
		t.Fatal(err)
	}
	if issued.Token == "" || issued.Entry.Role != "viewer" {
		t.Fatalf("issued token response=%+v", issued)
	}
	updated := request(http.MethodPut, "/api/v1/admin/tokens/viewer-one", admin.Token, []byte(`{"role":"operator"}`))
	if updated.Code != http.StatusOK || !strings.Contains(updated.Body.String(), `"role":"operator"`) {
		t.Fatalf("update role status=%d body=%s", updated.Code, updated.Body.String())
	}
	if response := request(http.MethodGet, "/api/state", issued.Token, nil); response.Code != http.StatusOK {
		t.Fatalf("new token did not take effect immediately: status=%d body=%s", response.Code, response.Body.String())
	}
	revoked := request(http.MethodDelete, "/api/v1/admin/tokens/viewer-one", admin.Token, nil)
	if revoked.Code != http.StatusOK {
		t.Fatalf("revoke status=%d body=%s", revoked.Code, revoked.Body.String())
	}
	if got := request(http.MethodGet, "/api/state", issued.Token, nil).Code; got != http.StatusUnauthorized {
		t.Fatalf("revoked token status=%d, want %d", got, http.StatusUnauthorized)
	}
	rotated := request(http.MethodPost, "/api/v1/admin/tokens/admin-main/rotate", admin.Token, nil)
	if rotated.Code != http.StatusOK {
		t.Fatalf("rotate status=%d body=%s", rotated.Code, rotated.Body.String())
	}
	var replacement IssuedToken
	if err := json.Unmarshal(rotated.Body.Bytes(), &replacement); err != nil {
		t.Fatal(err)
	}
	if replacement.Token == "" || replacement.Token == admin.Token {
		t.Fatalf("rotation did not return a fresh token: %+v", replacement)
	}
	if got := request(http.MethodGet, "/api/v1/admin/tokens", admin.Token, nil).Code; got != http.StatusUnauthorized {
		t.Fatalf("old token after rotation status=%d, want %d", got, http.StatusUnauthorized)
	}
	if got := request(http.MethodGet, "/api/v1/admin/tokens", replacement.Token, nil).Code; got != http.StatusOK {
		t.Fatalf("rotated token status=%d, want %d", got, http.StatusOK)
	}
	if got := request(http.MethodDelete, "/api/v1/admin/tokens/admin-main", replacement.Token, nil).Code; got != http.StatusConflict {
		t.Fatalf("last admin revoke status=%d, want %d", got, http.StatusConflict)
	}
	if got := request(http.MethodPut, "/api/v1/admin/tokens/admin-main", replacement.Token, []byte(`{"role":"operator"}`)).Code; got != http.StatusConflict {
		t.Fatalf("last admin demotion status=%d, want %d", got, http.StatusConflict)
	}
	page, err := auditLog.Query(50, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Items) < 10 {
		t.Fatalf("token lifecycle mutations were not fully audited: got %d events", len(page.Items))
	}
	for _, event := range page.Items {
		if event.Actor != "admin-main" && event.Actor != "anonymous" {
			t.Fatalf("unexpected audit actor %q", event.Actor)
		}
		if strings.Contains(event.Object, admin.Token) || strings.Contains(event.Object, replacement.Token) || strings.Contains(event.Object, issued.Token) {
			t.Fatal("audit event leaked a bearer token")
		}
	}
	reopened, err := state.OpenSQLite(databasePath)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	restored, err := OpenTokenRegistry(reopened, nil)
	if err != nil {
		t.Fatal(err)
	}
	var restoredAdmin, restoredViewer AuthToken
	for _, token := range restored.authTokens() {
		switch token.ID {
		case "admin-main":
			restoredAdmin = token
		case "viewer-one":
			restoredViewer = token
		}
	}
	if !restoredAdmin.matches(replacement.Token) || restoredAdmin.matches(admin.Token) {
		t.Fatal("rotated secret did not persist across restart")
	}
	if !restoredViewer.Revoked || restoredViewer.Role != "operator" {
		t.Fatalf("updated/revoked token metadata did not persist: %+v", restoredViewer)
	}
}

func TestEmptySQLiteTokenRegistryImportsBootstrapOnNextStart(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "state.db")
	database, err := state.OpenSQLite(databasePath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenTokenRegistry(database, nil); err != nil {
		t.Fatal(err)
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}
	database, err = state.OpenSQLite(databasePath)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	registry, err := OpenTokenRegistry(database, []AuthToken{{ID: "seed-admin", Token: "seed-admin-token-12345", Role: "admin"}})
	if err != nil {
		t.Fatal(err)
	}
	tokens := registry.authTokens()
	if len(tokens) != 1 || !tokens[0].matches("seed-admin-token-12345") {
		t.Fatalf("bootstrap token not imported into empty registry: %+v", tokens)
	}
}

func TestTokenManagementRequiresAdminOutsideLoopback(t *testing.T) {
	registry, err := OpenTokenRegistry(nil, []AuthToken{
		{ID: "viewer", Token: "viewer-token-012345", Role: "viewer"},
		{ID: "admin", Token: "admin-token-012345", Role: "admin"},
	})
	if err != nil {
		t.Fatal(err)
	}
	handler := (Server{Address: "0.0.0.0:9090", TokenRegistry: registry}).Handler()
	request := httptest.NewRequest(http.MethodGet, "/api/v1/admin/tokens", nil)
	request.RemoteAddr = "192.0.2.11:1234"
	request.Header.Set("Authorization", "Bearer viewer-token-012345")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("viewer token management status=%d, want %d", response.Code, http.StatusForbidden)
	}
}

func TestLoopbackTokenManagementDoesNotRequireBearer(t *testing.T) {
	registry, err := OpenTokenRegistry(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	auditLog, err := audit.OpenSQLite(filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer auditLog.Close()
	handler := (Server{Address: "127.0.0.1:9090", TokenRegistry: registry, Audit: auditLog}).Handler()
	request := httptest.NewRequest(http.MethodPost, "/api/v1/admin/tokens", strings.NewReader(`{"id":"local-admin","role":"admin"}`))
	request.RemoteAddr = "127.0.0.1:1234"
	request.Host = "127.0.0.1:9090"
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusCreated {
		t.Fatalf("loopback token creation status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestTokenMutationFailsClosedWithoutAudit(t *testing.T) {
	registry, err := OpenTokenRegistry(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	handler := (Server{Address: "127.0.0.1:9090", TokenRegistry: registry}).Handler()
	request := httptest.NewRequest(http.MethodPost, "/api/v1/admin/tokens", strings.NewReader(`{"id":"local-admin","role":"admin"}`))
	request.RemoteAddr = "127.0.0.1:1234"
	request.Host = "127.0.0.1:9090"
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("unaudited token mutation status=%d, want %d", response.Code, http.StatusServiceUnavailable)
	}
	if len(registry.List()) != 0 {
		t.Fatal("token was created although audit was unavailable")
	}
}
