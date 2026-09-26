package webpanel

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestTokenAuthProtectsAPIAndLeavesStaticPanelAvailable(t *testing.T) {
	server := Server{Address: "0.0.0.0:9090", AuthToken: "0123456789abcdef"}
	handler := server.Handler()

	tests := []struct {
		name       string
		authority  string
		wantStatus int
	}{
		{name: "missing", wantStatus: http.StatusUnauthorized},
		{name: "wrong token", authority: "Bearer 0123456789abcdee", wantStatus: http.StatusUnauthorized},
		{name: "wrong scheme", authority: "Basic 0123456789abcdef", wantStatus: http.StatusUnauthorized},
		{name: "valid token", authority: "bearer 0123456789abcdef", wantStatus: http.StatusOK},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, "/api/v1/tls/presets", nil)
			request.RemoteAddr = "127.0.0.1:1234"
			request.Host = "127.0.0.1:9090"
			request.Host = "127.0.0.1:9090"
			if test.authority != "" {
				request.Header.Set("Authorization", test.authority)
			}
			response := httptest.NewRecorder()

			handler.ServeHTTP(response, request)

			if response.Code != test.wantStatus {
				t.Fatalf("status = %d, want %d", response.Code, test.wantStatus)
			}
			if test.wantStatus == http.StatusUnauthorized {
				if got := response.Header().Get("WWW-Authenticate"); got != `Bearer realm="ja3proxy-panel"` {
					t.Fatalf("WWW-Authenticate = %q", got)
				}
				if strings.Contains(response.Body.String(), "0123456789") {
					t.Fatal("error response leaked the configured token")
				}
			}
		})
	}

	staticRequest := httptest.NewRequest(http.MethodGet, "/", nil)
	staticResponse := httptest.NewRecorder()
	handler.ServeHTTP(staticResponse, staticRequest)
	if staticResponse.Code != http.StatusOK {
		t.Fatalf("static panel status = %d, want %d", staticResponse.Code, http.StatusOK)
	}
}

func TestTokenAuthDoesNotProtectWhenTokenIsUnset(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "/api/v1/tls/presets", nil)
	request.RemoteAddr = "127.0.0.1:1234"
	request.Host = "127.0.0.1:9090"
	response := httptest.NewRecorder()

	Server{}.Handler().ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusOK)
	}
}

func TestTokenAuthLimitsRepeatedFailuresPerClient(t *testing.T) {
	handler := (Server{Address: "0.0.0.0:9090", AuthToken: "0123456789abcdef"}).Handler()
	for attempt := 0; attempt < authFailureLimit; attempt++ {
		request := httptest.NewRequest(http.MethodGet, "/api/v1/tls/presets", nil)
		request.RemoteAddr = "127.0.0.1:1234"
		request.Host = "127.0.0.1:9090"
		request.Header.Set("Authorization", "Bearer wrong-token")
		response := httptest.NewRecorder()

		handler.ServeHTTP(response, request)

		if response.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d status = %d, want %d", attempt+1, response.Code, http.StatusUnauthorized)
		}
	}

	request := httptest.NewRequest(http.MethodGet, "/api/v1/tls/presets", nil)
	request.RemoteAddr = "127.0.0.1:1234"
	request.Host = "127.0.0.1:9090"
	request.Header.Set("Authorization", "Bearer wrong-token")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	if response.Code != http.StatusTooManyRequests {
		t.Fatalf("locked status = %d, want %d", response.Code, http.StatusTooManyRequests)
	}
	if response.Header().Get("Retry-After") != "60" {
		t.Fatalf("Retry-After = %q, want 60", response.Header().Get("Retry-After"))
	}

	// A different client remains usable; a single noisy source must not block
	// all local operators.
	request = httptest.NewRequest(http.MethodGet, "/api/v1/tls/presets", nil)
	request.RemoteAddr = "127.0.0.2:1234"
	request.Host = "127.0.0.1:9090"
	request.Header.Set("Authorization", "Bearer 0123456789abcdef")
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("different client status = %d, want %d", response.Code, http.StatusOK)
	}
}

func TestTokenAuthRequiresSensitiveScopes(t *testing.T) {
	handler := (Server{Address: "0.0.0.0:9090", AuthToken: "0123456789abcdef", AuthScopes: []string{"read", "write"}}).Handler()
	for _, path := range []string{"/api/v1/observations/observation-id", "/api/v1/export/observations"} {
		request := httptest.NewRequest(http.MethodGet, path, nil)
		request.RemoteAddr = "127.0.0.1:1234"
		request.Host = "127.0.0.1:9090"
		request.Header.Set("Authorization", "Bearer 0123456789abcdef")
		response := httptest.NewRecorder()

		handler.ServeHTTP(response, request)

		if response.Code != http.StatusForbidden {
			t.Fatalf("%s status = %d, want %d", path, response.Code, http.StatusForbidden)
		}
	}

	request := httptest.NewRequest(http.MethodGet, "/api/v1/tls/presets", nil)
	request.RemoteAddr = "127.0.0.1:1234"
	request.Host = "127.0.0.1:9090"
	request.Header.Set("Authorization", "Bearer 0123456789abcdef")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("ordinary API status = %d, want %d", response.Code, http.StatusOK)
	}
}

func TestTokenAuthRejectsExpiredToken(t *testing.T) {
	handler := (Server{Address: "0.0.0.0:9090", AuthToken: "0123456789abcdef", AuthTokenExpiry: time.Now().Add(-time.Minute)}).Handler()
	request := httptest.NewRequest(http.MethodGet, "/api/v1/tls/presets", nil)
	request.RemoteAddr = "127.0.0.1:1234"
	request.Host = "127.0.0.1:9090"
	request.Header.Set("Authorization", "Bearer 0123456789abcdef")
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusUnauthorized)
	}
	if !strings.Contains(response.Body.String(), "expired") {
		t.Fatalf("body = %q, want expiry error", response.Body.String())
	}
}

func TestTokenAuthSupportsRoleBasedTokenRegistry(t *testing.T) {
	handler := (Server{Address: "0.0.0.0:9090", AuthTokens: []AuthToken{
		{ID: "viewer-1", Token: "viewer-token-012345", Role: "viewer"},
		{ID: "admin-1", Token: "admin-token-012345", Role: "admin"},
	}}).Handler()

	request := httptest.NewRequest(http.MethodGet, "/api/v1/observations/viewer", nil)
	request.RemoteAddr = "127.0.0.1:1234"
	request.Host = "127.0.0.1:9090"
	request.Header.Set("Authorization", "Bearer viewer-token-012345")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("viewer raw status = %d, want %d", response.Code, http.StatusForbidden)
	}

	request = httptest.NewRequest(http.MethodGet, "/api/v1/tls/presets", nil)
	request.RemoteAddr = "127.0.0.1:1234"
	request.Host = "127.0.0.1:9090"
	request.Header.Set("Authorization", "Bearer viewer-token-012345")
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("viewer ordinary status = %d, want %d", response.Code, http.StatusOK)
	}

	request = httptest.NewRequest(http.MethodGet, "/api/v1/export/telemetry", nil)
	request.RemoteAddr = "127.0.0.1:1234"
	request.Host = "127.0.0.1:9090"
	request.Header.Set("Authorization", "Bearer admin-token-012345")
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("admin export status = %d, want recorder-unavailable %d", response.Code, http.StatusServiceUnavailable)
	}
}

func TestTokenAuthRejectsRevokedRegistryToken(t *testing.T) {
	handler := (Server{Address: "0.0.0.0:9090", AuthTokens: []AuthToken{{ID: "revoked-1", Token: "revoked-token-012345", Role: "admin", Revoked: true}}}).Handler()
	request := httptest.NewRequest(http.MethodGet, "/api/v1/tls/presets", nil)
	request.RemoteAddr = "127.0.0.1:1234"
	request.Host = "127.0.0.1:9090"
	request.Header.Set("Authorization", "Bearer revoked-token-012345")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusUnauthorized)
	}
}

func TestLoopbackPanelDoesNotRequireConfiguredToken(t *testing.T) {
	for _, address := range []string{"127.0.0.1:9090", "[::1]:9090", "localhost:9090"} {
		t.Run(address, func(t *testing.T) {
			handler := (Server{Address: address, AuthToken: "0123456789abcdef"}).Handler()
			request := httptest.NewRequest(http.MethodGet, "/api/state", nil)
			request.RemoteAddr = "127.0.0.1:1234"
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != http.StatusOK {
				t.Fatalf("status = %d, want %d", response.Code, http.StatusOK)
			}
		})
	}
}
