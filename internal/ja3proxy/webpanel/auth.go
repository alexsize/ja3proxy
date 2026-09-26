package webpanel

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// AuthToken describes one bearer credential loaded from the local token file.
// Token values are never returned by the panel API or audit log.
type AuthToken struct {
	ID        string
	Token     string
	tokenHash string
	Role      string
	Scopes    []string
	ExpiresAt time.Time
	Revoked   bool
	createdAt time.Time
	updatedAt time.Time
}

type authPrincipalKey struct{}

var roleScopes = map[string][]string{
	"viewer":       {"read"},
	"operator":     {"read", "write"},
	"investigator": {"read", "raw", "export"},
	"admin":        {"read", "write", "raw", "export"},
}

// ScopesForRole returns the built-in least-privilege scope set for a role.
func ScopesForRole(role string) ([]string, bool) {
	role = strings.ToLower(strings.TrimSpace(role))
	scopes, ok := roleScopes[role]
	if !ok {
		return nil, false
	}
	return append([]string(nil), scopes...), true
}

func (token AuthToken) grantedScopes() []string {
	if len(token.Scopes) > 0 {
		return token.Scopes
	}
	if scopes, ok := ScopesForRole(token.Role); ok {
		return scopes
	}
	return nil
}

func (token AuthToken) actor() string {
	if id := strings.TrimSpace(token.ID); id != "" {
		return id
	}
	if role := strings.TrimSpace(token.Role); role != "" {
		return "role:" + role
	}
	return "token"
}

const (
	authFailureWindow = time.Minute
	authFailureLimit  = 8
	authLimiterSize   = 1024
)

type authFailure struct {
	started time.Time
	count   int
}

type authLimiter struct {
	mu       sync.Mutex
	failures map[string]authFailure
}

func (limiter *authLimiter) allowed(key string, now time.Time) bool {
	limiter.mu.Lock()
	defer limiter.mu.Unlock()
	limiter.pruneLocked(now)
	failure, ok := limiter.failures[key]
	return !ok || failure.count < authFailureLimit
}

func (limiter *authLimiter) recordFailure(key string, now time.Time) {
	limiter.mu.Lock()
	defer limiter.mu.Unlock()
	limiter.pruneLocked(now)
	failure, ok := limiter.failures[key]
	if !ok {
		if len(limiter.failures) >= authLimiterSize {
			limiter.evictOldestLocked()
		}
		failure = authFailure{started: now}
	}
	failure.count++
	limiter.failures[key] = failure
}

func (limiter *authLimiter) clear(key string) {
	limiter.mu.Lock()
	defer limiter.mu.Unlock()
	delete(limiter.failures, key)
}

func (limiter *authLimiter) pruneLocked(now time.Time) {
	for key, failure := range limiter.failures {
		if now.Sub(failure.started) >= authFailureWindow {
			delete(limiter.failures, key)
		}
	}
}

func (limiter *authLimiter) evictOldestLocked() {
	var oldestKey string
	var oldest time.Time
	for key, failure := range limiter.failures {
		if oldestKey == "" || failure.started.Before(oldest) {
			oldestKey = key
			oldest = failure.started
		}
	}
	if oldestKey != "" {
		delete(limiter.failures, oldestKey)
	}
}

// tokenAuth applies configured bearer credentials to non-loopback panels.
// Loopback development panels remain usable without authentication.
func (panel Server) tokenAuth(next http.Handler) http.Handler {
	if loopbackPanelAddress(panel.Address) {
		return next
	}
	if panel.TokenRegistry == nil && len(panel.authTokens()) == 0 {
		return next
	}
	limiter := &authLimiter{failures: make(map[string]authFailure)}

	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if !strings.HasPrefix(request.URL.Path, "/api/") {
			next.ServeHTTP(response, request)
			return
		}
		clientKey := authClientKey(request)
		if !limiter.allowed(clientKey, time.Now()) {
			response.Header().Set("Retry-After", "60")
			writeAPIError(response, http.StatusTooManyRequests, "too many authentication failures")
			return
		}

		scheme, value, ok := strings.Cut(request.Header.Get("Authorization"), " ")
		provided := strings.TrimSpace(value)
		matched := -1
		tokens := panel.authTokens()
		if ok && strings.EqualFold(scheme, "Bearer") {
			for i := range tokens {
				if tokens[i].Revoked {
					continue
				}
				if tokens[i].matches(provided) {
					matched = i
				}
			}
		}
		if matched < 0 {
			limiter.recordFailure(clientKey, time.Now())
			response.Header().Set("WWW-Authenticate", `Bearer realm="ja3proxy-panel"`)
			writeAPIError(response, http.StatusUnauthorized, "bearer token required")
			return
		}
		limiter.clear(clientKey)
		principal := tokens[matched]
		if !principal.ExpiresAt.IsZero() && !time.Now().Before(principal.ExpiresAt) {
			response.Header().Set("WWW-Authenticate", `Bearer realm="ja3proxy-panel", error="invalid_token"`)
			writeAPIError(response, http.StatusUnauthorized, "bearer token expired")
			return
		}
		request = request.WithContext(context.WithValue(request.Context(), authPrincipalKey{}, principal))
		if missing := missingAuthScopes(request, principal.grantedScopes()); len(missing) > 0 {
			writeAPIError(response, http.StatusForbidden, "insufficient token scope")
			return
		}

		next.ServeHTTP(response, request)
	})
}

func loopbackPanelAddress(address string) bool {
	host, _, err := net.SplitHostPort(strings.TrimSpace(address))
	if err != nil {
		return false
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	if zone := strings.LastIndexByte(host, '%'); zone >= 0 {
		host = host[:zone]
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func (panel Server) authTokens() []AuthToken {
	if panel.TokenRegistry != nil {
		return panel.TokenRegistry.authTokens()
	}
	if len(panel.AuthTokens) > 0 {
		return panel.AuthTokens
	}
	if strings.TrimSpace(panel.AuthToken) == "" {
		return nil
	}
	return []AuthToken{{ID: "legacy", Token: panel.AuthToken, Scopes: panel.AuthScopes, ExpiresAt: panel.AuthTokenExpiry}}
}

func (token AuthToken) matches(provided string) bool {
	providedHash := sha256.Sum256([]byte(provided))
	wantHash := token.tokenHash
	if wantHash == "" {
		wantHash = tokenDigest(token.Token)
	}
	if len(wantHash) != sha256.Size*2 {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(wantHash), []byte(providedHashHex(providedHash))) == 1
}

func authenticatedActor(r *http.Request) string {
	if r != nil {
		if principal, ok := r.Context().Value(authPrincipalKey{}).(AuthToken); ok {
			return principal.actor()
		}
	}
	return ""
}

func missingAuthScopes(request *http.Request, granted []string) []string {
	if granted == nil {
		return nil
	}
	available := make(map[string]struct{}, len(granted))
	for _, scope := range granted {
		available[strings.ToLower(strings.TrimSpace(scope))] = struct{}{}
	}
	required := []string{"read"}
	if request.URL.Path == "/api/config" || isMutationRequest(request) {
		required = append(required, "write")
	}
	if isRawObservationRequest(request) {
		required = append(required, "raw")
	}
	if strings.HasPrefix(request.URL.Path, "/api/v1/export/") {
		required = append(required, "export")
	}
	if request.URL.Path == "/api/v1/export/telemetry" {
		required = append(required, "raw")
	}
	if request.URL.Path == "/api/v1/import/telemetry" {
		required = append(required, "raw")
	}
	if request.URL.Path == "/api/v1/export/observations" {
		required = append(required, "raw")
	}
	missing := make([]string, 0, len(required))
	seen := make(map[string]struct{}, len(required))
	for _, scope := range required {
		if _, ok := seen[scope]; ok {
			continue
		}
		seen[scope] = struct{}{}
		if _, ok := available[scope]; !ok {
			missing = append(missing, scope)
		}
	}
	return missing
}

func isMutationRequest(request *http.Request) bool {
	if request.Method != http.MethodPost && request.Method != http.MethodPut && request.Method != http.MethodPatch && request.Method != http.MethodDelete {
		return false
	}
	return strings.HasPrefix(request.URL.Path, "/api/v1/")
}

func isRawObservationRequest(request *http.Request) bool {
	path := request.URL.Path
	return strings.HasPrefix(path, "/api/v1/observations/") ||
		path == "/api/v1/reparse/sqlite"
}

func authClientKey(request *http.Request) string {
	if host, _, err := net.SplitHostPort(request.RemoteAddr); err == nil && host != "" {
		return host
	}
	if request.RemoteAddr != "" {
		return request.RemoteAddr
	}
	return "unknown"
}
