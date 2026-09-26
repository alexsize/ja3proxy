package webpanel

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/lylemi/ja3proxy/internal/ja3proxy/state"
)

const tokenRegistryEntity = "webpanel.auth_tokens"

var tokenIDPattern = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,64}$`)

var errTokenNotFound = errors.New("token not found")

type tokenRegistryState interface {
	Load(entity string) (state.Document, bool, error)
	SaveSnapshot(entity, schemaVersion string, revision uint64, payload []byte) error
}

type TokenRegistry struct {
	mu       sync.RWMutex
	state    tokenRegistryState
	revision uint64
	tokens   []AuthToken
}

type storedTokenRegistry struct {
	SchemaVersion string            `json:"schema_version"`
	Tokens        []storedAuthToken `json:"tokens"`
}

type storedAuthToken struct {
	ID        string    `json:"id"`
	TokenHash string    `json:"token_hash"`
	Role      string    `json:"role"`
	Scopes    []string  `json:"scopes,omitempty"`
	ExpiresAt time.Time `json:"expires_at,omitempty"`
	Revoked   bool      `json:"revoked,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type TokenMetadata struct {
	ID        string     `json:"id"`
	Role      string     `json:"role"`
	Scopes    []string   `json:"scopes"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
	Revoked   bool       `json:"revoked"`
	CreatedAt time.Time  `json:"created_at"`
	UpdatedAt time.Time  `json:"updated_at"`
}

type TokenIssue struct {
	ID        string   `json:"id"`
	Role      string   `json:"role"`
	Scopes    []string `json:"scopes"`
	ExpiresAt string   `json:"expires_at"`
}

type TokenUpdate struct {
	Role      string   `json:"role"`
	Scopes    []string `json:"scopes"`
	ExpiresAt string   `json:"expires_at"`
}

type IssuedToken struct {
	Token string        `json:"token"`
	Entry TokenMetadata `json:"entry"`
}

func OpenTokenRegistry(store tokenRegistryState, bootstrap []AuthToken) (*TokenRegistry, error) {
	registry := &TokenRegistry{state: store}
	if store == nil {
		for _, token := range bootstrap {
			if _, err := registry.importToken(token); err != nil {
				return nil, err
			}
		}
		return registry, nil
	}
	document, found, err := store.Load(tokenRegistryEntity)
	if err != nil {
		return nil, fmt.Errorf("load panel token registry: %w", err)
	}
	if found {
		var saved storedTokenRegistry
		if err := json.Unmarshal(document.Payload, &saved); err != nil {
			return nil, fmt.Errorf("decode panel token registry: %w", err)
		}
		if saved.SchemaVersion != "webpanel-token-registry/1" {
			return nil, fmt.Errorf("unsupported panel token registry schema %q", saved.SchemaVersion)
		}
		registry.revision = document.Revision
		for _, stored := range saved.Tokens {
			if !tokenIDPattern.MatchString(stored.ID) || len(stored.TokenHash) != sha256.Size*2 {
				return nil, errors.New("invalid entry in panel token registry")
			}
			registry.tokens = append(registry.tokens, AuthToken{
				ID: stored.ID, tokenHash: stored.TokenHash, Role: stored.Role,
				Scopes: append([]string(nil), stored.Scopes...), ExpiresAt: stored.ExpiresAt,
				Revoked: stored.Revoked, createdAt: stored.CreatedAt, updatedAt: stored.UpdatedAt,
			})
		}
		if len(registry.tokens) == 0 && len(bootstrap) > 0 {
			now := time.Now().UTC()
			for _, token := range bootstrap {
				if _, err := registry.importTokenAt(token, now); err != nil {
					return nil, err
				}
			}
			if err := registry.persistLocked(); err != nil {
				return nil, err
			}
		}
		return registry, nil
	}
	now := time.Now().UTC()
	for _, token := range bootstrap {
		if _, err := registry.importTokenAt(token, now); err != nil {
			return nil, err
		}
	}
	if err := registry.persistLocked(); err != nil {
		return nil, err
	}
	return registry, nil
}

func (registry *TokenRegistry) importToken(token AuthToken) (TokenMetadata, error) {
	return registry.importTokenAt(token, time.Now().UTC())
}

func (registry *TokenRegistry) importTokenAt(token AuthToken, now time.Time) (TokenMetadata, error) {
	id := strings.TrimSpace(token.ID)
	if id == "" {
		generated, err := randomToken(12)
		if err != nil {
			return TokenMetadata{}, err
		}
		id = "panel-" + generated[:12]
	}
	if !tokenIDPattern.MatchString(id) {
		return TokenMetadata{}, fmt.Errorf("invalid token id %q", id)
	}
	if token.Token == "" && token.tokenHash == "" {
		return TokenMetadata{}, fmt.Errorf("token %q has no secret", id)
	}
	role := strings.ToLower(strings.TrimSpace(token.Role))
	if role != "" {
		roleScopes, ok := ScopesForRole(role)
		if !ok {
			return TokenMetadata{}, fmt.Errorf("unknown web panel role %q", role)
		}
		if role == "admin" && !containsAllScopes(token.grantedScopes(), roleScopes) {
			return TokenMetadata{}, errors.New("admin role requires all admin scopes")
		}
	}
	for _, existing := range registry.tokens {
		if existing.ID == id {
			return TokenMetadata{}, fmt.Errorf("duplicate token id %q", id)
		}
		if token.Token != "" && existing.matches(token.Token) {
			return TokenMetadata{}, errors.New("duplicate panel token")
		}
	}
	digest := token.tokenHash
	if digest == "" {
		digest = tokenDigest(token.Token)
	}
	entry := AuthToken{
		ID: id, Token: token.Token, tokenHash: digest, Role: role,
		Scopes: append([]string(nil), token.grantedScopes()...), ExpiresAt: token.ExpiresAt.UTC(), Revoked: token.Revoked, createdAt: now, updatedAt: now,
	}
	registry.tokens = append(registry.tokens, entry)
	return registry.metadata(entry), nil
}

func (registry *TokenRegistry) authTokens() []AuthToken {
	registry.mu.RLock()
	defer registry.mu.RUnlock()
	tokens := make([]AuthToken, len(registry.tokens))
	copy(tokens, registry.tokens)
	for i := range tokens {
		tokens[i].Scopes = append([]string(nil), tokens[i].Scopes...)
	}
	return tokens
}

func (registry *TokenRegistry) List() []TokenMetadata {
	registry.mu.RLock()
	defer registry.mu.RUnlock()
	result := make([]TokenMetadata, 0, len(registry.tokens))
	for _, token := range registry.tokens {
		result = append(result, registry.metadata(token))
	}
	return result
}

func (registry *TokenRegistry) Issue(request TokenIssue) (IssuedToken, error) {
	role := strings.ToLower(strings.TrimSpace(request.Role))
	roleScopes, ok := ScopesForRole(role)
	if !ok {
		return IssuedToken{}, fmt.Errorf("unknown role %q", request.Role)
	}
	scopes := request.Scopes
	if len(scopes) == 0 {
		scopes = roleScopes
	}
	normalizedScopes, err := validateTokenScopes(scopes)
	if err != nil {
		return IssuedToken{}, err
	}
	if role == "admin" && !containsAllScopes(normalizedScopes, roleScopes) {
		return IssuedToken{}, errors.New("admin role requires all admin scopes")
	}
	expiresAt, err := parseTokenExpiry(request.ExpiresAt)
	if err != nil {
		return IssuedToken{}, err
	}
	id := strings.TrimSpace(request.ID)
	if id == "" {
		value, err := randomToken(9)
		if err != nil {
			return IssuedToken{}, err
		}
		id = "token-" + value
	}
	if !tokenIDPattern.MatchString(id) {
		return IssuedToken{}, fmt.Errorf("invalid token id %q", id)
	}
	secret, err := randomToken(32)
	if err != nil {
		return IssuedToken{}, err
	}
	registry.mu.Lock()
	defer registry.mu.Unlock()
	for _, existing := range registry.tokens {
		if existing.ID == id {
			return IssuedToken{}, fmt.Errorf("token id %q already exists", id)
		}
	}
	now := time.Now().UTC()
	registry.tokens = append(registry.tokens, AuthToken{ID: id, tokenHash: tokenDigest(secret), Role: role, Scopes: normalizedScopes, ExpiresAt: expiresAt, createdAt: now, updatedAt: now})
	if err := registry.persistLocked(); err != nil {
		registry.tokens = registry.tokens[:len(registry.tokens)-1]
		return IssuedToken{}, err
	}
	return IssuedToken{Token: secret, Entry: TokenMetadata{ID: id, Role: role, Scopes: normalizedScopes, ExpiresAt: optionalTime(expiresAt), CreatedAt: now, UpdatedAt: now}}, nil
}

func (registry *TokenRegistry) Rotate(id string) (IssuedToken, error) {
	registry.mu.Lock()
	defer registry.mu.Unlock()
	index := registry.indexLocked(id)
	if index < 0 {
		return IssuedToken{}, errTokenNotFound
	}
	if registry.tokens[index].Revoked {
		return IssuedToken{}, errors.New("revoked token cannot be rotated")
	}
	secret, err := randomToken(32)
	if err != nil {
		return IssuedToken{}, err
	}
	previous := registry.tokens[index]
	registry.tokens[index].Token = ""
	registry.tokens[index].tokenHash = tokenDigest(secret)
	registry.tokens[index].updatedAt = time.Now().UTC()
	if err := registry.persistLocked(); err != nil {
		registry.tokens[index] = previous
		return IssuedToken{}, err
	}
	entry := registry.metadata(registry.tokens[index])
	return IssuedToken{Token: secret, Entry: entry}, nil
}

func (registry *TokenRegistry) Update(id string, request TokenUpdate) (TokenMetadata, error) {
	role := strings.ToLower(strings.TrimSpace(request.Role))
	roleScopes, ok := ScopesForRole(role)
	if !ok {
		return TokenMetadata{}, fmt.Errorf("unknown role %q", request.Role)
	}
	scopes := request.Scopes
	if len(scopes) == 0 {
		scopes = roleScopes
	}
	normalizedScopes, err := validateTokenScopes(scopes)
	if err != nil {
		return TokenMetadata{}, err
	}
	if role == "admin" && !containsAllScopes(normalizedScopes, roleScopes) {
		return TokenMetadata{}, errors.New("admin role requires all admin scopes")
	}
	expiresAt, err := parseTokenExpiry(request.ExpiresAt)
	if err != nil {
		return TokenMetadata{}, err
	}
	registry.mu.Lock()
	defer registry.mu.Unlock()
	index := registry.indexLocked(id)
	if index < 0 {
		return TokenMetadata{}, errTokenNotFound
	}
	previous := registry.tokens[index]
	now := time.Now().UTC()
	wasActiveAdmin := previous.Role == "admin" && !previous.Revoked && (previous.ExpiresAt.IsZero() || now.Before(previous.ExpiresAt))
	willBeActiveAdmin := role == "admin" && !previous.Revoked && (expiresAt.IsZero() || now.Before(expiresAt))
	if wasActiveAdmin && !willBeActiveAdmin && registry.activeAdminCountLocked(now) <= 1 {
		return TokenMetadata{}, errors.New("cannot remove the last active admin")
	}
	registry.tokens[index].Role = role
	registry.tokens[index].Scopes = normalizedScopes
	registry.tokens[index].ExpiresAt = expiresAt
	registry.tokens[index].updatedAt = now
	if err := registry.persistLocked(); err != nil {
		registry.tokens[index] = previous
		return TokenMetadata{}, err
	}
	return registry.metadata(registry.tokens[index]), nil
}

func (registry *TokenRegistry) Revoke(id string) (TokenMetadata, error) {
	registry.mu.Lock()
	defer registry.mu.Unlock()
	index := registry.indexLocked(id)
	if index < 0 {
		return TokenMetadata{}, errTokenNotFound
	}
	if registry.tokens[index].Revoked {
		return registry.metadata(registry.tokens[index]), nil
	}
	now := time.Now().UTC()
	active := registry.tokens[index].ExpiresAt.IsZero() || now.Before(registry.tokens[index].ExpiresAt)
	if registry.tokens[index].Role == "admin" && active && registry.activeAdminCountLocked(now) <= 1 {
		return TokenMetadata{}, errors.New("cannot revoke the last active admin token")
	}
	previous := registry.tokens[index]
	registry.tokens[index].Revoked = true
	registry.tokens[index].updatedAt = time.Now().UTC()
	if err := registry.persistLocked(); err != nil {
		registry.tokens[index] = previous
		return TokenMetadata{}, err
	}
	return registry.metadata(registry.tokens[index]), nil
}

func (registry *TokenRegistry) indexLocked(id string) int {
	for i := range registry.tokens {
		if registry.tokens[i].ID == id {
			return i
		}
	}
	return -1
}

func (registry *TokenRegistry) activeAdminCountLocked(now time.Time) int {
	count := 0
	for _, token := range registry.tokens {
		if token.Role == "admin" && !token.Revoked && (token.ExpiresAt.IsZero() || now.Before(token.ExpiresAt)) {
			count++
		}
	}
	return count
}

func (registry *TokenRegistry) metadata(token AuthToken) TokenMetadata {
	return TokenMetadata{ID: token.ID, Role: token.Role, Scopes: append([]string(nil), token.grantedScopes()...), ExpiresAt: optionalTime(token.ExpiresAt), Revoked: token.Revoked, CreatedAt: token.createdAt, UpdatedAt: token.updatedAt}
}

func optionalTime(value time.Time) *time.Time {
	if value.IsZero() {
		return nil
	}
	value = value.UTC()
	return &value
}

func (registry *TokenRegistry) storedLocked(token AuthToken) storedAuthToken {
	return storedAuthToken{ID: token.ID, TokenHash: token.tokenHash, Role: token.Role, Scopes: token.grantedScopes(), ExpiresAt: token.ExpiresAt, Revoked: token.Revoked, CreatedAt: token.createdAt, UpdatedAt: token.updatedAt}
}

func (registry *TokenRegistry) persistLocked() error {
	registry.revision++
	stored := storedTokenRegistry{SchemaVersion: "webpanel-token-registry/1", Tokens: make([]storedAuthToken, 0, len(registry.tokens))}
	for _, token := range registry.tokens {
		stored.Tokens = append(stored.Tokens, registry.storedLocked(token))
	}
	data, err := json.Marshal(stored)
	if err != nil {
		registry.revision--
		return err
	}
	if registry.state != nil {
		if err := registry.state.SaveSnapshot(tokenRegistryEntity, stored.SchemaVersion, registry.revision, data); err != nil {
			registry.revision--
			return fmt.Errorf("persist panel token registry: %w", err)
		}
	}
	return nil
}

func tokenDigest(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])
}

func providedHashHex(sum [sha256.Size]byte) string { return hex.EncodeToString(sum[:]) }

func randomToken(size int) (string, error) {
	bytes := make([]byte, size)
	if _, err := io.ReadFull(rand.Reader, bytes); err != nil {
		return "", fmt.Errorf("generate panel token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(bytes), nil
}

func validateTokenScopes(scopes []string) ([]string, error) {
	valid := map[string]bool{"read": true, "write": true, "raw": true, "export": true}
	seen := make(map[string]bool, len(scopes))
	result := make([]string, 0, len(scopes))
	for _, scope := range scopes {
		scope = strings.ToLower(strings.TrimSpace(scope))
		if !valid[scope] {
			return nil, fmt.Errorf("unknown token scope %q", scope)
		}
		if !seen[scope] {
			seen[scope] = true
			result = append(result, scope)
		}
	}
	if len(result) == 0 {
		return nil, errors.New("at least one token scope is required")
	}
	return result, nil
}

func containsAllScopes(granted, required []string) bool {
	set := make(map[string]bool, len(granted))
	for _, scope := range granted {
		set[scope] = true
	}
	for _, scope := range required {
		if !set[scope] {
			return false
		}
	}
	return true
}

func parseTokenExpiry(value string) (time.Time, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return time.Time{}, nil
	}
	expiresAt, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return time.Time{}, fmt.Errorf("expires_at must use RFC3339: %w", err)
	}
	if !expiresAt.After(time.Now().UTC()) {
		return time.Time{}, errors.New("expires_at must be in the future")
	}
	return expiresAt.UTC(), nil
}
