package upstreamtls

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/lylemi/ja3proxy/internal/ja3proxy/fingerprint"
	"github.com/lylemi/ja3proxy/internal/ja3proxy/state"
)

const upstreamTLSProtocolUTLS = "utls"

const ProtocolUTLS = upstreamTLSProtocolUTLS

var ErrVersionConflict = errors.New("upstream TLS configuration version conflict")

type UpstreamTLSProfile struct {
	Protocol string `json:"protocol"`
	Client   string `json:"client"`
	Version  string `json:"version"`
}

type UpstreamTLSRoute struct {
	ID       string `json:"id,omitempty"`
	Host     string `json:"host"`
	Priority int    `json:"priority,omitempty"`
	UpstreamTLSProfile
}

type RouteResolution struct {
	Profile       UpstreamTLSProfile
	ConfigVersion uint64
	RouteID       string
	RouteHost     string
	Priority      int
	MatchReason   string
	Matched       bool
}

type UpstreamTLSConfig struct {
	Default UpstreamTLSProfile `json:"default"`
	Routes  []UpstreamTLSRoute `json:"routes"`
}

type UpstreamTLSProfileStore struct {
	mu      sync.RWMutex
	current *UpstreamTLSConfig
	version uint64
	stateDB *state.SQLiteStore
}

const stateSchemaVersion = "upstream-tls-config/1"

// Snapshot returns a detached immutable configuration snapshot and its
// publication version. The boolean is false until a configuration is loaded.
func (s *UpstreamTLSProfileStore) Snapshot() (UpstreamTLSConfig, uint64, bool) {
	if s == nil {
		return UpstreamTLSConfig{}, 0, false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.current == nil {
		return UpstreamTLSConfig{}, s.version, false
	}
	return cloneUpstreamTLSConfig(*s.current), s.version, true
}

func (s *UpstreamTLSProfileStore) Get(host string) (UpstreamTLSProfile, bool) {
	resolution := s.Resolve(host)
	return resolution.Profile, resolution.Matched
}

// GetWithVersion resolves a profile from one immutable configuration snapshot.
// The returned version identifies the snapshot used for the resolution.
func (s *UpstreamTLSProfileStore) GetWithVersion(host string) (UpstreamTLSProfile, uint64, bool) {
	resolution := s.Resolve(host)
	return resolution.Profile, resolution.ConfigVersion, resolution.Matched
}

// Resolve returns the exact route decision made from one immutable snapshot.
func (s *UpstreamTLSProfileStore) Resolve(host string) RouteResolution {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.current == nil {
		return RouteResolution{ConfigVersion: s.version}
	}
	resolution := s.current.resolve(host)
	resolution.ConfigVersion = s.version
	return resolution
}

func (s *UpstreamTLSProfileStore) Set(config UpstreamTLSConfig) {
	s.mu.Lock()
	defer s.mu.Unlock()

	cfg := cloneUpstreamTLSConfig(config)
	s.current = &cfg
	s.version++
}

func (s *UpstreamTLSProfileStore) SetValidated(config UpstreamTLSConfig) error {
	if err := Validate(config); err != nil {
		return err
	}
	if s == nil {
		return fmt.Errorf("upstream TLS profile store is unavailable")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	clone := cloneUpstreamTLSConfig(config)
	if s.stateDB != nil {
		payload, err := json.Marshal(clone)
		if err != nil {
			return fmt.Errorf("encode upstream TLS configuration: %w", err)
		}
		if err := s.stateDB.SaveSnapshot("upstream_tls", stateSchemaVersion, s.version+1, payload); err != nil {
			return fmt.Errorf("persist upstream TLS configuration in SQLite: %w", err)
		}
	}
	s.current = &clone
	s.version++
	return nil
}

// ReplaceValidated installs an upstream TLS snapshot after an optimistic
// version check and advances the local publication version.
func (s *UpstreamTLSProfileStore) ReplaceValidated(config UpstreamTLSConfig, expectedVersion uint64) error {
	if s == nil {
		return fmt.Errorf("upstream TLS profile store is unavailable")
	}
	if config.Default != (UpstreamTLSProfile{}) || len(config.Routes) > 0 {
		if err := Validate(config); err != nil {
			return err
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.version != expectedVersion {
		return ErrVersionConflict
	}
	clone := cloneUpstreamTLSConfig(config)
	if s.stateDB != nil {
		payload, err := json.Marshal(clone)
		if err != nil {
			return fmt.Errorf("encode upstream TLS configuration: %w", err)
		}
		if err := s.stateDB.SaveSnapshot("upstream_tls", stateSchemaVersion, s.version+1, payload); err != nil {
			return fmt.Errorf("persist upstream TLS configuration in SQLite: %w", err)
		}
	}
	s.current = &clone
	s.version++
	return nil
}

// Validate checks an upstream TLS configuration without changing a store.
func Validate(config UpstreamTLSConfig) error {
	return validateUpstreamTLSConfig(config)
}

func (s *UpstreamTLSProfileStore) ApplyFile(path string) error {
	config, err := loadUpstreamTLSConfigFile(path)
	if err != nil {
		return err
	}
	return s.SetValidated(config)
}

// RestoreWithState prefers the SQLite snapshot and imports a legacy JSON
// configuration only when no snapshot exists yet.
func (s *UpstreamTLSProfileStore) RestoreWithState(path string, stateDB *state.SQLiteStore) error {
	if s == nil {
		return fmt.Errorf("upstream TLS profile store is unavailable")
	}
	s.mu.Lock()
	s.stateDB = stateDB
	s.mu.Unlock()
	if stateDB != nil {
		document, found, err := stateDB.Load("upstream_tls")
		if err != nil {
			return err
		}
		if found {
			if document.SchemaVersion != stateSchemaVersion {
				return fmt.Errorf("unsupported sqlite upstream TLS schema %q", document.SchemaVersion)
			}
			var config UpstreamTLSConfig
			if err := json.Unmarshal(document.Payload, &config); err != nil {
				return fmt.Errorf("decode sqlite upstream TLS configuration: %w", err)
			}
			if config.Default != (UpstreamTLSProfile{}) || len(config.Routes) > 0 {
				if err := Validate(config); err != nil {
					return err
				}
			}
			s.mu.Lock()
			clone := cloneUpstreamTLSConfig(config)
			s.current = &clone
			s.version = document.Revision
			s.mu.Unlock()
			return nil
		}
	}
	if strings.TrimSpace(path) == "" {
		return nil
	}
	return s.ApplyFile(path)
}

func loadUpstreamTLSConfigFile(path string) (UpstreamTLSConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return UpstreamTLSConfig{}, err
	}

	var config UpstreamTLSConfig
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&config); err != nil {
		return UpstreamTLSConfig{}, err
	}
	return config, nil
}

func validateUpstreamTLSConfig(config UpstreamTLSConfig) error {
	if err := validateDefaultUpstreamTLSProfile(config.Default); err != nil {
		return err
	}
	if err := validateUpstreamTLSRoutes(config.Routes); err != nil {
		return err
	}
	if config.Default.isZero() && len(config.Routes) == 0 {
		return fmt.Errorf("upstream TLS config requires a default profile or at least one route")
	}
	return nil
}

func validateDefaultUpstreamTLSProfile(profile UpstreamTLSProfile) error {
	if profile.isZero() {
		return nil
	}
	if err := validateUpstreamTLSProfile(profile); err != nil {
		return fmt.Errorf("default upstream TLS profile: %w", err)
	}
	return nil
}

func validateUpstreamTLSRoutes(routes []UpstreamTLSRoute) error {
	for i, route := range routes {
		if err := validateUpstreamTLSRoute(i, route); err != nil {
			return err
		}
	}
	return nil
}

func validateUpstreamTLSRoute(index int, route UpstreamTLSRoute) error {
	if strings.TrimSpace(route.Host) == "" {
		return fmt.Errorf("upstream TLS route %d: host is required", index)
	}
	if err := validateHostPattern(route.Host); err != nil {
		return fmt.Errorf("upstream TLS route %q: %w", route.Host, err)
	}
	if err := validateUpstreamTLSProfile(route.UpstreamTLSProfile); err != nil {
		return fmt.Errorf("upstream TLS route %q: %w", route.Host, err)
	}
	return nil
}

func validateUpstreamTLSProfile(profile UpstreamTLSProfile) error {
	protocol := normalizeUpstreamTLSProtocol(profile.Protocol)
	switch protocol {
	case upstreamTLSProtocolUTLS:
		if profile.Client == "" {
			return fmt.Errorf("utls client is required")
		}
		if profile.Version == "" {
			return fmt.Errorf("utls version is required")
		}
		if err := fingerprint.ValidateTLSFingerprint(fingerprint.TLSFingerprint{
			Client:  profile.Client,
			Version: profile.Version,
		}); err != nil {
			return err
		}
		return nil
	default:
		return fmt.Errorf("unsupported upstream TLS protocol %q", profile.Protocol)
	}
}

func validateHostPattern(pattern string) error {
	pattern = normalizeRouteHost(pattern)
	if strings.Contains(pattern, "*") && !strings.HasPrefix(pattern, "*.") {
		return fmt.Errorf("wildcard host must start with '*.'")
	}
	if pattern == "*." {
		return fmt.Errorf("wildcard host suffix is required")
	}
	return nil
}

func (config UpstreamTLSConfig) profileForHost(host string) (UpstreamTLSProfile, bool) {
	resolution := config.resolve(host)
	return resolution.Profile, resolution.Matched
}

func (config UpstreamTLSConfig) resolve(host string) RouteResolution {
	host = normalizeRouteHost(host)
	bestIndex := -1
	bestPriority := 0
	bestSpecificity := -1
	for index, route := range config.Routes {
		matched, specificity := routeMatchScore(route.Host, host)
		if !matched {
			continue
		}
		if bestIndex < 0 || route.Priority > bestPriority ||
			(route.Priority == bestPriority && specificity > bestSpecificity) {
			bestIndex, bestPriority, bestSpecificity = index, route.Priority, specificity
		}
	}
	if bestIndex >= 0 {
		route := config.Routes[bestIndex]
		reason := "wildcard"
		if bestSpecificity == 2 {
			reason = "exact"
		}
		return RouteResolution{
			Profile:     route.normalizedProfile(),
			RouteID:     routeID(route),
			RouteHost:   normalizeRouteHost(route.Host),
			Priority:    route.Priority,
			MatchReason: reason,
			Matched:     true,
		}
	}

	if !config.Default.isZero() {
		return RouteResolution{
			Profile:     config.Default.normalized(),
			MatchReason: "default",
			Matched:     true,
		}
	}
	return RouteResolution{}
}

func routeMatchScore(pattern, host string) (bool, int) {
	pattern = normalizeRouteHost(pattern)
	host = normalizeRouteHost(host)
	if pattern == host {
		return true, 2
	}
	if hostPatternMatches(pattern, host) {
		return true, 1
	}
	return false, -1
}

func hostPatternMatches(pattern string, host string) bool {
	pattern = normalizeRouteHost(pattern)
	host = normalizeRouteHost(host)
	if pattern == host {
		return true
	}
	if !strings.HasPrefix(pattern, "*.") {
		return false
	}

	suffix := strings.TrimPrefix(pattern, "*")
	return strings.HasSuffix(host, suffix) && host != strings.TrimPrefix(suffix, ".")
}

func normalizeRouteHost(host string) string {
	host = strings.TrimSpace(strings.ToLower(host))
	if strings.HasSuffix(host, ".") {
		host = strings.TrimSuffix(host, ".")
	}
	if strings.HasPrefix(host, "[") {
		return host
	}
	if strings.Count(host, ":") == 1 {
		if withoutPort, _, found := strings.Cut(host, ":"); found && withoutPort != "" {
			return withoutPort
		}
	}
	return host
}

func normalizeUpstreamTLSProtocol(protocol string) string {
	if protocol == "" {
		return upstreamTLSProtocolUTLS
	}
	return strings.ToLower(strings.TrimSpace(protocol))
}

func NormalizeProtocol(protocol string) string {
	return normalizeUpstreamTLSProtocol(protocol)
}

func (profile UpstreamTLSProfile) normalized() UpstreamTLSProfile {
	profile.Protocol = normalizeUpstreamTLSProtocol(profile.Protocol)
	return profile
}

func (profile UpstreamTLSProfile) isZero() bool {
	return profile.Protocol == "" && profile.Client == "" && profile.Version == ""
}

func (route UpstreamTLSRoute) normalizedProfile() UpstreamTLSProfile {
	return route.UpstreamTLSProfile.normalized()
}

func routeID(route UpstreamTLSRoute) string {
	if id := strings.TrimSpace(route.ID); id != "" {
		return id
	}
	return "upstream-tls:" + normalizeRouteHost(route.Host)
}

func cloneUpstreamTLSConfig(config UpstreamTLSConfig) UpstreamTLSConfig {
	clone := config
	clone.Routes = append([]UpstreamTLSRoute(nil), config.Routes...)
	return clone
}

func ProfileFromFingerprint(fp fingerprint.TLSFingerprint) UpstreamTLSProfile {
	return UpstreamTLSProfile{
		Protocol: upstreamTLSProtocolUTLS,
		Client:   fp.Client,
		Version:  fp.Version,
	}
}
