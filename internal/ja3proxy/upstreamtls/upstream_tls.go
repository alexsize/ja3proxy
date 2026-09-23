package upstreamtls

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/lylemi/ja3proxy/internal/ja3proxy/fingerprint"
)

const upstreamTLSProtocolUTLS = "utls"

const ProtocolUTLS = upstreamTLSProtocolUTLS

type UpstreamTLSProfile struct {
	Protocol string `json:"protocol"`
	Client   string `json:"client"`
	Version  string `json:"version"`
}

type UpstreamTLSRoute struct {
	Host     string `json:"host"`
	Priority int    `json:"priority,omitempty"`
	UpstreamTLSProfile
}

type UpstreamTLSConfig struct {
	Default UpstreamTLSProfile `json:"default"`
	Routes  []UpstreamTLSRoute `json:"routes"`
}

type UpstreamTLSProfileStore struct {
	mu      sync.RWMutex
	current *UpstreamTLSConfig
	version uint64
}

func (s *UpstreamTLSProfileStore) Get(host string) (UpstreamTLSProfile, bool) {
	profile, _, ok := s.GetWithVersion(host)
	return profile, ok
}

// GetWithVersion resolves a profile from one immutable configuration snapshot.
// The returned version identifies the snapshot used for the resolution.
func (s *UpstreamTLSProfileStore) GetWithVersion(host string) (UpstreamTLSProfile, uint64, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.current == nil {
		return UpstreamTLSProfile{}, s.version, false
	}
	profile, ok := s.current.profileForHost(host)
	return profile, s.version, ok
}

func (s *UpstreamTLSProfileStore) Set(config UpstreamTLSConfig) {
	s.mu.Lock()
	defer s.mu.Unlock()

	cfg := cloneUpstreamTLSConfig(config)
	s.current = &cfg
	s.version++
}

func (s *UpstreamTLSProfileStore) SetValidated(config UpstreamTLSConfig) error {
	if err := validateUpstreamTLSConfig(config); err != nil {
		return err
	}
	s.Set(config)
	return nil
}

func (s *UpstreamTLSProfileStore) ApplyFile(path string) error {
	config, err := loadUpstreamTLSConfigFile(path)
	if err != nil {
		return err
	}
	return s.SetValidated(config)
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
		return config.Routes[bestIndex].normalizedProfile(), true
	}

	if !config.Default.isZero() {
		return config.Default.normalized(), true
	}
	return UpstreamTLSProfile{}, false
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
