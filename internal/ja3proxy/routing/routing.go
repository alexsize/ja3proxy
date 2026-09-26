// Package routing provides deterministic two-phase connection routing.
package routing

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"sort"
	"strings"
	"sync"

	"github.com/lylemi/ja3proxy/internal/ja3proxy/state"
)

type Phase string

const (
	PhasePreTLS          Phase = "PRE_TLS"
	PhasePostClientHello Phase = "POST_CLIENTHELLO"

	CaptureFailureContinuePassthrough      = "continue_passthrough"
	CaptureFailureContinueWithoutRecording = "continue_without_recording"
	CaptureFailureBlock                    = "block"
)

type Action struct {
	Mode                 string `json:"mode,omitempty"`
	Upstream             string `json:"upstream,omitempty"`
	TLSProfile           string `json:"tls_profile,omitempty"`
	MatchPolicy          string `json:"match_policy,omitempty"`
	CaptureFailurePolicy string `json:"capture_failure_policy,omitempty"`
}

type Match struct {
	Host        string   `json:"host,omitempty"`
	CIDR        string   `json:"cidr,omitempty"`
	Port        int      `json:"port,omitempty"`
	DeviceID    string   `json:"device_id,omitempty"`
	DeviceTag   string   `json:"device_tag,omitempty"`
	Username    string   `json:"username,omitempty"`
	ALPN        []string `json:"alpn,omitempty"`
	TLSVersions []uint16 `json:"tls_versions,omitempty"`
	JA3         string   `json:"ja3,omitempty"`
	JA3Hash     string   `json:"ja3_hash,omitempty"`
	JA4         string   `json:"ja4,omitempty"`
}

type Rule struct {
	ID             string `json:"id"`
	Priority       int    `json:"priority"`
	Enabled        bool   `json:"enabled"`
	Phase          Phase  `json:"phase"`
	Match          Match  `json:"match"`
	Action         Action `json:"action"`
	CreatedVersion uint64 `json:"created_version,omitempty"`
}

type Config struct {
	Default Action `json:"default,omitempty"`
	Rules   []Rule `json:"rules"`
}

type Request struct {
	Host        string
	SNI         string
	IP          netip.Addr
	Port        int
	DeviceID    string
	DeviceTags  []string
	Username    string
	ALPN        []string
	TLSVersions []uint16
	JA3         string
	JA3Hash     string
	JA4         string
}

type Decision struct {
	ConfigVersion       uint64   `json:"config_version"`
	Phase               Phase    `json:"phase"`
	MatchedRuleID       string   `json:"matched_rule_id,omitempty"`
	MatchedRulePriority int      `json:"matched_rule_priority,omitempty"`
	MatchReason         string   `json:"match_reason"`
	CandidateRuleIDs    []string `json:"candidate_rule_ids,omitempty"`
	Action              Action   `json:"action"`
}

type Store struct {
	mu      sync.RWMutex
	current *Config
	version uint64
	stateDB *state.SQLiteStore
}

var ErrVersionConflict = errors.New("route configuration version conflict")

const stateSchemaVersion = "routing-config/1"

func LoadFile(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, err
	}
	var config Config
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&config); err != nil {
		return Config{}, err
	}
	return config, nil
}

func (s *Store) ApplyFile(path string) error {
	config, err := LoadFile(path)
	if err != nil {
		return err
	}
	return s.SetValidated(config)
}

// RestoreWithState prefers the SQLite snapshot and imports a legacy JSON
// configuration only when no snapshot exists yet.
func (s *Store) RestoreWithState(path string, stateDB *state.SQLiteStore) error {
	s.mu.Lock()
	s.stateDB = stateDB
	s.mu.Unlock()
	if stateDB != nil {
		document, found, err := stateDB.Load("routes")
		if err != nil {
			return err
		}
		if found {
			if document.SchemaVersion != stateSchemaVersion {
				return fmt.Errorf("unsupported sqlite route configuration schema %q", document.SchemaVersion)
			}
			var config Config
			if err := json.Unmarshal(document.Payload, &config); err != nil {
				return fmt.Errorf("decode sqlite route configuration: %w", err)
			}
			if err := Validate(config); err != nil {
				return err
			}
			s.mu.Lock()
			clone := cloneConfig(config)
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

func (s *Store) SetValidated(config Config) error {
	if err := Validate(config); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	clone := cloneConfig(config)
	if s.stateDB != nil {
		payload, err := json.Marshal(clone)
		if err != nil {
			return fmt.Errorf("encode route configuration: %w", err)
		}
		if err := s.stateDB.SaveSnapshot("routes", stateSchemaVersion, s.version+1, payload); err != nil {
			return fmt.Errorf("persist route configuration in SQLite: %w", err)
		}
	}
	s.current = &clone
	s.version++
	return nil
}

// ReplaceValidated installs a validated route snapshot after an optimistic
// version check and advances the local publication version.
func (s *Store) ReplaceValidated(config Config, expectedVersion uint64) error {
	if err := Validate(config); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.version != expectedVersion {
		return ErrVersionConflict
	}
	clone := cloneConfig(config)
	if s.stateDB != nil {
		payload, err := json.Marshal(clone)
		if err != nil {
			return fmt.Errorf("encode route configuration: %w", err)
		}
		if err := s.stateDB.SaveSnapshot("routes", stateSchemaVersion, s.version+1, payload); err != nil {
			return fmt.Errorf("persist route configuration in SQLite: %w", err)
		}
	}
	s.current = &clone
	s.version++
	return nil
}

func (s *Store) Snapshot() (Config, uint64, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.current == nil {
		return Config{}, s.version, false
	}
	return cloneConfig(*s.current), s.version, true
}

func (s *Store) Resolve(phase Phase, request Request) Decision {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.current == nil {
		return Decision{ConfigVersion: s.version, Phase: phase, MatchReason: "no_config"}
	}
	return ResolveSnapshot(*s.current, s.version, phase, request)
}

// ResolveSnapshot evaluates a caller-owned immutable configuration snapshot.
// It lets all route phases of one connection use the same published version.
func ResolveSnapshot(config Config, version uint64, phase Phase, request Request) Decision {
	return resolve(config, version, phase, request)
}

// HasPhase reports whether the current immutable snapshot contains an enabled
// rule for phase. Tunnel code uses it to decide whether a ClientHello must be
// buffered before selecting a POST_CLIENTHELLO mode.
func (s *Store) HasPhase(phase Phase) bool {
	config, _, ok := s.Snapshot()
	if !ok {
		return false
	}
	for _, rule := range config.Rules {
		if rule.Enabled && rule.Phase == phase {
			return true
		}
	}
	return false
}

func Validate(config Config) error {
	seenIDs := make(map[string]struct{}, len(config.Rules))
	for index, rule := range config.Rules {
		if strings.TrimSpace(rule.ID) == "" {
			return fmt.Errorf("route rule %d: id is required", index)
		}
		if _, exists := seenIDs[rule.ID]; exists {
			return fmt.Errorf("route rule %q: duplicate id", rule.ID)
		}
		seenIDs[rule.ID] = struct{}{}
		if rule.Phase != PhasePreTLS && rule.Phase != PhasePostClientHello {
			return fmt.Errorf("route rule %q: unsupported phase %q", rule.ID, rule.Phase)
		}
		if err := validateMatch(rule.ID, rule.Match); err != nil {
			return err
		}
		if err := validateAction(rule.ID, rule.Action); err != nil {
			return err
		}
	}
	for i, left := range config.Rules {
		if !left.Enabled {
			continue
		}
		for _, right := range config.Rules[i+1:] {
			if !right.Enabled || left.Phase != right.Phase || left.Priority != right.Priority {
				continue
			}
			if staticSpecificity(left.Match) != staticSpecificity(right.Match) || !matchesCanOverlap(left.Match, right.Match) {
				continue
			}
			if hostPatternSpecificity(left.Match.Host) != hostPatternSpecificity(right.Match.Host) {
				continue
			}
			return fmt.Errorf("route rules %q and %q are ambiguous at priority %d", left.ID, right.ID, left.Priority)
		}
	}
	return nil
}

func validateAction(id string, action Action) error {
	switch strings.ToUpper(strings.TrimSpace(action.Mode)) {
	case "", "ALLOW_AND_RECORD", "MITM_REISSUE", "PASSTHROUGH", "OBSERVE_ONLY", "BLOCK":
		// mode is valid
	default:
		return fmt.Errorf("route rule %q: unsupported action mode %q", id, action.Mode)
	}
	switch strings.ToLower(strings.TrimSpace(action.MatchPolicy)) {
	case "", "allow", "allow_and_record", "passthrough", "block":
		// match policy is valid
	default:
		return fmt.Errorf("route rule %q: unsupported match_policy %q", id, action.MatchPolicy)
	}
	// Keep capture failure behavior explicit and bounded. Empty means the
	// backwards-compatible safe default: preserve the TCP stream.
	switch NormalizeCaptureFailurePolicy(action.CaptureFailurePolicy) {
	case CaptureFailureContinuePassthrough, CaptureFailureContinueWithoutRecording, CaptureFailureBlock:
		return nil
	default:
		return fmt.Errorf("route rule %q: unsupported capture_failure_policy %q", id, action.CaptureFailurePolicy)
	}
}

func NormalizeCaptureFailurePolicy(policy string) string {
	policy = strings.ToLower(strings.TrimSpace(policy))
	if policy == "" {
		return CaptureFailureContinuePassthrough
	}
	return policy
}

func validateMatch(id string, match Match) error {
	if staticSpecificity(match) == 0 {
		return fmt.Errorf("route rule %q: at least one match field is required", id)
	}
	if match.Host != "" {
		if err := validateHostPattern(match.Host); err != nil {
			return fmt.Errorf("route rule %q: %w", id, err)
		}
	}
	if match.CIDR != "" {
		if _, err := netip.ParsePrefix(strings.TrimSpace(match.CIDR)); err != nil {
			return fmt.Errorf("route rule %q: invalid cidr %q", id, match.CIDR)
		}
	}
	if match.Port < 0 || match.Port > 65535 {
		return fmt.Errorf("route rule %q: port must be between 1 and 65535", id)
	}
	if len(match.ALPN) > 32 || len(match.TLSVersions) > 16 {
		return fmt.Errorf("route rule %q: too many TLS metadata match values", id)
	}
	for _, protocol := range match.ALPN {
		if strings.TrimSpace(protocol) == "" || len(protocol) > 255 {
			return fmt.Errorf("route rule %q: each ALPN match must have length 1..255", id)
		}
	}
	return nil
}

func resolve(config Config, version uint64, phase Phase, request Request) Decision {
	type candidate struct {
		rule  Rule
		score int
		index int
	}
	candidates := make([]candidate, 0, len(config.Rules))
	for index, rule := range config.Rules {
		if !rule.Enabled || rule.Phase != phase || !matches(rule.Match, phase, request) {
			continue
		}
		candidates = append(candidates, candidate{rule: rule, score: specificity(rule.Match, phase, request), index: index})
	}
	sort.SliceStable(candidates, func(i, j int) bool {
		if candidates[i].rule.Priority != candidates[j].rule.Priority {
			return candidates[i].rule.Priority < candidates[j].rule.Priority
		}
		if candidates[i].score != candidates[j].score {
			return candidates[i].score > candidates[j].score
		}
		return candidates[i].index < candidates[j].index
	})
	decision := Decision{ConfigVersion: version, Phase: phase, MatchReason: "default", Action: config.Default}
	for _, candidate := range candidates {
		decision.CandidateRuleIDs = append(decision.CandidateRuleIDs, candidate.rule.ID)
	}
	if len(candidates) == 0 {
		return decision
	}
	winner := candidates[0]
	decision.MatchedRuleID = winner.rule.ID
	decision.MatchedRulePriority = winner.rule.Priority
	decision.MatchReason = matchReason(winner.rule.Match, phase, request)
	decision.Action = winner.rule.Action
	return decision
}

func matches(match Match, phase Phase, request Request) bool {
	host := request.Host
	if phase == PhasePostClientHello && request.SNI != "" {
		host = request.SNI
	}
	if match.Host != "" && !hostPatternMatches(match.Host, host) {
		return false
	}
	if match.CIDR != "" {
		prefix, _ := netip.ParsePrefix(strings.TrimSpace(match.CIDR))
		if !request.IP.IsValid() || !prefix.Contains(request.IP) {
			return false
		}
	}
	if match.Port != 0 && match.Port != request.Port {
		return false
	}
	if match.DeviceID != "" && match.DeviceID != request.DeviceID {
		return false
	}
	if match.DeviceTag != "" && !contains(request.DeviceTags, match.DeviceTag) {
		return false
	}
	if match.Username != "" && match.Username != request.Username {
		return false
	}
	if len(match.ALPN) > 0 && !anyOverlap(match.ALPN, request.ALPN) {
		return false
	}
	if len(match.TLSVersions) > 0 && !anyUint16Overlap(match.TLSVersions, request.TLSVersions) {
		return false
	}
	if match.JA3 != "" && match.JA3 != request.JA3 {
		return false
	}
	if match.JA3Hash != "" && match.JA3Hash != request.JA3Hash {
		return false
	}
	return match.JA4 == "" || match.JA4 == request.JA4
}

func specificity(match Match, phase Phase, request Request) int {
	score := staticSpecificity(match) * 1000
	if match.Host != "" {
		host := request.Host
		if phase == PhasePostClientHello && request.SNI != "" {
			host = request.SNI
		}
		if normalizeHost(match.Host) == normalizeHost(host) {
			score += 900
		} else {
			score += hostPatternSpecificity(match.Host)
		}
	}
	return score
}

func staticSpecificity(match Match) int {
	count := 0
	if match.Host != "" {
		count++
	}
	if match.CIDR != "" {
		count++
	}
	if match.Port != 0 {
		count++
	}
	if match.DeviceID != "" {
		count++
	}
	if match.DeviceTag != "" {
		count++
	}
	if match.Username != "" {
		count++
	}
	if len(match.ALPN) > 0 {
		count++
	}
	if len(match.TLSVersions) > 0 {
		count++
	}
	if match.JA3 != "" {
		count++
	}
	if match.JA3Hash != "" {
		count++
	}
	if match.JA4 != "" {
		count++
	}
	return count
}

func matchReason(match Match, phase Phase, request Request) string {
	reasons := make([]string, 0, 11)
	if match.Host != "" {
		host := request.Host
		if phase == PhasePostClientHello && request.SNI != "" {
			host = request.SNI
		}
		if normalizeHost(match.Host) == normalizeHost(host) {
			reasons = append(reasons, "host_exact")
		} else {
			reasons = append(reasons, "host_wildcard")
		}
	}
	if match.CIDR != "" {
		reasons = append(reasons, "cidr")
	}
	if match.Port != 0 {
		reasons = append(reasons, "port")
	}
	if match.DeviceID != "" {
		reasons = append(reasons, "device")
	}
	if match.DeviceTag != "" {
		reasons = append(reasons, "device_tag")
	}
	if match.Username != "" {
		reasons = append(reasons, "username")
	}
	if len(match.ALPN) > 0 {
		reasons = append(reasons, "alpn")
	}
	if len(match.TLSVersions) > 0 {
		reasons = append(reasons, "tls_versions")
	}
	if match.JA3 != "" {
		reasons = append(reasons, "ja3")
	}
	if match.JA3Hash != "" {
		reasons = append(reasons, "ja3_hash")
	}
	if match.JA4 != "" {
		reasons = append(reasons, "ja4")
	}
	return strings.Join(reasons, "+")
}

func matchesCanOverlap(left, right Match) bool {
	if left.Host != "" && right.Host != "" && !hostPatternsOverlap(left.Host, right.Host) {
		return false
	}
	if left.CIDR != "" && right.CIDR != "" {
		leftPrefix, _ := netip.ParsePrefix(strings.TrimSpace(left.CIDR))
		rightPrefix, _ := netip.ParsePrefix(strings.TrimSpace(right.CIDR))
		if !leftPrefix.Overlaps(rightPrefix) {
			return false
		}
	}
	if left.Port != 0 && right.Port != 0 && left.Port != right.Port {
		return false
	}
	if left.DeviceID != "" && right.DeviceID != "" && left.DeviceID != right.DeviceID {
		return false
	}
	if left.DeviceTag != "" && right.DeviceTag != "" && left.DeviceTag != right.DeviceTag {
		return false
	}
	if left.Username != "" && right.Username != "" && left.Username != right.Username {
		return false
	}
	if !stringSlicesCanOverlap(left.ALPN, right.ALPN) || !uint16SlicesCanOverlap(left.TLSVersions, right.TLSVersions) {
		return false
	}
	if left.JA3 != "" && right.JA3 != "" && left.JA3 != right.JA3 {
		return false
	}
	if left.JA3Hash != "" && right.JA3Hash != "" && left.JA3Hash != right.JA3Hash {
		return false
	}
	return left.JA4 == "" || right.JA4 == "" || left.JA4 == right.JA4
}

func anyOverlap(wanted, offered []string) bool {
	for _, value := range wanted {
		if contains(offered, value) {
			return true
		}
	}
	return false
}

func anyUint16Overlap(wanted, offered []uint16) bool {
	for _, value := range wanted {
		for _, candidate := range offered {
			if value == candidate {
				return true
			}
		}
	}
	return false
}

func stringSlicesCanOverlap(left, right []string) bool {
	return len(left) == 0 || len(right) == 0 || anyOverlap(left, right)
}

func uint16SlicesCanOverlap(left, right []uint16) bool {
	return len(left) == 0 || len(right) == 0 || anyUint16Overlap(left, right)
}

func hostPatternsOverlap(left, right string) bool {
	left = normalizeHost(left)
	right = normalizeHost(right)
	if left == right {
		return true
	}
	if strings.HasPrefix(left, "*.") {
		return hostPatternMatches(left, right) || strings.HasPrefix(right, "*.") && hostPatternMatches(right, strings.TrimPrefix(left, "*."))
	}
	return strings.HasPrefix(right, "*.") && hostPatternMatches(right, left)
}

func hostPatternMatches(pattern, host string) bool {
	pattern = normalizeHost(pattern)
	host = normalizeHost(host)
	if pattern == host {
		return true
	}
	if !strings.HasPrefix(pattern, "*.") {
		return false
	}
	suffix := strings.TrimPrefix(pattern, "*")
	return strings.HasSuffix(host, suffix) && host != strings.TrimPrefix(suffix, ".")
}

func hostPatternSpecificity(pattern string) int {
	pattern = normalizeHost(pattern)
	if !strings.HasPrefix(pattern, "*.") {
		return 900
	}
	return 100 + len(strings.TrimPrefix(pattern, "*."))
}

func validateHostPattern(pattern string) error {
	pattern = normalizeHost(pattern)
	if strings.Contains(pattern, "*") && !strings.HasPrefix(pattern, "*.") {
		return fmt.Errorf("wildcard host must start with '*.'")
	}
	if pattern == "*." || pattern == "" {
		return fmt.Errorf("host pattern is empty or wildcard suffix is missing")
	}
	return nil
}

func normalizeHost(host string) string {
	host = strings.ToLower(strings.TrimSpace(host))
	return strings.TrimSuffix(host, ".")
}

func contains(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

func cloneConfig(config Config) Config {
	clone := config
	clone.Rules = make([]Rule, len(config.Rules))
	for i, rule := range config.Rules {
		clone.Rules[i] = rule
		clone.Rules[i].Match.ALPN = append([]string(nil), rule.Match.ALPN...)
		clone.Rules[i].Match.TLSVersions = append([]uint16(nil), rule.Match.TLSVersions...)
	}
	return clone
}
