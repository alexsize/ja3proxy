// Package tlsprofile manages versioned, replayable ClientHello templates.
package tlsprofile

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/lylemi/ja3proxy/internal/ja3proxy/capture/tlshello"
	"github.com/lylemi/ja3proxy/internal/ja3proxy/fingerprint"
)

const (
	SchemaVersion          = "tls-profile-template/1"
	MaterializerVersion    = "utls-template-materializer/1"
	VerificationVersion    = "tls-profile-verification/1"
	GREASEPlaceholder      = uint16(0x0a0a)
	DefaultTemplateLogPath = "profiles/tls-templates.jsonl"
)

var ErrVersionConflict = errors.New("tls profile configuration version conflict")

type StaticFields struct {
	CipherSuites        []uint16 `json:"cipher_suites"`
	ExtensionOrder      []uint16 `json:"extension_order"`
	ALPN                []string `json:"alpn"`
	SupportedVersions   []uint16 `json:"supported_versions"`
	SupportedGroups     []uint16 `json:"supported_groups"`
	SignatureAlgorithms []uint16 `json:"signature_algorithms"`
}

type MatchPolicy struct {
	MustMatch      []string     `json:"must_match"`
	ShouldMatch    []string     `json:"should_match"`
	IgnoredDynamic []string     `json:"ignored_dynamic"`
	Constraints    []Constraint `json:"constraints"`
}

type Constraint struct {
	Path     string            `json:"path"`
	Operator string            `json:"operator"`
	Value    json.RawMessage   `json:"value,omitempty"`
	Values   []json.RawMessage `json:"values,omitempty"`
}

func DefaultMatchPolicy() MatchPolicy {
	return MatchPolicy{
		MustMatch:      []string{"/ciphers", "/extensions"},
		ShouldMatch:    []string{"/legacy_version", "/compression_methods", "/session_id_length"},
		IgnoredDynamic: []string{"client_random", "session_id_bytes", "key_share_bytes", "psk_identities", "psk_binders", "session_tickets", "grease_values"},
		Constraints:    []Constraint{},
	}
}

type Expected struct {
	JA3                  string          `json:"ja3"`
	JA3Hash              string          `json:"ja3_hash"`
	JA4                  string          `json:"ja4"`
	NormalizedSHA256     string          `json:"normalized_sha256"`
	Normalized           json.RawMessage `json:"normalized"`
	NormalizationVersion string          `json:"normalization_version"`
	MaterializerVersion  string          `json:"materializer_version"`
	CalculatedAt         time.Time       `json:"calculated_at"`
}

type Replayability struct {
	Status      string   `json:"status"`
	Unsupported []string `json:"unsupported,omitempty"`
	Warnings    []string `json:"warnings,omitempty"`
}

type ObservedSource struct {
	ObservationID        string          `json:"observation_id"`
	ServerName           string          `json:"server_name,omitempty"`
	JA3                  string          `json:"ja3"`
	JA3Hash              string          `json:"ja3_hash"`
	JA4                  string          `json:"ja4"`
	NormalizedSHA256     string          `json:"normalized_sha256"`
	Normalized           json.RawMessage `json:"normalized"`
	NormalizationVersion string          `json:"normalization_version"`
}

type Template struct {
	SchemaVersion       string                     `json:"schema_version"`
	ID                  string                     `json:"id"`
	Name                string                     `json:"name"`
	Version             uint64                     `json:"version"`
	BasedOnVersion      uint64                     `json:"based_on_version,omitempty"`
	Enabled             bool                       `json:"enabled"`
	HostPatterns        []string                   `json:"host_patterns"`
	BasePreset          fingerprint.TLSFingerprint `json:"base_preset"`
	Fields              StaticFields               `json:"fields"`
	Policy              MatchPolicy                `json:"policy"`
	SourceObservationID string                     `json:"source_observation_id,omitempty"`
	Source              *ObservedSource            `json:"source,omitempty"`
	Expected            *Expected                  `json:"expected,omitempty"`
	Replayability       Replayability              `json:"replayability"`
	CreatedAt           time.Time                  `json:"created_at"`
	UpdatedAt           time.Time                  `json:"updated_at"`
}

type Library struct {
	SchemaVersion string     `json:"schema_version"`
	ConfigVersion uint64     `json:"config_version"`
	ActiveID      string     `json:"active_id,omitempty"`
	Templates     []Template `json:"templates"`
}

func FieldsFromHello(h *tlshello.Hello) (StaticFields, error) {
	if h == nil {
		return StaticFields{}, errors.New("ClientHello отсутствует")
	}
	alpn := make([]string, 0, len(h.ALPN))
	for _, value := range h.ALPN {
		decoded, err := hex.DecodeString(value)
		if err != nil {
			return StaticFields{}, fmt.Errorf("некорректный ALPN: %w", err)
		}
		alpn = append(alpn, string(decoded))
	}
	extensions := make([]uint16, len(h.Extensions))
	for i, extension := range h.Extensions {
		extensions[i] = normalizeGREASE(extension.ID)
	}
	ciphers := append([]uint16(nil), h.CipherSuites...)
	for i := range ciphers {
		ciphers[i] = normalizeGREASE(ciphers[i])
	}
	groups := append([]uint16(nil), h.SupportedGroups...)
	for i := range groups {
		groups[i] = normalizeGREASE(groups[i])
	}
	versions := append([]uint16(nil), h.SupportedVersions...)
	for i := range versions {
		versions[i] = normalizeGREASE(versions[i])
	}
	return StaticFields{
		CipherSuites:        ciphers,
		ExtensionOrder:      extensions,
		ALPN:                alpn,
		SupportedVersions:   versions,
		SupportedGroups:     groups,
		SignatureAlgorithms: append([]uint16(nil), h.SignatureAlgorithms...),
	}, nil
}

// ConstrainALPN returns a connection-specific copy of a template whose ALPN
// list contains only protocols offered by the inbound client. The template
// order remains authoritative because it is part of the desired fingerprint.
func ConstrainALPN(template Template, offered []string) (Template, error) {
	if len(template.Fields.ALPN) == 0 {
		return template, nil
	}
	allowed := make(map[string]struct{}, len(offered))
	for _, protocol := range offered {
		allowed[protocol] = struct{}{}
	}
	matched := make([]string, 0, len(template.Fields.ALPN))
	for _, protocol := range template.Fields.ALPN {
		if _, ok := allowed[protocol]; ok {
			matched = append(matched, protocol)
		}
	}
	if len(matched) == 0 {
		return Template{}, fmt.Errorf("ALPN профиля %q не пересекается с ALPN входящего клиента", strings.Join(template.Fields.ALPN, ", "))
	}
	template.Fields.ALPN = matched
	return template, nil
}

func normalizeGREASE(value uint16) uint16 {
	if tlshello.IsGREASE(value) {
		return GREASEPlaceholder
	}
	return value
}

func validateTemplate(template Template) error {
	if strings.TrimSpace(template.Name) == "" {
		return errors.New("имя профиля обязательно")
	}
	if len(template.Name) > 128 {
		return errors.New("имя профиля длиннее 128 символов")
	}
	if err := fingerprint.ValidateTLSFingerprint(template.BasePreset); err != nil {
		return fmt.Errorf("базовый пресет: %w", err)
	}
	if len(template.Fields.CipherSuites) == 0 || len(template.Fields.CipherSuites) > 256 {
		return errors.New("cipher_suites должен содержать от 1 до 256 значений")
	}
	if len(template.Fields.ExtensionOrder) > 256 || len(template.Fields.ALPN) > 32 || len(template.Fields.SupportedVersions) > 16 || len(template.Fields.SupportedGroups) > 128 || len(template.Fields.SignatureAlgorithms) > 128 {
		return errors.New("одно из полей профиля превышает допустимый размер")
	}
	for _, protocol := range template.Fields.ALPN {
		if len(protocol) == 0 || len(protocol) > 255 {
			return errors.New("каждый ALPN должен иметь длину 1..255 байт")
		}
	}
	if len(template.HostPatterns) > 64 {
		return errors.New("слишком много host patterns")
	}
	for _, pattern := range template.HostPatterns {
		if err := validateHostPattern(pattern); err != nil {
			return err
		}
	}
	if len(template.Policy.MustMatch) == 0 {
		return errors.New("must_match не может быть пустым")
	}
	paths := append(append([]string{}, template.Policy.MustMatch...), template.Policy.ShouldMatch...)
	for _, constraint := range template.Policy.Constraints {
		paths = append(paths, constraint.Path)
		switch constraint.Operator {
		case "present":
			if len(constraint.Value) != 0 || len(constraint.Values) != 0 {
				return fmt.Errorf("constraint present для %q не принимает value", constraint.Path)
			}
		case "equals":
			if len(constraint.Value) == 0 || !json.Valid(constraint.Value) || len(constraint.Values) != 0 {
				return fmt.Errorf("constraint equals для %q требует одно JSON value", constraint.Path)
			}
		case "one_of":
			if len(constraint.Values) == 0 || len(constraint.Value) != 0 {
				return fmt.Errorf("constraint one_of для %q требует values", constraint.Path)
			}
			for _, value := range constraint.Values {
				if !json.Valid(value) {
					return fmt.Errorf("constraint one_of для %q содержит некорректный JSON", constraint.Path)
				}
			}
		default:
			return fmt.Errorf("неподдерживаемый constraint operator %q", constraint.Operator)
		}
	}
	for _, path := range paths {
		if path == "" || !strings.HasPrefix(path, "/") || strings.Contains(path, "..") {
			return fmt.Errorf("некорректный путь политики %q", path)
		}
	}
	return nil
}

func validatePolicyPaths(normalized json.RawMessage, policy MatchPolicy) error {
	var root any
	if err := json.Unmarshal(normalized, &root); err != nil {
		return fmt.Errorf("проверка политики: %w", err)
	}
	paths := append(append([]string{}, policy.MustMatch...), policy.ShouldMatch...)
	for _, constraint := range policy.Constraints {
		paths = append(paths, constraint.Path)
	}
	for _, path := range paths {
		if _, ok := normalizedValueAtPath(root, path); !ok {
			return fmt.Errorf("путь политики %q отсутствует в TLS-NORM", path)
		}
	}
	return nil
}

func normalizedValueAtPath(root any, path string) (any, bool) {
	current := root
	for _, encoded := range strings.Split(strings.TrimPrefix(path, "/"), "/") {
		key := strings.ReplaceAll(strings.ReplaceAll(encoded, "~1", "/"), "~0", "~")
		switch typed := current.(type) {
		case map[string]any:
			var ok bool
			current, ok = typed[key]
			if !ok {
				return nil, false
			}
		case []any:
			index, err := strconv.Atoi(key)
			if err != nil || index < 0 || index >= len(typed) {
				return nil, false
			}
			current = typed[index]
		default:
			return nil, false
		}
	}
	return current, true
}

func assessObservedSource(template Template, expected Expected) Replayability {
	status := Replayability{Status: "REPLAYABLE_WITH_DYNAMIC_FIELDS", Warnings: []string{"random, session ID, GREASE и key shares создаются uTLS динамически"}}
	if template.Source == nil {
		return status
	}
	if template.Source.NormalizationVersion != expected.NormalizationVersion {
		return Replayability{Status: "UNSUPPORTED", Unsupported: []string{"source observation использует несовместимую версию TLS-NORM"}}
	}
	var sourceValue, expectedValue any
	if json.Unmarshal(template.Source.Normalized, &sourceValue) != nil || json.Unmarshal(expected.Normalized, &expectedValue) != nil {
		return Replayability{Status: "UNSUPPORTED", Unsupported: []string{"source observation содержит некорректную TLS-NORM"}}
	}
	for _, path := range template.Policy.MustMatch {
		sourceField, sourceOK := normalizedValueAtPath(sourceValue, path)
		expectedField, expectedOK := normalizedValueAtPath(expectedValue, path)
		if !sourceOK || !expectedOK || !reflect.DeepEqual(sourceField, expectedField) {
			status.Status = "UNSUPPORTED"
			status.Unsupported = append(status.Unsupported, fmt.Sprintf("наблюдаемое MUST-поле %s не воспроизводится выбранным пресетом", path))
		}
	}
	for _, constraint := range template.Policy.Constraints {
		sourceField, sourceOK := normalizedValueAtPath(sourceValue, constraint.Path)
		if !templateConstraintMatches(constraint, sourceField, sourceOK) {
			status.Status = "UNSUPPORTED"
			status.Unsupported = append(status.Unsupported, fmt.Sprintf("source observation нарушает constraint %s %s", constraint.Path, constraint.Operator))
		}
	}
	if status.Status == "UNSUPPORTED" {
		return status
	}
	for _, path := range template.Policy.ShouldMatch {
		sourceField, sourceOK := normalizedValueAtPath(sourceValue, path)
		expectedField, expectedOK := normalizedValueAtPath(expectedValue, path)
		if !sourceOK || !expectedOK || !reflect.DeepEqual(sourceField, expectedField) {
			status.Warnings = append(status.Warnings, fmt.Sprintf("наблюдаемое SHOULD-поле %s отличается от materialized ClientHello", path))
		}
	}
	return status
}

func templateConstraintMatches(constraint Constraint, actual any, exists bool) bool {
	switch constraint.Operator {
	case "present":
		return exists
	case "equals":
		if !exists {
			return false
		}
		var expected any
		return json.Unmarshal(constraint.Value, &expected) == nil && reflect.DeepEqual(expected, actual)
	case "one_of":
		if !exists {
			return false
		}
		for _, encoded := range constraint.Values {
			var allowed any
			if json.Unmarshal(encoded, &allowed) == nil && reflect.DeepEqual(allowed, actual) {
				return true
			}
		}
	}
	return false
}

func validateHostPattern(pattern string) error {
	pattern = strings.TrimSpace(strings.ToLower(pattern))
	if pattern == "" {
		return errors.New("host pattern не может быть пустым")
	}
	if strings.ContainsAny(pattern, "/?#") {
		return fmt.Errorf("некорректный host pattern %q", pattern)
	}
	if strings.Contains(pattern, "*") && (!strings.HasPrefix(pattern, "*.") || strings.Count(pattern, "*") != 1) {
		return fmt.Errorf("wildcard разрешён только в начале: %q", pattern)
	}
	return nil
}

func hostMatches(pattern, host string) bool {
	pattern = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(pattern)), ".")
	host = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	if pattern == host {
		return true
	}
	if strings.HasPrefix(pattern, "*.") {
		suffix := strings.TrimPrefix(pattern, "*")
		return strings.HasSuffix(host, suffix) && host != strings.TrimPrefix(suffix, ".")
	}
	return false
}
