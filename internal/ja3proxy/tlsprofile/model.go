// Package tlsprofile manages versioned, replayable ClientHello templates.
package tlsprofile

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/lylemi/ja3proxy/internal/ja3proxy/capture/tlshello"
	"github.com/lylemi/ja3proxy/internal/ja3proxy/fingerprint"
	"github.com/lylemi/ja3proxy/internal/ja3proxy/recorder"
)

const (
	SchemaVersion                     = "tls-profile-template/1"
	MaterializerVersion               = "utls-template-materializer/1"
	VerificationVersion               = "tls-profile-verification/1"
	GREASEPlaceholder                 = uint16(0x0a0a)
	DefaultTemplateLogPath            = "profiles/tls-templates.jsonl"
	ALPNPolicyProfile                 = "PROFILE"
	ALPNPolicyDownstream              = "DOWNSTREAM"
	ALPNPolicyIntersection            = "INTERSECTION"
	ALPNPolicyCustom                  = "CUSTOM"
	ALPSPolicyProfile                 = "PROFILE"
	ALPSPolicyDownstream              = "DOWNSTREAM"
	ALPSPolicyIntersection            = "INTERSECTION"
	ALPSPolicyCustom                  = "CUSTOM"
	ProfileTypePreset                 = "PRESET"
	ProfileTypeObserved               = "OBSERVED"
	ProfileTypeCustom                 = "CUSTOM"
	ProfileTypeRandomized             = "RANDOMIZED"
	RandomizedALPNAuto                = "AUTO"
	RandomizedALPNRequired            = "REQUIRED"
	RandomizedALPNDisabled            = "DISABLED"
	CompatibilityValid                = "VALID"
	CompatibilityValidWithDifferences = "VALID_WITH_DIFFERENCES"
	CompatibilityIncompatible         = "INCOMPATIBLE"
	CompatibilityNotValidated         = "NOT_VALIDATED"
	CompatibilityRevalidationRequired = "PROFILE_REVALIDATION_REQUIRED"
	ProfileModeStrict                 = "STRICT"
	ProfileModeAdaptive               = "ADAPTIVE"
)

var ErrVersionConflict = errors.New("tls profile configuration version conflict")
var ErrProtocolConflict = errors.New("PROFILE_PROTOCOL_CONFLICT")

type StaticFields struct {
	CipherSuites        []uint16 `json:"cipher_suites"`
	ExtensionOrder      []uint16 `json:"extension_order"`
	ALPN                []string `json:"alpn"`
	ALPNPolicy          string   `json:"alpn_policy,omitempty"`
	CustomALPN          []string `json:"custom_alpn,omitempty"`
	ALPS                []string `json:"alps,omitempty"`
	ALPSPolicy          string   `json:"alps_policy,omitempty"`
	CustomALPS          []string `json:"custom_alps,omitempty"`
	PaddingLength       int      `json:"padding_length,omitempty"`
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
	SchemaVersion         string                     `json:"schema_version"`
	ProfileType           string                     `json:"profile_type,omitempty"`
	ProfileMode           string                     `json:"profile_mode,omitempty"`
	RandomizedALPN        string                     `json:"randomized_alpn,omitempty"`
	ID                    string                     `json:"id"`
	Name                  string                     `json:"name"`
	FamilyID              string                     `json:"family_id,omitempty"`
	Version               uint64                     `json:"version"`
	BasedOnVersion        uint64                     `json:"based_on_version,omitempty"`
	Enabled               bool                       `json:"enabled"`
	HostPatterns          []string                   `json:"host_patterns"`
	BasePreset            fingerprint.TLSFingerprint `json:"base_preset"`
	Fields                StaticFields               `json:"fields"`
	Policy                MatchPolicy                `json:"policy"`
	SourceObservationID   string                     `json:"source_observation_id,omitempty"`
	Source                *ObservedSource            `json:"source,omitempty"`
	Expected              *Expected                  `json:"expected,omitempty"`
	Replayability         Replayability              `json:"replayability"`
	CreatedWithUTLS       string                     `json:"created_with_utls,omitempty"`
	CurrentRuntimeUTLS    string                     `json:"current_runtime_utls,omitempty"`
	LastValidatedWithUTLS string                     `json:"last_validated_with_utls,omitempty"`
	CompatibilityStatus   string                     `json:"compatibility_status,omitempty"`
	LastValidatedAt       time.Time                  `json:"last_validated_at,omitempty"`
	CreatedAt             time.Time                  `json:"created_at"`
	UpdatedAt             time.Time                  `json:"updated_at"`
}

// EngineCompatibility returns the current compatibility state without mutating
// a persisted profile. The last validated engine is the comparison baseline
// after a successful replay; before the first replay, creation engine is used.
func EngineCompatibility(template Template) string {
	baseline := template.LastValidatedWithUTLS
	if baseline == "" {
		baseline = template.CreatedWithUTLS
	}
	if baseline == "" {
		return CompatibilityNotValidated
	}
	if baseline != recorder.TLSEngineUTLSVersion {
		return CompatibilityRevalidationRequired
	}
	if template.CompatibilityStatus == CompatibilityIncompatible || template.CompatibilityStatus == CompatibilityValid || template.CompatibilityStatus == CompatibilityValidWithDifferences {
		return template.CompatibilityStatus
	}
	return CompatibilityNotValidated
}

func compatibilityAllowsUse(template Template) bool {
	status := EngineCompatibility(template)
	if template.CreatedWithUTLS == "" && template.LastValidatedWithUTLS == "" {
		return false
	}
	return status != CompatibilityRevalidationRequired && status != CompatibilityIncompatible
}

type Library struct {
	SchemaVersion string     `json:"schema_version"`
	ConfigVersion uint64     `json:"config_version"`
	ActiveID      string     `json:"active_id,omitempty"`
	ActiveIDs     []string   `json:"active_ids,omitempty"`
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
	alps := make([]string, 0, len(h.ALPS))
	for _, value := range h.ALPS {
		decoded, err := hex.DecodeString(value)
		if err != nil {
			return StaticFields{}, fmt.Errorf("некорректный ALPS: %w", err)
		}
		alps = append(alps, string(decoded))
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
		ALPNPolicy:          ALPNPolicyIntersection,
		ALPS:                alps,
		ALPSPolicy:          ALPSPolicyIntersection,
		PaddingLength:       paddingLength(h),
		SupportedVersions:   versions,
		SupportedGroups:     groups,
		SignatureAlgorithms: append([]uint16(nil), h.SignatureAlgorithms...),
	}, nil
}

func paddingLength(h *tlshello.Hello) int {
	if h == nil {
		return 0
	}
	for _, extension := range h.Extensions {
		if extension.ID == 21 {
			return extension.Length
		}
	}
	return 0
}

// ConstrainALPN returns a connection-specific copy of a template according to
// its explicit ALPN policy. An empty policy keeps the historical intersection
// behavior for profiles created before policy support was added.
func ConstrainALPN(template Template, offered []string) (Template, error) {
	effective, _, err := ConstrainALPNAudited(template, offered)
	return effective, err
}

// ConstrainALPNAudited creates a connection-specific template and describes
// every ALPN/ALPS change required to make it compatible with the downstream.
func ConstrainALPNAudited(template Template, offered []string) (Template, []recorder.RuntimeMutation, error) {
	mode := strings.ToUpper(strings.TrimSpace(template.ProfileMode))
	if mode == "" {
		mode = ProfileModeAdaptive // Preserve behavior of templates predating profile_mode.
	}
	alpn, err := effectiveALPN(template, offered)
	if err != nil {
		if mode == ProfileModeStrict {
			return Template{}, nil, fmt.Errorf("%w: %v", ErrProtocolConflict, err)
		}
		return Template{}, nil, err
	}
	alps, err := effectiveALPS(template, offered, alpn)
	if err != nil {
		if mode == ProfileModeStrict {
			return Template{}, nil, fmt.Errorf("%w: %v", ErrProtocolConflict, err)
		}
		return Template{}, nil, err
	}
	if mode != ProfileModeStrict && mode != ProfileModeAdaptive {
		return Template{}, nil, fmt.Errorf("unsupported profile_mode %q", template.ProfileMode)
	}
	if mode == ProfileModeStrict {
		for _, protocol := range template.Fields.ALPN {
			if !slices.Contains(offered, protocol) {
				return Template{}, nil, fmt.Errorf("%w: downstream не поддерживает ALPN %q из профиля", ErrProtocolConflict, protocol)
			}
		}
	}
	mutations := []recorder.RuntimeMutation{}
	if !reflect.DeepEqual(template.Fields.ALPN, alpn) {
		if mode == ProfileModeStrict {
			return Template{}, nil, fmt.Errorf("%w: ALPN профиля несовместим с downstream", ErrProtocolConflict)
		}
		mutations = append(mutations, recorder.RuntimeMutation{Type: "PROFILE_RUNTIME_MUTATION", Field: "ALPN", Before: append([]string{}, template.Fields.ALPN...), After: append([]string{}, alpn...), Reason: "downstream protocol compatibility"})
	}
	if !reflect.DeepEqual(template.Fields.ALPS, alps) {
		if mode == ProfileModeStrict {
			return Template{}, nil, fmt.Errorf("%w: ALPS профиля несовместим с ALPN/downstream", ErrProtocolConflict)
		}
		mutations = append(mutations, recorder.RuntimeMutation{Type: "PROFILE_RUNTIME_MUTATION", Field: "ALPS", Before: append([]string{}, template.Fields.ALPS...), After: append([]string{}, alps...), Reason: "downstream protocol compatibility"})
	}
	template.Fields.ALPN = alpn
	template.Fields.ALPS = alps
	return template, mutations, nil
}

// auditMaterializedFields compares the requested static fields with the
// ClientHello actually assembled by uTLS. Dynamic bytes such as random,
// key shares and GREASE values are excluded by FieldsFromHello.
func auditMaterializedFields(template Template, hello *tlshello.Hello) ([]recorder.RuntimeMutation, error) {
	actual, err := FieldsFromHello(hello)
	if err != nil {
		return nil, err
	}
	mutations := []recorder.RuntimeMutation{}
	compare := func(field string, before, after []string) error {
		if slices.Equal(before, after) {
			return nil
		}
		if template.ProfileMode == ProfileModeStrict {
			return fmt.Errorf("%w: uTLS изменил поле %s при сборке ClientHello", ErrProtocolConflict, field)
		}
		mutations = append(mutations, recorder.RuntimeMutation{
			Type: "PROFILE_RUNTIME_MUTATION", Field: field,
			Before: append([]string{}, before...), After: append([]string{}, after...),
			Reason: "uTLS materialization",
		})
		return nil
	}
	uint16Strings := func(values []uint16) []string {
		out := make([]string, len(values))
		for i, value := range values {
			out[i] = strconv.FormatUint(uint64(value), 10)
		}
		return out
	}
	for _, field := range []struct {
		name          string
		before, after []string
	}{
		{"CIPHER_SUITES", uint16Strings(template.Fields.CipherSuites), uint16Strings(actual.CipherSuites)},
		{"EXTENSIONS", uint16Strings(template.Fields.ExtensionOrder), uint16Strings(actual.ExtensionOrder)},
		{"ALPN", template.Fields.ALPN, actual.ALPN},
		{"ALPS", template.Fields.ALPS, actual.ALPS},
		{"SUPPORTED_VERSIONS", uint16Strings(template.Fields.SupportedVersions), uint16Strings(actual.SupportedVersions)},
		{"SUPPORTED_GROUPS", uint16Strings(template.Fields.SupportedGroups), uint16Strings(actual.SupportedGroups)},
		{"SIGNATURE_ALGORITHMS", uint16Strings(template.Fields.SignatureAlgorithms), uint16Strings(actual.SignatureAlgorithms)},
	} {
		if err := compare(field.name, field.before, field.after); err != nil {
			return nil, err
		}
	}
	if template.Fields.PaddingLength > 0 {
		if err := compare("PADDING", []string{strconv.Itoa(template.Fields.PaddingLength)}, []string{strconv.Itoa(actual.PaddingLength)}); err != nil {
			return nil, err
		}
	}
	return mutations, nil
}

func effectiveALPN(template Template, offered []string) ([]string, error) {
	policy := template.Fields.ALPNPolicy
	if policy == "" {
		policy = ALPNPolicyIntersection
	}
	switch policy {
	case ALPNPolicyProfile:
		return append([]string(nil), template.Fields.ALPN...), nil
	case ALPNPolicyDownstream:
		if len(offered) == 0 {
			return append([]string(nil), template.Fields.ALPN...), nil
		}
		return append([]string(nil), offered...), nil
	case ALPNPolicyIntersection:
		if len(template.Fields.ALPN) == 0 || len(offered) == 0 {
			return append([]string(nil), template.Fields.ALPN...), nil
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
			return nil, fmt.Errorf("ALPN профиля %q не пересекается с ALPN входящего клиента", strings.Join(template.Fields.ALPN, ", "))
		}
		return matched, nil
	case ALPNPolicyCustom:
		if len(template.Fields.CustomALPN) == 0 {
			return nil, errors.New("custom_alpn обязателен для ALPN policy CUSTOM")
		}
		return append([]string(nil), template.Fields.CustomALPN...), nil
	default:
		return nil, fmt.Errorf("неподдерживаемая ALPN policy %q", policy)
	}
}

func effectiveALPS(template Template, offered []string, effectiveALPN []string) ([]string, error) {
	policy := template.Fields.ALPSPolicy
	if policy == "" {
		policy = ALPSPolicyIntersection
	}
	var candidate []string
	switch policy {
	case ALPSPolicyProfile:
		candidate = template.Fields.ALPS
	case ALPSPolicyDownstream:
		candidate = template.Fields.ALPS
		if len(offered) > 0 {
			candidate = offered
		}
	case ALPSPolicyIntersection:
		candidate = template.Fields.ALPS
		if len(offered) > 0 {
			candidate = matchingStrings(template.Fields.ALPS, offered)
		}
	case ALPSPolicyCustom:
		if len(template.Fields.CustomALPS) == 0 {
			return nil, errors.New("custom_alps обязателен для ALPS policy CUSTOM")
		}
		candidate = template.Fields.CustomALPS
	default:
		return nil, fmt.Errorf("неподдерживаемая ALPS policy %q", policy)
	}
	if len(candidate) == 0 {
		return nil, nil
	}
	allowed := make(map[string]struct{}, len(effectiveALPN))
	for _, protocol := range effectiveALPN {
		allowed[protocol] = struct{}{}
	}
	filtered := make([]string, 0, len(candidate))
	for _, protocol := range candidate {
		if _, ok := allowed[protocol]; ok {
			filtered = append(filtered, protocol)
		}
	}
	if policy == ALPSPolicyCustom && len(filtered) != len(candidate) {
		return nil, fmt.Errorf("CUSTOM ALPS содержит протокол, отсутствующий в эффективном ALPN")
	}
	if len(filtered) == 0 {
		return nil, nil
	}
	return filtered, nil
}

func matchingStrings(source, allowed []string) []string {
	set := make(map[string]struct{}, len(allowed))
	for _, value := range allowed {
		set[value] = struct{}{}
	}
	matched := make([]string, 0, len(source))
	for _, value := range source {
		if _, ok := set[value]; ok {
			matched = append(matched, value)
		}
	}
	return matched
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
	if template.FamilyID != strings.TrimSpace(template.FamilyID) || len(template.FamilyID) > 64 {
		return errors.New("family_id должен быть без пробелов по краям и не длиннее 64 символов")
	}
	for _, character := range template.FamilyID {
		if !(character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' || strings.ContainsRune("._:-", character)) {
			return errors.New("family_id допускает только латинские буквы, цифры, точку, дефис, двоеточие и подчёркивание")
		}
	}
	if template.ProfileType == "" {
		template.ProfileType = ProfileTypeCustom
	}
	if template.ProfileMode == "" {
		template.ProfileMode = ProfileModeAdaptive
	}
	switch template.ProfileMode {
	case ProfileModeStrict, ProfileModeAdaptive:
	default:
		return fmt.Errorf("неподдерживаемый profile_mode %q", template.ProfileMode)
	}
	switch template.ProfileType {
	case ProfileTypePreset, ProfileTypeObserved, ProfileTypeCustom:
	case ProfileTypeRandomized:
		if template.ProfileMode == ProfileModeStrict {
			return fmt.Errorf("%w: STRICT недоступен для RANDOMIZED ClientHello с непредсказуемыми extensions", ErrProtocolConflict)
		}
		if template.RandomizedALPN == "" {
			template.RandomizedALPN = RandomizedALPNAuto
		}
		switch template.RandomizedALPN {
		case RandomizedALPNAuto, RandomizedALPNRequired, RandomizedALPNDisabled:
		default:
			return fmt.Errorf("неподдерживаемый randomized_alpn %q", template.RandomizedALPN)
		}
		if len(template.HostPatterns) > 64 {
			return errors.New("слишком много host patterns")
		}
		for _, pattern := range template.HostPatterns {
			if err := validateHostPattern(pattern); err != nil {
				return err
			}
		}
		return nil
	default:
		return fmt.Errorf("неподдерживаемый profile_type %q", template.ProfileType)
	}
	if err := fingerprint.ValidateTLSFingerprint(template.BasePreset); err != nil {
		return fmt.Errorf("базовый пресет: %w", err)
	}
	if len(template.Fields.CipherSuites) == 0 || len(template.Fields.CipherSuites) > 256 {
		return errors.New("cipher_suites должен содержать от 1 до 256 значений")
	}
	if template.Fields.ALPNPolicy == "" {
		template.Fields.ALPNPolicy = ALPNPolicyIntersection
	}
	if template.Fields.ALPSPolicy == "" {
		template.Fields.ALPSPolicy = ALPSPolicyIntersection
	}
	switch template.Fields.ALPNPolicy {
	case ALPNPolicyProfile, ALPNPolicyDownstream, ALPNPolicyIntersection:
		if len(template.Fields.CustomALPN) != 0 {
			return errors.New("custom_alpn разрешён только для ALPN policy CUSTOM")
		}
	case ALPNPolicyCustom:
		if len(template.Fields.CustomALPN) == 0 {
			return errors.New("custom_alpn обязателен для ALPN policy CUSTOM")
		}
	default:
		return fmt.Errorf("неподдерживаемая ALPN policy %q", template.Fields.ALPNPolicy)
	}
	switch template.Fields.ALPSPolicy {
	case ALPSPolicyProfile, ALPSPolicyDownstream, ALPSPolicyIntersection:
		if len(template.Fields.CustomALPS) != 0 {
			return errors.New("custom_alps разрешён только для ALPS policy CUSTOM")
		}
	case ALPSPolicyCustom:
		if len(template.Fields.CustomALPS) == 0 {
			return errors.New("custom_alps обязателен для ALPS policy CUSTOM")
		}
	default:
		return fmt.Errorf("неподдерживаемая ALPS policy %q", template.Fields.ALPSPolicy)
	}
	for _, protocol := range template.Fields.CustomALPN {
		if len(protocol) == 0 || len(protocol) > 255 {
			return errors.New("каждый custom ALPN должен иметь длину 1..255 байт")
		}
	}
	if len(template.Fields.ExtensionOrder) > 256 || len(template.Fields.ALPN) > 32 || len(template.Fields.SupportedVersions) > 16 || len(template.Fields.SupportedGroups) > 128 || len(template.Fields.SignatureAlgorithms) > 128 {
		return errors.New("одно из полей профиля превышает допустимый размер")
	}
	for _, protocol := range template.Fields.ALPN {
		if len(protocol) == 0 || len(protocol) > 255 {
			return errors.New("каждый ALPN должен иметь длину 1..255 байт")
		}
	}
	for _, protocol := range append(append([]string{}, template.Fields.ALPS...), template.Fields.CustomALPS...) {
		if len(protocol) == 0 || len(protocol) > 255 {
			return errors.New("каждый ALPS должен иметь длину 1..255 байт")
		}
	}
	if (len(template.Fields.ALPS) > 0 || len(template.Fields.CustomALPS) > 0) && !containsALPSExtension(template.Fields.ExtensionOrder) {
		return errors.New("ALPS настроен, но ApplicationSettingsExtension отсутствует в extension_order")
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

func containsALPSExtension(extensionOrder []uint16) bool {
	for _, id := range extensionOrder {
		if id == 17513 || id == 17613 {
			return true
		}
	}
	return false
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
