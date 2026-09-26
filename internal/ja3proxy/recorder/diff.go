package recorder

import (
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"strconv"
	"strings"

	dnscapture "github.com/lylemi/ja3proxy/internal/ja3proxy/capture/dns"
	"github.com/lylemi/ja3proxy/internal/ja3proxy/capture/http1"
	http2capture "github.com/lylemi/ja3proxy/internal/ja3proxy/capture/http2"
	quiccapture "github.com/lylemi/ja3proxy/internal/ja3proxy/capture/quic"
)

const (
	DiffAlgorithmVersion          = "tls-normalized-diff/1"
	SupportedMaterializerVersion  = "utls-template-materializer/1"
	SupportedProfileSchemaVersion = "tls-profile-template/1"
)

type Change struct {
	Op     string `json:"op"`
	Path   string `json:"path"`
	From   string `json:"from,omitempty"`
	Before any    `json:"before,omitempty"`
	After  any    `json:"after,omitempty"`
}
type Comparison struct {
	Family  string   `json:"family,omitempty"`
	Status  string   `json:"status"`
	Reason  string   `json:"reason,omitempty"`
	Changes []Change `json:"changes"`
}

func Compare(a, b Observation) Comparison {
	out := Comparison{Status: "UNKNOWN", Changes: []Change{}}
	if a.Fingerprints != nil || b.Fingerprints != nil {
		out.Family = "tls_client_hello"
		if a.Fingerprints == nil || b.Fingerprints == nil {
			out.Reason = "incompatible_fingerprint_family"
			return out
		}
		if a.Completeness != "complete" || b.Completeness != "complete" {
			out.Reason = "incomplete_capture"
			return out
		}
		if a.Fingerprints.NormalizationVersion != b.Fingerprints.NormalizationVersion {
			out.Reason = "incompatible_normalization_version"
			return out
		}
		return compareJSON(out, a.Fingerprints.Normalized, b.Fingerprints.Normalized, false)
	}
	if a.ServerFingerprints != nil || b.ServerFingerprints != nil {
		out.Family = "tls_server_hello"
		if a.ServerFingerprints == nil || b.ServerFingerprints == nil {
			out.Reason = "incompatible_fingerprint_family"
			return out
		}
		left := struct{ JA3S, JA3SVersion, JA4S, JA4SVersion string }{a.ServerFingerprints.JA3S, a.ServerFingerprints.JA3SVersion, a.ServerFingerprints.JA4S, a.ServerFingerprints.JA4SVersion}
		right := struct{ JA3S, JA3SVersion, JA4S, JA4SVersion string }{b.ServerFingerprints.JA3S, b.ServerFingerprints.JA3SVersion, b.ServerFingerprints.JA4S, b.ServerFingerprints.JA4SVersion}
		return compareJSON(out, marshalJSON(left), marshalJSON(right), false)
	}
	left, leftName := observationFingerprint(a)
	right, rightName := observationFingerprint(b)
	if leftName == "" || rightName == "" {
		out.Reason = "unsupported_fingerprint_family"
		return out
	}
	if leftName != rightName {
		out.Reason = "incompatible_fingerprint_family"
		return out
	}
	if !hasFingerprintData(a, leftName) || !hasFingerprintData(b, rightName) {
		out.Family = leftName
		out.Reason = "insufficient_fingerprint_data"
		return out
	}
	out.Family = leftName
	return compareJSON(out, marshalJSON(left), marshalJSON(right), true)
}

func hasFingerprintData(o Observation, family string) bool {
	switch family {
	case "http1":
		return o.HTTP1.HTTPVersion != "" && (o.HTTP1.Method != "" || o.HTTP1.StatusCode != 0)
	case "http2":
		return o.HTTP2.Hash != ""
	case "tcp_syn":
		return o.TCPSYN.JA4T != ""
	case "dns_exchange":
		return o.DNS.Status != "" && len(o.DNS.Questions) > 0
	case "quic_initial":
		return o.QUIC.Version != 0
	default:
		return false
	}
}

// observationFingerprint intentionally omits flow endpoints, timestamps,
// sequence IDs and other correlation data that are not fingerprint features.
func observationFingerprint(o Observation) (any, string) {
	switch {
	case o.HTTP1 != nil:
		value := struct {
			Direction        string            `json:"direction"`
			Kind             string            `json:"kind"`
			Completeness     string            `json:"completeness"`
			BodyFraming      string            `json:"body_framing"`
			BodyCaptured     bool              `json:"body_captured"`
			TrailerStatus    string            `json:"trailer_status,omitempty"`
			Method           string            `json:"method,omitempty"`
			HTTPVersion      string            `json:"http_version"`
			StatusCode       int               `json:"status_code,omitempty"`
			HeaderOrder      []string          `json:"header_order"`
			HeaderNames      []string          `json:"original_header_names"`
			Headers          []http1.Header    `json:"headers"`
			TransferEncoding []string          `json:"transfer_encoding,omitempty"`
		}{o.HTTP1.Direction, o.HTTP1.Kind, o.HTTP1.Completeness, o.HTTP1.BodyFraming, o.HTTP1.BodyCaptured, o.HTTP1.TrailerStatus, o.HTTP1.Method, o.HTTP1.HTTPVersion, o.HTTP1.StatusCode, o.HTTP1.HeaderOrder, o.HTTP1.OriginalHeaderNames, o.HTTP1.Headers, o.HTTP1.TransferEncoding}
		return value, "http1"
	case o.HTTP2 != nil:
		value := struct {
			Completeness      string                 `json:"completeness"`
			Direction         string                 `json:"direction"`
			Preface           bool                   `json:"preface"`
			Settings          []http2capture.Setting `json:"settings"`
			SettingsOrder     []uint16               `json:"settings_order"`
			WindowUpdates     []uint32               `json:"window_update_increments"`
			Priorities        []http2Priority        `json:"priorities"`
			DynamicTableSizes []uint32               `json:"dynamic_table_size_updates"`
			FrameTypes        []uint8                `json:"frame_types"`
			PseudoHeaderOrder []string               `json:"pseudo_header_order"`
			Availability      []http2capture.FieldAvailability `json:"availability"`
		}{o.HTTP2.Completeness, o.HTTP2.Direction, o.HTTP2.Preface, o.HTTP2.Settings, o.HTTP2.SettingsOrder, http2WindowUpdates(o.HTTP2.WindowUpdates), http2Priorities(o.HTTP2.Priorities), o.HTTP2.DynamicTableSizes, o.HTTP2.FrameTypes, o.HTTP2.PseudoHeaderOrder, o.HTTP2.Availability}
		return value, "http2"
	case o.TCPSYN != nil:
		return struct {
			JA4T        string `json:"ja4t"`
			JA4TVersion string `json:"ja4t_version"`
		}{o.TCPSYN.JA4T, o.TCPSYN.JA4TVersion}, "tcp_syn"
	case o.DNS != nil:
		return struct {
			Transport string                     `json:"transport"`
			Status    string                     `json:"status"`
			Questions []dnsQuestion               `json:"questions"`
			Addresses []dnsAddressAnswer          `json:"addresses,omitempty"`
			Aliases   []dnsCNAMEAnswer             `json:"aliases,omitempty"`
		}{o.DNS.Transport, o.DNS.Status, dnsQuestions(o.DNS.Questions), dnsAddresses(o.DNS.Addresses), dnsAliases(o.DNS.Aliases)}, "dns_exchange"
	case o.QUIC != nil:
		return struct {
			Version             uint32                       `json:"version"`
			TransportParameters []quicTransportParameter     `json:"transport_parameters"`
		}{o.QUIC.Version, quicParameters(o.QUIC.TransportParameters)}, "quic_initial"
	default:
		return nil, ""
	}
}

type dnsQuestion struct {
	Name  string `json:"name"`
	Type  uint16 `json:"type"`
	Class uint16 `json:"class"`
}

type dnsAddressAnswer struct {
	Name    string `json:"name"`
	Address string `json:"address"`
	TTL     uint32 `json:"ttl"`
}

type dnsCNAMEAnswer struct {
	Name   string `json:"name"`
	Target string `json:"target"`
	TTL    uint32 `json:"ttl"`
}

type quicTransportParameter struct {
	ID       uint64  `json:"id"`
	Position int     `json:"position"`
	Kind     string  `json:"kind"`
	Length   int     `json:"length"`
	Value    *uint64 `json:"value,omitempty"`
	Present  bool    `json:"present,omitempty"`
}

type http2Priority struct {
	Exclusive bool   `json:"exclusive"`
	Weight    uint16 `json:"weight"`
}

func http2WindowUpdates(values []http2capture.WindowUpdate) []uint32 {
	result := make([]uint32, len(values))
	for i, value := range values {
		result[i] = value.Increment
	}
	return result
}

func http2Priorities(values []http2capture.Priority) []http2Priority {
	result := make([]http2Priority, len(values))
	for i, value := range values {
		result[i] = http2Priority{value.Exclusive, value.Weight}
	}
	return result
}

func dnsQuestions(values []dnscapture.Question) []dnsQuestion {
	result := make([]dnsQuestion, len(values))
	for i, value := range values {
		result[i] = dnsQuestion{value.Name, value.Type, value.Class}
	}
	return result
}

func dnsAddresses(values []dnscapture.AddressAnswer) []dnsAddressAnswer {
	result := make([]dnsAddressAnswer, len(values))
	for i, value := range values {
		result[i] = dnsAddressAnswer{value.Name, value.Address.String(), value.TTL}
	}
	return result
}

func dnsAliases(values []dnscapture.CNAMEAnswer) []dnsCNAMEAnswer {
	result := make([]dnsCNAMEAnswer, len(values))
	for i, value := range values {
		result[i] = dnsCNAMEAnswer{value.Name, value.Target, value.TTL}
	}
	return result
}

func quicParameters(values []quiccapture.TransportParameter) []quicTransportParameter {
	result := make([]quicTransportParameter, len(values))
	for i, value := range values {
		result[i] = quicTransportParameter{value.ID, value.Position, value.Kind, value.Length, value.Value, value.Present}
	}
	return result
}

func marshalJSON(value any) []byte {
	encoded, _ := json.Marshal(value)
	return encoded
}

func compareJSON(out Comparison, left, right []byte, partial bool) Comparison {
	if partial {
		out.Reason = "captured_fingerprint_fields_only"
	}
	var a, b any
	if json.Unmarshal(left, &a) != nil || json.Unmarshal(right, &b) != nil {
		out.Reason = "invalid_normalized_data"
		return out
	}
	diffValue("", a, b, &out.Changes)
	if len(out.Changes) > 0 {
		out.Status = "MISMATCH"
		return out
	}
	out.Status = "MATCH"
	if partial {
		out.Status = "PARTIAL_MATCH"
	}
	return out
}

func VerifyExpected(expected FingerprintExpected, actual Observation) *Verification {
	verification := &Verification{
		SchemaVersion:        "tls-profile-verification/1",
		Status:               "UNKNOWN",
		Expected:             expected,
		DiffAlgorithmVersion: DiffAlgorithmVersion,
		Changes:              []Change{},
	}
	if actual.Completeness != "complete" || actual.Fingerprints == nil {
		verification.Reason = "incomplete_capture"
		return verification
	}
	verification.ActualJA3 = actual.Fingerprints.JA3
	verification.ActualJA3Hash = actual.Fingerprints.JA3Hash
	verification.ActualJA4 = actual.Fingerprints.JA4
	verification.ActualNormalizedSHA256 = actual.Fingerprints.NormalizedSHA256
	if expected.NormalizationVersion == "" || expected.NormalizationVersion != actual.Fingerprints.NormalizationVersion {
		verification.Reason = "incompatible_normalization_version"
		return verification
	}
	if expected.MaterializerVersion != SupportedMaterializerVersion {
		verification.Reason = "incompatible_materializer_version"
		return verification
	}
	if expected.ProfileSchemaVersion != SupportedProfileSchemaVersion {
		verification.Reason = "incompatible_profile_schema_version"
		return verification
	}
	var expectedValue, actualValue any
	if json.Unmarshal(expected.Normalized, &expectedValue) != nil || json.Unmarshal(actual.Fingerprints.Normalized, &actualValue) != nil {
		verification.Reason = "invalid_normalized_data"
		return verification
	}
	diffValue("", expectedValue, actualValue, &verification.Changes)
	for _, constraint := range expected.Constraints {
		actualConstraintValue, exists := valueAtPointer(actualValue, constraint.Path)
		if !constraintMatches(constraint, actualConstraintValue, exists) {
			verification.ViolatedConstraints = append(verification.ViolatedConstraints, constraint.Path)
		}
	}
	for _, path := range expected.MustMatch {
		left, leftOK := valueAtPointer(expectedValue, path)
		right, rightOK := valueAtPointer(actualValue, path)
		if !leftOK || !rightOK || !reflect.DeepEqual(left, right) {
			verification.MismatchedMustMatch = append(verification.MismatchedMustMatch, path)
		}
	}
	for _, path := range expected.ShouldMatch {
		left, leftOK := valueAtPointer(expectedValue, path)
		right, rightOK := valueAtPointer(actualValue, path)
		if !leftOK || !rightOK || !reflect.DeepEqual(left, right) {
			verification.MismatchedShouldMatch = append(verification.MismatchedShouldMatch, path)
		}
	}
	if len(verification.ViolatedConstraints) > 0 {
		verification.Status = "MISMATCH"
		verification.Reason = "constraint_violation"
		return verification
	}
	if len(verification.MismatchedMustMatch) > 0 {
		verification.Status = "MISMATCH"
		verification.Reason = "must_match_difference"
		return verification
	}
	if len(verification.MismatchedShouldMatch) > 0 {
		verification.Status = "PARTIAL_MATCH"
		verification.Reason = "should_match_difference"
		return verification
	}
	verification.Status = "MATCH"
	return verification
}

func constraintMatches(constraint FingerprintConstraint, actual any, exists bool) bool {
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

func valueAtPointer(value any, path string) (any, bool) {
	if path == "" {
		return value, true
	}
	if !strings.HasPrefix(path, "/") {
		return nil, false
	}
	current := value
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

func pointer(s string) string { return strings.ReplaceAll(strings.ReplaceAll(s, "~", "~0"), "/", "~1") }
func diffValue(path string, a, b any, out *[]Change) {
	if reflect.DeepEqual(a, b) {
		return
	}
	if am, ok := a.(map[string]any); ok {
		if bm, ok := b.(map[string]any); ok {
			keys := map[string]bool{}
			for k := range am {
				keys[k] = true
			}
			for k := range bm {
				keys[k] = true
			}
			names := []string{}
			for k := range keys {
				names = append(names, k)
			}
			sort.Strings(names)
			for _, k := range names {
				av, aa := am[k]
				bv, bb := bm[k]
				p := path + "/" + pointer(k)
				if !aa {
					*out = append(*out, Change{Op: "add", Path: p, After: bv})
				} else if !bb {
					*out = append(*out, Change{Op: "remove", Path: p, Before: av})
				} else {
					diffValue(p, av, bv, out)
				}
			}
			return
		}
	}
	if aa, ok := a.([]any); ok {
		if bb, ok := b.([]any); ok && len(aa) <= 256 && len(bb) <= 256 {
			work := append([]any(nil), aa...)
			for i, v := range bb {
				p := fmt.Sprintf("%s/%d", path, i)
				if i < len(work) && reflect.DeepEqual(work[i], v) {
					continue
				}
				found := -1
				for j := i + 1; j < len(work); j++ {
					if reflect.DeepEqual(work[j], v) {
						found = j
						break
					}
				}
				if found >= 0 {
					moved := work[found]
					copy(work[i+1:found+1], work[i:found])
					work[i] = moved
					*out = append(*out, Change{Op: "move", Path: p, From: fmt.Sprintf("%s/%d", path, found)})
					continue
				}
				if i < len(work) {
					diffValue(p, work[i], v, out)
					work[i] = v
				} else {
					work = append(work, v)
					*out = append(*out, Change{Op: "add", Path: p, After: v})
				}
			}
			for i := len(work) - 1; i >= len(bb); i-- {
				*out = append(*out, Change{Op: "remove", Path: fmt.Sprintf("%s/%d", path, i), Before: work[i]})
			}
			return
		}
	}
	*out = append(*out, Change{Op: "replace", Path: path, Before: a, After: b})
}
