package recorder

import (
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"strconv"
	"strings"
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
	Status  string   `json:"status"`
	Reason  string   `json:"reason,omitempty"`
	Changes []Change `json:"changes"`
}

func Compare(a, b Observation) Comparison {
	out := Comparison{Status: "UNKNOWN", Changes: []Change{}}
	if a.Completeness != "complete" || b.Completeness != "complete" || a.Fingerprints == nil || b.Fingerprints == nil {
		out.Reason = "incomplete_capture"
		return out
	}
	if a.Fingerprints.NormalizationVersion != b.Fingerprints.NormalizationVersion {
		out.Reason = "incompatible_normalization_version"
		return out
	}
	var av, bv any
	if json.Unmarshal(a.Fingerprints.Normalized, &av) != nil || json.Unmarshal(b.Fingerprints.Normalized, &bv) != nil {
		out.Reason = "invalid_normalized_data"
		return out
	}
	diffValue("", av, bv, &out.Changes)
	out.Status = "MATCH"
	if len(out.Changes) > 0 {
		out.Status = "MISMATCH"
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
			verification.Status = "MISMATCH"
			verification.Reason = "constraint_violation"
			return verification
		}
	}
	for _, path := range expected.MustMatch {
		left, leftOK := valueAtPointer(expectedValue, path)
		right, rightOK := valueAtPointer(actualValue, path)
		if !leftOK || !rightOK || !reflect.DeepEqual(left, right) {
			verification.Status = "MISMATCH"
			verification.Reason = "must_match_difference"
			return verification
		}
	}
	for _, path := range expected.ShouldMatch {
		left, leftOK := valueAtPointer(expectedValue, path)
		right, rightOK := valueAtPointer(actualValue, path)
		if !leftOK || !rightOK || !reflect.DeepEqual(left, right) {
			verification.Status = "PARTIAL_MATCH"
			verification.Reason = "should_match_difference"
			return verification
		}
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
