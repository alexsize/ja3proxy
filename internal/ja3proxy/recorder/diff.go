package recorder

import (
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"strings"
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
