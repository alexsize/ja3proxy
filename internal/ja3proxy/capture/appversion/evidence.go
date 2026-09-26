// Package appversion extracts unverified version claims from protocol metadata.
package appversion

import "strings"

const (
	SourceUserAgent   = "http_user_agent"
	ConfidenceLow     = "low"
	StatusUnverified  = "unverified"
	MaxCandidates     = 8
	maxUserAgentBytes = 4096
)

// Evidence is a structured, unverified product/version claim. It is not an
// application assignment and must never be used for identity or policy alone.
type Evidence struct {
	Product    string `json:"product"`
	Version    string `json:"version"`
	Source     string `json:"source"`
	Confidence string `json:"confidence"`
	Status     string `json:"status"`
}

var genericProducts = map[string]struct{}{
	"mozilla": {}, "applewebkit": {}, "khtml": {}, "gecko": {},
	"safari": {}, "mobile": {}, "compatible": {}, "version": {},
}

// FromUserAgent extracts product/version tokens without retaining the header.
// User-Agent is self-reported, so every result remains low-confidence and
// unverified until an operator binds it to an application and device.
func FromUserAgent(value string) []Evidence {
	if len(value) > maxUserAgentBytes {
		return nil
	}
	var result []Evidence
	seen := make(map[string]struct{})
	for _, token := range strings.Fields(value) {
		token = strings.Trim(token, "()[]{};,\"'")
		product, version, ok := strings.Cut(token, "/")
		if !ok || !validProduct(product) || !validVersion(version) {
			continue
		}
		if _, generic := genericProducts[strings.ToLower(product)]; generic {
			continue
		}
		key := strings.ToLower(product) + "\x00" + version
		if _, duplicate := seen[key]; duplicate {
			continue
		}
		seen[key] = struct{}{}
		result = append(result, Evidence{
			Product: product, Version: version, Source: SourceUserAgent,
			Confidence: ConfidenceLow, Status: StatusUnverified,
		})
		if len(result) == MaxCandidates {
			break
		}
	}
	return result
}

// AppendUserAgent adds distinct claims while keeping aggregate evidence bounded.
func AppendUserAgent(existing []Evidence, value string) []Evidence {
	for _, candidate := range FromUserAgent(value) {
		if len(existing) >= MaxCandidates {
			break
		}
		duplicate := false
		for _, current := range existing {
			if strings.EqualFold(current.Product, candidate.Product) && current.Version == candidate.Version {
				duplicate = true
				break
			}
		}
		if !duplicate {
			existing = append(existing, candidate)
		}
	}
	return existing
}

func validProduct(value string) bool {
	if value == "" || len(value) > 64 {
		return false
	}
	for _, r := range value {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("!#$%&'*+-.^_`|~", r)) {
			return false
		}
	}
	return true
}

func validVersion(value string) bool {
	if value == "" || len(value) > 64 || value[0] < '0' || value[0] > '9' {
		return false
	}
	for _, r := range value {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("._+-", r)) {
			return false
		}
	}
	return true
}
