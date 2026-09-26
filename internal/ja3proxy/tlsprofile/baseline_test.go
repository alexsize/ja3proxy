package tlsprofile

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

type utlsProfileBaseline struct {
	SchemaVersion string                     `json:"schema_version"`
	UTLSVersion   string                     `json:"utls_version"`
	Profiles      []utlsProfileBaselineEntry `json:"profiles"`
}

type utlsProfileBaselineEntry struct {
	Name                string   `json:"name"`
	Client              string   `json:"client"`
	Version             string   `json:"version"`
	ProfileMaterializer string   `json:"profile_materializer_version"`
	JA3                 string   `json:"ja3"`
	JA3Hash             string   `json:"ja3_hash"`
	JA4                 string   `json:"ja4"`
	NormalizedSHA256    string   `json:"normalized_sha256"`
	CipherSuites        []uint16 `json:"cipher_suites"`
	ExtensionOrder      []uint16 `json:"extension_order"`
}

func TestUTLSProfileBaseline(t *testing.T) {
	actual := utlsProfileBaseline{
		SchemaVersion: "ja3proxy-utls-profile-baseline/1",
		UTLSVersion:   linkedUTLSVersion(t),
	}
	for _, profile := range []struct{ name, client, version string }{
		{"Firefox 105", "Firefox", "105"},
		{"Safari 16.0", "Safari", "16.0"},
		{"iOS 14", "iOS", "14"},
	} {
		template, err := TemplateFromPreset(profile.name, profile.client, profile.version)
		if err != nil {
			t.Fatalf("materialize %s: %v", profile.name, err)
		}
		if template.Expected == nil {
			t.Fatalf("%s has no deterministic expected fingerprint", profile.name)
		}
		actual.Profiles = append(actual.Profiles, utlsProfileBaselineEntry{
			Name: profile.name, Client: profile.client, Version: profile.version,
			ProfileMaterializer: template.Expected.MaterializerVersion,
			JA3:                 template.Expected.JA3, JA3Hash: template.Expected.JA3Hash,
			JA4: template.Expected.JA4, NormalizedSHA256: template.Expected.NormalizedSHA256,
			CipherSuites:   append([]uint16(nil), template.Fields.CipherSuites...),
			ExtensionOrder: append([]uint16(nil), template.Fields.ExtensionOrder...),
		})
	}
	encoded, err := json.MarshalIndent(actual, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	baselinePath := filepath.Join("testdata", "utls-profile-baseline.json")
	baselineBytes, err := os.ReadFile(baselinePath)
	if err != nil {
		t.Logf("Generated uTLS baseline; save as %s:\n%s", baselinePath, encoded)
		t.Fatalf("read committed uTLS baseline: %v", err)
	}
	var expected utlsProfileBaseline
	if err := json.Unmarshal(baselineBytes, &expected); err != nil {
		t.Fatalf("decode uTLS baseline: %v", err)
	}
	if expected.SchemaVersion != actual.SchemaVersion {
		t.Fatalf("uTLS baseline schema changed: got %q, want %q", actual.SchemaVersion, expected.SchemaVersion)
	}
	if expected.UTLSVersion != actual.UTLSVersion {
		t.Errorf("uTLS dependency changed: got %s, baseline pins %s; review profile/wire diffs before updating the baseline", actual.UTLSVersion, expected.UTLSVersion)
	}
	if len(expected.Profiles) != len(actual.Profiles) {
		t.Fatalf("profile baseline count changed: got %d, want %d", len(actual.Profiles), len(expected.Profiles))
	}
	for i := range expected.Profiles {
		want, got := expected.Profiles[i], actual.Profiles[i]
		if !sameProfileSlices(want, got) {
			wantJSON, _ := json.MarshalIndent(want, "    ", "  ")
			gotJSON, _ := json.MarshalIndent(got, "    ", "  ")
			t.Errorf("uTLS profile baseline drift for %s:\n  want:\n    %s\n   got:\n    %s", want.Name, wantJSON, gotJSON)
		}
	}
}

func sameProfileSlices(a, b utlsProfileBaselineEntry) bool {
	if a.Name != b.Name || a.Client != b.Client || a.Version != b.Version || a.ProfileMaterializer != b.ProfileMaterializer || a.JA3 != b.JA3 || a.JA3Hash != b.JA3Hash || a.JA4 != b.JA4 || a.NormalizedSHA256 != b.NormalizedSHA256 {
		return false
	}
	return strings.Join(uint16Strings(a.CipherSuites), ",") == strings.Join(uint16Strings(b.CipherSuites), ",") &&
		strings.Join(uint16Strings(a.ExtensionOrder), ",") == strings.Join(uint16Strings(b.ExtensionOrder), ",")
}

func uint16Strings(values []uint16) []string {
	result := make([]string, len(values))
	for i, value := range values {
		result[i] = strconv.FormatUint(uint64(value), 10)
	}
	return result
}

func linkedUTLSVersion(t *testing.T) string {
	t.Helper()
	goMod, err := os.ReadFile(filepath.Join("..", "..", "..", "go.mod"))
	if err != nil {
		t.Fatalf("read go.mod to verify uTLS pin: %v", err)
	}
	for _, line := range strings.Split(string(goMod), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[0] == "github.com/refraction-networking/utls" {
			return fields[1]
		}
	}
	t.Fatal("uTLS dependency missing from go.mod")
	return ""
}
