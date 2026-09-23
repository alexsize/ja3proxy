package fingerprint

import (
	"strings"
	"testing"

	utls "github.com/refraction-networking/utls"
)

func TestParseTLSFingerprintSpec(t *testing.T) {
	tests := []struct {
		name       string
		spec       string
		wantClient string
		wantVer    string
	}{
		{
			name:       "client and version",
			spec:       "chrome@120",
			wantClient: "Chrome",
			wantVer:    "120",
		},
		{
			name:       "default version",
			spec:       "firefox",
			wantClient: "Firefox",
			wantVer:    utls.HelloFirefox_Auto.Version,
		},
		{
			name:       "colon separator",
			spec:       "Chrome:100_psk",
			wantClient: "Chrome",
			wantVer:    "100_PSK",
		},
		{
			name:       "space separator",
			spec:       "edge 85",
			wantClient: "Edge",
			wantVer:    "85",
		},
		{
			name:       "client alias",
			spec:       "360@7.5",
			wantClient: "360Browser",
			wantVer:    "7.5",
		},
		{
			name:       "version alias",
			spec:       "ios@11.1",
			wantClient: "iOS",
			wantVer:    "111",
		},
		{
			name:       "auto version alias",
			spec:       "chrome@auto",
			wantClient: "Chrome",
			wantVer:    utls.HelloChrome_Auto.Version,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseTLSFingerprintSpec(tt.spec)
			if err != nil {
				t.Fatalf("parseTLSFingerprintSpec(%q) error = %v", tt.spec, err)
			}
			if got.Client != tt.wantClient || got.Version != tt.wantVer {
				t.Fatalf("parseTLSFingerprintSpec(%q) = %+v, want %s %s", tt.spec, got, tt.wantClient, tt.wantVer)
			}
		})
	}
}

func TestParseTLSFingerprintSpecRejectsInvalidInput(t *testing.T) {
	tests := []struct {
		name string
		spec string
		want string
	}{
		{
			name: "unknown client",
			spec: "NoSuchBrowser",
			want: "available clients",
		},
		{
			name: "unknown version",
			spec: "chrome@999",
			want: "available Chrome versions",
		},
		{
			name: "missing version",
			spec: "chrome@",
			want: "fingerprint version is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parseTLSFingerprintSpec(tt.spec)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("parseTLSFingerprintSpec(%q) error = %v, want %q", tt.spec, err, tt.want)
			}
			if tt.want != "fingerprint version is required" && !strings.Contains(err.Error(), "--list-tls-fingerprints") {
				t.Fatalf("parseTLSFingerprintSpec(%q) error = %v, want list hint", tt.spec, err)
			}
		})
	}
}

func TestTLSFingerprintCatalogEntriesValidate(t *testing.T) {
	for _, preset := range tlsFingerprintPresets {
		for _, version := range preset.Versions {
			fingerprint := TLSFingerprint{Client: preset.Client, Version: version}
			if err := validateTLSFingerprint(fingerprint); err != nil {
				t.Fatalf("validateTLSFingerprint(%+v) error = %v", fingerprint, err)
			}
		}
	}
}

func TestFormatTLSFingerprintCatalog(t *testing.T) {
	got := formatTLSFingerprintCatalog()
	for _, want := range []string{
		"Available TLS fingerprints:",
		"Chrome:",
		utls.HelloChrome_Auto.Version,
		"ja3proxy --tls-fingerprint chrome@120",
		"ja3proxy --tls-fingerprint firefox",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("formatTLSFingerprintCatalog() missing %q in:\n%s", want, got)
		}
	}
}

func TestPresetsCanBeParsed(t *testing.T) {
	presets := Presets()
	if len(presets) == 0 {
		t.Fatal("Presets() returned no fingerprints")
	}
	for _, preset := range presets {
		spec := preset.Client + "@" + preset.Version
		parsed, err := ParseSpec(spec)
		if err != nil {
			t.Fatalf("ParseSpec(%q) error = %v", spec, err)
		}
		if parsed != preset {
			t.Fatalf("ParseSpec(%q) = %+v, want %+v", spec, parsed, preset)
		}
	}
}

func TestPSKPresetsAreMarkedAsResumptionProfiles(t *testing.T) {
	var psk, full TLSFingerprint
	for _, preset := range Presets() {
		if IsPSK(preset) {
			psk = preset
		}
		if preset.Client == "Chrome" && preset.Version == "120" {
			full = preset
		}
	}
	if psk.Version == "" || psk.HandshakeType != "PSK" {
		t.Fatalf("catalog has no marked PSK preset: %+v", psk)
	}
	if full.HandshakeType != "FULL" {
		t.Fatalf("regular Chrome preset marked incorrectly: %+v", full)
	}
	parsed, err := ParseSpec(psk.Client + "@" + psk.Version)
	if err != nil || parsed != psk {
		t.Fatalf("ParseSpec(%+v) = %+v, %v", psk, parsed, err)
	}
	if got := formatTLSFingerprintCatalog(); !strings.Contains(got, psk.Version+" — PSK / resumption profile") {
		t.Fatalf("catalog output does not mark PSK preset: %s", got)
	}
}
