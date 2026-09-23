package fingerprint

import (
	"fmt"
	"strings"

	utls "github.com/refraction-networking/utls"
)

type tlsFingerprintPreset struct {
	Client         string
	Versions       []string
	DefaultVersion string
	ClientAliases  []string
	VersionAliases map[string]string
}

var tlsFingerprintPresets = []tlsFingerprintPreset{
	{
		Client:         utls.HelloGolang.Client,
		Versions:       fingerprintVersions(utls.HelloGolang),
		DefaultVersion: utls.HelloGolang.Version,
		ClientAliases:  []string{"go", "crypto"},
	},
	{
		Client: utls.HelloChrome_Auto.Client,
		Versions: fingerprintVersions(
			utls.HelloChrome_58,
			utls.HelloChrome_62,
			utls.HelloChrome_70,
			utls.HelloChrome_72,
			utls.HelloChrome_83,
			utls.HelloChrome_87,
			utls.HelloChrome_96,
			utls.HelloChrome_100,
			utls.HelloChrome_100_PSK,
			utls.HelloChrome_102,
			utls.HelloChrome_106_Shuffle,
			utls.HelloChrome_112_PSK_Shuf,
			utls.HelloChrome_114_Padding_PSK_Shuf,
			utls.HelloChrome_115_PQ,
			utls.HelloChrome_115_PQ_PSK,
			utls.HelloChrome_120,
			utls.HelloChrome_120_PQ,
			utls.HelloChrome_131,
			utls.HelloChrome_133,
		),
		DefaultVersion: utls.HelloChrome_Auto.Version,
	},
	{
		Client: utls.HelloFirefox_Auto.Client,
		Versions: fingerprintVersions(
			utls.HelloFirefox_55,
			utls.HelloFirefox_56,
			utls.HelloFirefox_63,
			utls.HelloFirefox_65,
			utls.HelloFirefox_99,
			utls.HelloFirefox_102,
			utls.HelloFirefox_105,
			utls.HelloFirefox_120,
		),
		DefaultVersion: utls.HelloFirefox_Auto.Version,
	},
	{
		Client: utls.HelloIOS_Auto.Client,
		Versions: fingerprintVersions(
			utls.HelloIOS_11_1,
			utls.HelloIOS_12_1,
			utls.HelloIOS_13,
			utls.HelloIOS_14,
		),
		DefaultVersion: utls.HelloIOS_Auto.Version,
		ClientAliases:  []string{"ios"},
		VersionAliases: map[string]string{"11.1": utls.HelloIOS_11_1.Version},
	},
	{
		Client:         utls.HelloAndroid_11_OkHttp.Client,
		Versions:       fingerprintVersions(utls.HelloAndroid_11_OkHttp),
		DefaultVersion: utls.HelloAndroid_11_OkHttp.Version,
	},
	{
		Client: utls.HelloEdge_Auto.Client,
		Versions: fingerprintVersions(
			utls.HelloEdge_85,
			utls.HelloEdge_106,
		),
		DefaultVersion: utls.HelloEdge_Auto.Version,
	},
	{
		Client:         utls.HelloSafari_Auto.Client,
		Versions:       fingerprintVersions(utls.HelloSafari_16_0),
		DefaultVersion: utls.HelloSafari_Auto.Version,
	},
	{
		Client: utls.Hello360_Auto.Client,
		Versions: fingerprintVersions(
			utls.Hello360_7_5,
			utls.Hello360_11_0,
		),
		DefaultVersion: utls.Hello360_Auto.Version,
		ClientAliases:  []string{"360"},
	},
	{
		Client:         utls.HelloQQ_Auto.Client,
		Versions:       fingerprintVersions(utls.HelloQQ_11_1),
		DefaultVersion: utls.HelloQQ_Auto.Version,
		ClientAliases:  []string{"qq"},
	},
}

func fingerprintVersions(ids ...utls.ClientHelloID) []string {
	versions := make([]string, 0, len(ids))
	for _, id := range ids {
		versions = append(versions, id.Version)
	}
	return versions
}

func parseTLSFingerprintSpec(spec string) (TLSFingerprint, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return TLSFingerprint{}, fmt.Errorf("fingerprint shorthand is required")
	}

	client, version, hasVersion := splitTLSFingerprintSpec(spec)
	client = strings.TrimSpace(client)
	version = strings.TrimSpace(version)
	if client == "" {
		return TLSFingerprint{}, fmt.Errorf("fingerprint client is required")
	}

	preset, ok := lookupTLSFingerprintPreset(client)
	if !ok {
		return TLSFingerprint{}, unsupportedTLSFingerprintClientError(client)
	}
	if !hasVersion {
		version = preset.DefaultVersion
	} else if version == "" {
		return TLSFingerprint{}, fmt.Errorf("fingerprint version is required")
	} else {
		canonicalVersion, ok := preset.canonicalVersion(version)
		if !ok {
			return TLSFingerprint{}, unsupportedTLSFingerprintVersionError(preset, version)
		}
		version = canonicalVersion
	}

	return TLSFingerprint{
		Client:        preset.Client,
		Version:       version,
		HandshakeType: handshakeTypeForVersion(version),
	}, nil
}

func ParseSpec(spec string) (TLSFingerprint, error) {
	return parseTLSFingerprintSpec(spec)
}

func splitTLSFingerprintSpec(spec string) (client string, version string, hasVersion bool) {
	for _, sep := range []string{"@", ":"} {
		if before, after, found := strings.Cut(spec, sep); found {
			return before, after, true
		}
	}

	fields := strings.Fields(spec)
	if len(fields) == 2 {
		return fields[0], fields[1], true
	}
	return spec, "", false
}

func lookupTLSFingerprintPreset(client string) (tlsFingerprintPreset, bool) {
	client = strings.TrimSpace(client)
	for _, preset := range tlsFingerprintPresets {
		if strings.EqualFold(client, preset.Client) {
			return preset, true
		}
		for _, alias := range preset.ClientAliases {
			if strings.EqualFold(client, alias) {
				return preset, true
			}
		}
	}
	return tlsFingerprintPreset{}, false
}

func (preset tlsFingerprintPreset) canonicalVersion(version string) (string, bool) {
	version = strings.TrimSpace(version)
	for _, alias := range []string{"auto", "default", "latest"} {
		if strings.EqualFold(version, alias) {
			return preset.DefaultVersion, true
		}
	}
	for alias, canonical := range preset.VersionAliases {
		if strings.EqualFold(version, alias) {
			return canonical, true
		}
	}
	for _, candidate := range preset.Versions {
		if strings.EqualFold(version, candidate) {
			return candidate, true
		}
	}
	return "", false
}

func formatTLSFingerprintCatalog() string {
	var builder strings.Builder
	builder.WriteString("Available TLS fingerprints:\n")
	for _, preset := range tlsFingerprintPresets {
		builder.WriteString("  ")
		builder.WriteString(preset.Client)
		builder.WriteString(": ")
		builder.WriteString(strings.Join(preset.Versions, ", "))
		builder.WriteString(" (default ")
		builder.WriteString(preset.DefaultVersion)
		builder.WriteString(")\n")
		for _, version := range preset.Versions {
			if handshakeTypeForVersion(version) == "PSK" {
				builder.WriteString("    ")
				builder.WriteString(version)
				builder.WriteString(" — PSK / resumption profile\n")
			}
		}
	}
	builder.WriteString("\nUse --tls-fingerprint client@version, for example:\n")
	builder.WriteString("  ja3proxy --tls-fingerprint chrome@120\n")
	builder.WriteString("  ja3proxy --tls-fingerprint firefox\n")
	return builder.String()
}

func FormatCatalog() string {
	return formatTLSFingerprintCatalog()
}

// Presets returns every fingerprint shorthand accepted by ParseSpec. The
// returned slice is detached from the internal catalog and is safe for callers
// to modify.
func Presets() []TLSFingerprint {
	presets := make([]TLSFingerprint, 0)
	for _, preset := range tlsFingerprintPresets {
		for _, version := range preset.Versions {
			presets = append(presets, TLSFingerprint{
				Client:        preset.Client,
				Version:       version,
				HandshakeType: handshakeTypeForVersion(version),
			})
		}
	}
	return presets
}

func availableTLSFingerprintClients() string {
	clients := make([]string, 0, len(tlsFingerprintPresets))
	for _, preset := range tlsFingerprintPresets {
		clients = append(clients, preset.Client)
	}
	return strings.Join(clients, ", ")
}

func unsupportedTLSFingerprintError(fingerprint TLSFingerprint, cause error) error {
	if preset, ok := lookupTLSFingerprintPreset(fingerprint.Client); ok {
		if fingerprint.Client != preset.Client {
			return fmt.Errorf(
				"unsupported TLS fingerprint client %q; did you mean %q?\navailable clients: %s\nrun with --list-tls-fingerprints to see all presets",
				fingerprint.Client,
				preset.Client,
				availableTLSFingerprintClients(),
			)
		}
		return unsupportedTLSFingerprintVersionError(preset, fingerprint.Version)
	}
	if cause != nil {
		return fmt.Errorf(
			"unsupported TLS fingerprint %s %s: %w\navailable clients: %s\nrun with --list-tls-fingerprints to see all presets",
			fingerprint.Version,
			fingerprint.Client,
			cause,
			availableTLSFingerprintClients(),
		)
	}
	return unsupportedTLSFingerprintClientError(fingerprint.Client)
}

func unsupportedTLSFingerprintClientError(client string) error {
	return fmt.Errorf(
		"unsupported TLS fingerprint client %q\navailable clients: %s\nrun with --list-tls-fingerprints to see all presets",
		client,
		availableTLSFingerprintClients(),
	)
}

func unsupportedTLSFingerprintVersionError(preset tlsFingerprintPreset, version string) error {
	return fmt.Errorf(
		"unsupported TLS fingerprint %s %s\navailable %s versions: %s\nrun with --list-tls-fingerprints to see all presets",
		version,
		preset.Client,
		preset.Client,
		strings.Join(preset.Versions, ", "),
	)
}
