package tlshello

import (
	"crypto/md5" // JA3 mandates MD5; not used for integrity or authentication.
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

const NormalizationVersion = "TLS-NORM-1"
const ImplementationVersion = "ja3proxy-recorder/1"
const ParserVersion = "1.0.0"
const JA3Version = "JA3/1"
const JA4Version = "FoxIO-JA4-TCP/2026-09-22"
const FingerprintModelVersion = "TLS-FP/1"

const (
	HandshakeTypeFull    = "FULL"
	HandshakeTypeResumed = "RESUMED"
	HandshakeTypePSK     = "PSK"
)

type Fingerprints struct {
	JA3                   string          `json:"ja3"`
	JA3Hash               string          `json:"ja3_hash"`
	JA3Version            string          `json:"ja3_version"`
	JA4                   string          `json:"ja4"`
	JA4A                  string          `json:"ja4_a"`
	JA4B                  string          `json:"ja4_b"`
	JA4C                  string          `json:"ja4_c"`
	JA4Version            string          `json:"ja4_version"`
	FingerprintModel      string          `json:"fingerprint_model"`
	HandshakeType         string          `json:"handshake_type"`
	SessionResumption     bool            `json:"session_resumption"`
	PSKPresent            bool            `json:"psk_present"`
	PSKIdentityCount      int             `json:"psk_identity_count"`
	EarlyData             bool            `json:"early_data"`
	NormalizationVersion  string          `json:"normalization_version"`
	ImplementationVersion string          `json:"implementation_version"`
	RawSHA256             string          `json:"raw_sha256"`
	RecordsSHA256         string          `json:"records_sha256"`
	NormalizedSHA256      string          `json:"normalized_sha256"`
	Normalized            json.RawMessage `json:"normalized"`
}

func SHA256(b []byte) string { v := sha256.Sum256(b); return hex.EncodeToString(v[:]) }
func clean(v []uint16) []uint16 {
	out := []uint16{}
	for _, id := range v {
		if !IsGREASE(id) {
			out = append(out, id)
		}
	}
	return out
}
func decimalIDs(v []uint16) string {
	out := []string{}
	for _, id := range clean(v) {
		out = append(out, strconv.Itoa(int(id)))
	}
	return strings.Join(out, "-")
}
func hexIDs(v []uint16, sorted bool) string {
	v = clean(v)
	if sorted {
		sort.Slice(v, func(i, j int) bool { return v[i] < v[j] })
	}
	out := make([]string, len(v))
	for i, id := range v {
		out[i] = fmt.Sprintf("%04x", id)
	}
	return strings.Join(out, ",")
}
func shortHash(s string) string {
	if s == "" {
		return "000000000000"
	}
	return SHA256([]byte(s))[:12]
}
func idValue(v uint16) any {
	if IsGREASE(v) {
		return "GREASE"
	}
	return int(v)
}
func normalizedIDs(v []uint16) []any {
	out := make([]any, len(v))
	for i, id := range v {
		out[i] = idValue(id)
	}
	return out
}
func integers(v []int) []int {
	out := make([]int, len(v))
	for i, b := range v {
		out[i] = int(b)
	}
	return out
}

// Normalize has a deliberately narrow JCS-compatible domain: ASCII object
// keys/strings (opaque bytes use lowercase hex), integers, booleans and arrays.
// Unknown extension payloads are represented by length, not a claim of replay.
func Normalize(h *Hello) ([]byte, error) {
	extensions := []any{}
	for _, e := range h.Extensions {
		fields := map[string]any{}
		for k, v := range e.Fields {
			fields[k] = v
		}
		// Descriptive names are retained in decoded observations but are not
		// part of TLS-NORM-1, whose numeric wire values remain stable.
		delete(fields, "values_named")
		delete(fields, "shares_named")
		switch e.ID {
		case 0:
			fields = map[string]any{"present": true} // exclude destination
		case 10, 13, 34, 43, 50, 27:
			if v, ok := e.Fields["values"].([]uint16); ok {
				fields["values"] = normalizedIDs(v)
			}
		case 11, 45:
			if v, ok := e.Fields["values"].([]int); ok {
				fields["values"] = integers(v)
			}
		case 51:
			shares := []any{}
			for _, v := range e.Fields["shares"].([]any) {
				m := v.(map[string]any)
				shares = append(shares, map[string]any{"group": idValue(uint16(m["group"].(int))), "key_length": m["key_length"]})
			}
			fields["shares"] = shares
		case 41:
			identities := []any{}
			for _, v := range e.Fields["identities"].([]any) {
				m := v.(map[string]any)
				identities = append(identities, map[string]any{"length": m["length"]})
			}
			fields["identities"] = identities
		case 65281:
			fields = map[string]any{"length": e.Length}
		}
		if IsGREASE(e.ID) {
			fields = map[string]any{"opaque_length": e.Length}
		}
		extensions = append(extensions, map[string]any{"id": idValue(e.ID), "fields": fields})
	}
	return json.Marshal(map[string]any{"legacy_version": h.LegacyVersion, "session_id_length": h.SessionIDLength, "ciphers": normalizedIDs(h.CipherSuites), "compression_methods": integers(h.CompressionMethods), "extensions": extensions})
}

func namedNumericIDs(values []uint16) []NumericIDName {
	result := make([]NumericIDName, 0, len(values))
	for _, value := range values {
		result = append(result, NumericIDName{NumericID: value, ResolvedName: resolveNumericGroup(value)})
	}
	return result
}

func resolveNumericGroup(value uint16) string {
	names := map[uint16]string{
		23: "secp256r1", 24: "secp384r1", 25: "secp521r1",
		29: "x25519", 30: "x448",
		256: "ffdhe2048", 257: "ffdhe3072", 258: "ffdhe4096", 259: "ffdhe6144", 260: "ffdhe8192",
		4587: "secp256r1_mlkem768", 4588: "x25519_mlkem768",
	}
	if IsGREASE(value) {
		return "GREASE"
	}
	if name, ok := names[value]; ok {
		return name
	}
	return "unknown"
}

// Calculate derives fingerprints from a successfully parsed wire message.
func Calculate(h *Hello, raw, records []byte) (Fingerprints, error) {
	if h == nil {
		return Fingerprints{}, fmt.Errorf("ClientHello отсутствует")
	}
	refreshHandshakeMetadata(h)
	norm, err := Normalize(h)
	if err != nil {
		return Fingerprints{}, err
	}
	exts := []uint16{}
	sni := false
	for _, e := range h.Extensions {
		exts = append(exts, e.ID)
		if e.ID == 0 {
			sni = true
		}
	}
	points := []string{}
	for _, v := range h.PointFormats {
		points = append(points, strconv.Itoa(int(v)))
	}
	ja3 := fmt.Sprintf("%d,%s,%s,%s,%s", h.LegacyVersion, decimalIDs(h.CipherSuites), decimalIDs(exts), decimalIDs(h.SupportedGroups), strings.Join(points, "-"))
	md := md5.Sum([]byte(ja3))
	version := h.LegacyVersion
	if len(h.SupportedVersions) > 0 {
		version = 0
		for _, v := range clean(h.SupportedVersions) {
			if v > version {
				version = v
			}
		}
	}
	versionCode := map[uint16]string{0x0300: "s3", 0x0301: "10", 0x0302: "11", 0x0303: "12", 0x0304: "13"}[version]
	if versionCode == "" {
		versionCode = "00"
	}
	alpn := "00"
	if len(h.ALPN) > 0 {
		v, _ := hex.DecodeString(h.ALPN[0])
		if len(v) > 0 {
			first, last := v[0], v[len(v)-1]
			if alphaNum(first) && alphaNum(last) {
				alpn = string([]byte{first, last})
			} else {
				hv := hex.EncodeToString(v)
				alpn = string([]byte{hv[0], hv[len(hv)-1]})
			}
		}
	}
	indicator := "i"
	if sni {
		indicator = "d"
	}
	a := fmt.Sprintf("t%s%s%02d%02d%s", versionCode, indicator, min(99, len(clean(h.CipherSuites))), min(99, len(clean(exts))), alpn)
	b := shortHash(hexIDs(h.CipherSuites, true))
	hashExts := []uint16{}
	for _, v := range exts {
		if v != 0 && v != 16 {
			hashExts = append(hashExts, v)
		}
	}
	extString := hexIDs(hashExts, true)
	c := "000000000000"
	if extString != "" {
		signatures := hexIDs(h.SignatureAlgorithms, false)
		if signatures != "" {
			extString += "_" + signatures
		}
		c = shortHash(extString)
	}
	return Fingerprints{
		JA3: ja3, JA3Hash: hex.EncodeToString(md[:]), JA3Version: JA3Version,
		JA4: a + "_" + b + "_" + c, JA4A: a, JA4B: b, JA4C: c, JA4Version: JA4Version,
		FingerprintModel: FingerprintModelVersion, HandshakeType: h.HandshakeType,
		SessionResumption: h.SessionResumption, PSKPresent: h.PSKPresent,
		PSKIdentityCount: h.PSKIdentityCount, EarlyData: h.EarlyData,
		NormalizationVersion: NormalizationVersion, ImplementationVersion: ImplementationVersion,
		RawSHA256: SHA256(raw), RecordsSHA256: SHA256(records),
		NormalizedSHA256: SHA256(append([]byte(NormalizationVersion+"\n"), norm...)), Normalized: norm,
	}, nil
}

func refreshHandshakeMetadata(h *Hello) {
	if h == nil {
		return
	}
	if h.PSKIdentityCount == 0 {
		for _, extension := range h.Extensions {
			if extension.ID != 41 {
				continue
			}
			if identities, ok := extension.Fields["identities"].([]any); ok {
				h.PSKIdentityCount = len(identities)
			}
		}
	}
	if h.PSKIdentityCount > 0 {
		h.PSKPresent = true
	}
	if h.HandshakeType != HandshakeTypeFull && h.HandshakeType != HandshakeTypeResumed && h.HandshakeType != HandshakeTypePSK {
		h.HandshakeType = ""
	}
	if h.HandshakeType == "" || h.HandshakeType == HandshakeTypeFull && h.PSKPresent {
		if h.PSKPresent {
			h.HandshakeType = HandshakeTypePSK
		} else {
			h.HandshakeType = HandshakeTypeFull
		}
	}
	if h.HandshakeType == HandshakeTypePSK {
		h.PSKPresent = true
	}
	h.SessionResumption = h.PSKPresent || h.HandshakeType == HandshakeTypeResumed
}

func alphaNum(b byte) bool {
	return b >= '0' && b <= '9' || b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z'
}
