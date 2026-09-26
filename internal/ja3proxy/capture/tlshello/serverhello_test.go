package tlshello

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestParseServerHelloAndCalculateJA3S(t *testing.T) {
	raw := testServerHello(false)
	hello, err := ParseServerHello(raw)
	if err != nil {
		t.Fatalf("ParseServerHello() error = %v", err)
	}
	if hello.Fields.TLSVersion.Value != 0x0304 || hello.Fields.SelectedCipher.Value != 0xc02f || hello.Fields.SelectedALPN.Value != "h2" || hello.Fields.SelectedGroup.Value != 29 || hello.Fields.SessionResumption.Available || hello.Fields.SessionResumption.Reason != "psk_selected_type_unknown" {
		t.Fatalf("server hello = %+v", hello)
	}
	if len(hello.Fields.Extensions.Value) != 4 || hello.Fields.Extensions.Value[0].ID != 43 || hello.Fields.Extensions.Value[3].ID != 41 {
		t.Fatalf("extensions = %+v", hello.Fields.Extensions.Value)
	}

	fingerprints, err := CalculateServerFingerprints(&hello)
	if err != nil {
		t.Fatalf("CalculateServerFingerprints() error = %v", err)
	}
	if fingerprints.JA3S != "772,49199,43-16-51-41" || fingerprints.JA3SHash != "1c38646d61855d3b24190ada58acd240" || fingerprints.JA3SVersion != JA3SVersion {
		t.Fatalf("server fingerprints = %+v", fingerprints)
	}
	if fingerprints.JA4S != "t1304h2_c02f_b5f0699ff2ed" || fingerprints.JA4SVersion != JA4SVersion {
		t.Fatalf("JA4S = %q/%q", fingerprints.JA4S, fingerprints.JA4SVersion)
	}
}

func TestParseHelloRetryRequest(t *testing.T) {
	raw := testServerHello(true)
	hello, err := ParseServerHello(raw)
	if err != nil {
		t.Fatalf("ParseServerHello() error = %v", err)
	}
	if !hello.Fields.HelloRetryRequest.Value || hello.Fields.SelectedGroup.Value != 29 || hello.Fields.TLSVersion.Value != 0x0304 {
		t.Fatalf("hello retry request = %+v", hello)
	}
}

func TestParseServerHelloMarksEncryptedALPNUnavailable(t *testing.T) {
	raw := testServerHello(false)
	extensionsStart := 4 + 2 + 32 + 1 + 2 + 1 + 2
	alpnStart := extensionsStart + 6
	copy(raw[alpnStart:], raw[alpnStart+9:])
	raw = raw[:len(raw)-9]
	newBodyLength := len(raw) - 4
	raw[1] = byte(newBodyLength >> 16)
	raw[2] = byte(newBodyLength >> 8)
	raw[3] = byte(newBodyLength)
	oldExtensionsLength := int(binary.BigEndian.Uint16(raw[extensionsStart-2 : extensionsStart]))
	binary.BigEndian.PutUint16(raw[extensionsStart-2:extensionsStart], uint16(oldExtensionsLength-9))

	hello, err := ParseServerHello(raw)
	if err != nil {
		t.Fatal(err)
	}
	if hello.Fields.SelectedALPN.Available || hello.Fields.SelectedALPN.Source != "wire_server_hello" || hello.Fields.SelectedALPN.Reason != "encrypted_without_keys" {
		t.Fatalf("ALPN availability = %+v", hello.Fields.SelectedALPN)
	}
	if hello.Fields.EncryptedExtensions.Available || hello.Fields.EncryptedExtensions.Source != "wire_server_hello" || hello.Fields.EncryptedExtensions.Reason != "encrypted_without_keys" {
		t.Fatalf("EncryptedExtensions availability = %+v", hello.Fields.EncryptedExtensions)
	}
}

func TestParseServerHelloMarksEncryptedExtensionsNotApplicableToTLS12(t *testing.T) {
	raw := testServerHello(false)
	extensionsStart := 4 + 2 + 32 + 1 + 2 + 1 + 2
	copy(raw[extensionsStart+4:extensionsStart+6], []byte{0x03, 0x03})

	hello, err := ParseServerHello(raw)
	if err != nil {
		t.Fatal(err)
	}
	if hello.Fields.TLSVersion.Value != 0x0303 {
		t.Fatalf("TLS version = %#04x, want TLS 1.2", hello.Fields.TLSVersion.Value)
	}
	if hello.Fields.EncryptedExtensions.Available || hello.Fields.EncryptedExtensions.Reason != "not_applicable" {
		t.Fatalf("TLS 1.2 EncryptedExtensions = %+v", hello.Fields.EncryptedExtensions)
	}
}

func TestTLS13LegacySessionIDEchoDoesNotMeanResumption(t *testing.T) {
	hello, err := ParseServerHello(testTLS13ServerHelloWithSessionID(false))
	if err != nil {
		t.Fatal(err)
	}
	if hello.Fields.SessionIDLength.Value != 1 || !hello.Fields.SessionResumption.Available || hello.Fields.SessionResumption.Value {
		t.Fatalf("legacy session ID was confused with PSK resumption: %+v", hello.Fields)
	}
}

func TestTLS13SelectedPSKDoesNotProveResumption(t *testing.T) {
	hello, err := ParseServerHello(testTLS13ServerHelloWithSessionID(true))
	if err != nil {
		t.Fatal(err)
	}
	if hello.Fields.SessionResumption.Available || hello.Fields.SessionResumption.Reason != "psk_selected_type_unknown" {
		t.Fatalf("selected PSK was confused with resumption: %+v", hello.Fields.SessionResumption)
	}
}

func testTLS13ServerHelloWithSessionID(selectedPSK bool) []byte {
	body := []byte{0x03, 0x03}
	body = append(body, bytes.Repeat([]byte{0x11}, 32)...)
	body = append(body, 1, 0x42)       // legacy_session_id_echo for compatibility
	body = append(body, 0x13, 0x01, 0) // TLS_AES_128_GCM_SHA256, null compression
	extensions := []byte{
		0, 43, 0, 2, 3, 4, // supported_versions: TLS 1.3
		0, 51, 0, 6, 0, 29, 0, 2, 1, 2, // key_share, no PSK selection
	}
	if selectedPSK {
		extensions = append(extensions, 0, 41, 0, 2, 0, 0)
	}
	body = append(body, 0, byte(len(extensions)))
	body = append(body, extensions...)
	raw := []byte{ServerHelloType, 0, byte(len(body) >> 8), byte(len(body))}
	return append(raw, body...)
}

func TestServerHelloWrapperPublishesHelloRetryAndFollowUp(t *testing.T) {
	first := record(testServerHello(true))
	second := record(testServerHello(false))
	wire := append(append([]byte(nil), first...), second...)
	under := &stubConn{}
	var captures []Capture
	conn := WrapServerHello(under, false, DefaultLimits(), func(c Capture) { captures = append(captures, c) })
	if _, err := conn.Write(wire); err != nil {
		t.Fatal(err)
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	if len(captures) != 2 || !isHelloRetryRequest(captures[0].Raw) || isHelloRetryRequest(captures[1].Raw) {
		t.Fatalf("server captures = %+v", captures)
	}
}

func TestServerHelloWrapperSkipsTLS13CompatibilityChangeCipherSpec(t *testing.T) {
	first := record(testServerHello(true))
	ccs := []byte{20, 3, 3, 0, 1, 1}
	second := record(testServerHello(false))
	under := &stubConn{input: bytes.NewReader(append(append(first, ccs...), second...))}
	var captures []Capture
	conn := WrapServerHello(under, true, DefaultLimits(), func(c Capture) { captures = append(captures, c) })
	buf := make([]byte, 256)
	for {
		_, err := conn.Read(buf)
		if err != nil {
			break
		}
	}
	if len(captures) != 2 {
		t.Fatalf("captures = %d, want 2: %+v", len(captures), captures)
	}
	if captures[0].Status != "complete" || captures[1].Status != "complete" {
		t.Fatalf("captures = %+v", captures)
	}
}

func TestParseServerHelloRejectsMalformedInput(t *testing.T) {
	valid := testServerHello(false)
	tests := [][]byte{
		nil,
		{1, 0, 0, 0},
		valid[:len(valid)-1],
	}
	for index, raw := range tests {
		if _, err := ParseServerHello(raw); err == nil {
			t.Fatalf("case %d: ParseServerHello() error = nil", index)
		}
	}
	badExtension := append([]byte(nil), valid...)
	// The first extension starts after the 2-byte extensions vector length.
	bodyOffset := 4 + 2 + 32 + 1 + 2 + 1
	firstExtensionLength := bodyOffset + 2 + 2
	binary.BigEndian.PutUint16(badExtension[firstExtensionLength:firstExtensionLength+2], 0xffff)
	if _, err := ParseServerHello(badExtension); err == nil {
		t.Fatal("invalid extension length was accepted")
	}
}

func FuzzParseServerHello(f *testing.F) {
	f.Add(testServerHello(false))
	f.Fuzz(func(t *testing.T, raw []byte) {
		_, _ = ParseServerHello(raw)
	})
}

func testServerHello(helloRetryRequest bool) []byte {
	random := bytes.Repeat([]byte{0x11}, 32)
	if helloRetryRequest {
		random = append([]byte(nil), helloRetryRequestRandom[:]...)
	}
	extensions := []byte{
		0x00, 0x2b, 0x00, 0x02, 0x03, 0x04,
		0x00, 0x10, 0x00, 0x05, 0x00, 0x03, 0x02, 'h', '2',
		0x00, 0x29, 0x00, 0x02, 0x00, 0x00,
	}
	if helloRetryRequest {
		extensions = append(extensions[:15], append([]byte{0x00, 0x33, 0x00, 0x02, 0x00, 0x1d}, extensions[15:]...)...)
	} else {
		extensions = append(extensions[:15], append([]byte{0x00, 0x33, 0x00, 0x06, 0x00, 0x1d, 0x00, 0x02, 0x01, 0x02}, extensions[15:]...)...)
	}
	body := make([]byte, 0, 4+2+32+1+2+1+2+len(extensions))
	body = append(body, 0x03, 0x03)
	body = append(body, random...)
	body = append(body, 0x00)
	body = append(body, 0xc0, 0x2f, 0x00)
	body = append(body, byte(len(extensions)>>8), byte(len(extensions)))
	body = append(body, extensions...)
	raw := make([]byte, 4, 4+len(body))
	raw[0] = ServerHelloType
	raw[1] = byte(len(body) >> 16)
	raw[2] = byte(len(body) >> 8)
	raw[3] = byte(len(body))
	return append(raw, body...)
}
