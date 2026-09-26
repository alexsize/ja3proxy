package tlshello

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

func TestParseEncryptedExtensionsAndRejectsDuplicateIDs(t *testing.T) {
	raw := testEncryptedExtensions("h2")
	parsed, err := ParseEncryptedExtensions(raw)
	if err != nil || !parsed.Extensions.Available || len(parsed.Extensions.Value) != 1 || parsed.Extensions.Value[0].ID != 16 || !parsed.SelectedALPN.Available || parsed.SelectedALPN.Value != "h2" || parsed.SelectedALPN.Source != "decrypted_encrypted_extensions" {
		t.Fatalf("EncryptedExtensions=%+v error=%v", parsed, err)
	}
	duplicate := []byte{8, 0, 0, 10, 0, 8, 0, 43, 0, 0, 0, 43, 0, 0}
	if _, err := ParseEncryptedExtensions(duplicate); err == nil {
		t.Fatal("duplicate extension IDs were accepted")
	}
}

func TestEncryptedExtensionsConnDecryptsWithMatchingKeyLogSecret(t *testing.T) {
	random := bytes.Repeat([]byte{0x5a}, 32)
	secret := bytes.Repeat([]byte{0x37}, 32)
	keyLog := filepath.Join(t.TempDir(), "tls.keys")
	contents := "SERVER_HANDSHAKE_TRAFFIC_SECRET " + hex.EncodeToString(random) + " " + hex.EncodeToString(secret) + "\n"
	if err := os.WriteFile(keyLog, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	serverHello := record(testTLS13ServerHelloWithSessionID(false))
	encryptedEE := encryptTLS13TestRecord(t, 0x1301, secret, testEncryptedExtensions("h2"), 22, 0)
	wire := append(serverHello, encryptedEE...)
	var captures []EncryptedExtensionsCapture
	conn := WrapEncryptedExtensions(&stubConn{input: bytes.NewReader(wire)}, keyLog, func() []byte { return append([]byte(nil), random...) }, func(capture EncryptedExtensionsCapture) {
		captures = append(captures, capture)
	})
	buffer := make([]byte, 4096)
	for {
		if _, err := conn.Read(buffer); err != nil {
			break
		}
	}
	if len(captures) != 1 || captures[0].Status != "complete" || !captures[0].Extensions.SelectedALPN.Available || captures[0].Extensions.SelectedALPN.Value != "h2" {
		t.Fatalf("decrypted captures=%+v", captures)
	}
	if len(conn.secret) != 0 || len(conn.key) != 0 || len(conn.iv) != 0 {
		t.Fatal("traffic secret material remained after successful decryption")
	}
}

func TestEncryptedExtensionsConnReportsMissingSecret(t *testing.T) {
	var captures []EncryptedExtensionsCapture
	conn := WrapEncryptedExtensions(&stubConn{input: bytes.NewReader(record(testTLS13ServerHelloWithSessionID(false)))}, filepath.Join(t.TempDir(), "missing.keys"), func() []byte { return bytes.Repeat([]byte{1}, 32) }, func(capture EncryptedExtensionsCapture) {
		captures = append(captures, capture)
	})
	buffer := make([]byte, 4096)
	for {
		if _, err := conn.Read(buffer); err != nil {
			break
		}
	}
	if len(captures) != 1 || captures[0].Status != "partial" || captures[0].Reason != "session_secret_unavailable" || captures[0].Extensions.SelectedALPN.Available {
		t.Fatalf("missing-secret captures=%+v", captures)
	}
}

func testEncryptedExtensions(alpn string) []byte {
	name := []byte(alpn)
	value := []byte{0, byte(len(name) + 1), byte(len(name))}
	value = append(value, name...)
	extension := []byte{0, 16, 0, byte(len(value))}
	extension = append(extension, value...)
	body := []byte{0, byte(len(extension))}
	body = append(body, extension...)
	return append([]byte{8, 0, 0, byte(len(body))}, body...)
}

func encryptTLS13TestRecord(t *testing.T, suite uint16, secret, message []byte, contentType byte, sequence uint64) []byte {
	t.Helper()
	key, iv, err := deriveTLS13KeyIV(secret, suite)
	if err != nil {
		t.Fatal(err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	inner := append(append([]byte(nil), message...), contentType)
	header := []byte{23, 3, 3, 0, 0}
	binaryLength := len(inner) + aead.Overhead()
	header[3], header[4] = byte(binaryLength>>8), byte(binaryLength)
	nonce := append([]byte(nil), iv...)
	for index := 0; index < 8; index++ {
		nonce[len(nonce)-1-index] ^= byte(sequence >> (8 * index))
	}
	return append(header, aead.Seal(nil, nonce, inner, header)...)
}
