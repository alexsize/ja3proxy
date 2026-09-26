package secrets

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestFileProviderReadsRegularFilesAndRejectsInvalidReferences(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secret")
	if err := os.WriteFile(path, []byte("test-secret"), 0600); err != nil {
		t.Fatal(err)
	}
	value, err := (FileProvider{}).Read(path)
	if err != nil || string(value) != "test-secret" {
		t.Fatalf("Read() = %q, %v", value, err)
	}
	clear(value)
	if _, err := (FileProvider{}).Read(""); err == nil {
		t.Fatal("empty reference accepted")
	}
	if _, err := (FileProvider{}).Read(dir); err == nil {
		t.Fatal("directory reference accepted")
	}
}

func TestFileProviderRejectsOversizedSecret(t *testing.T) {
	path := filepath.Join(t.TempDir(), "oversized")
	if err := os.WriteFile(path, make([]byte, MaxFileSecretSize+1), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := (FileProvider{}).Read(path); err == nil {
		t.Fatal("oversized secret accepted")
	}
}

func TestFileProviderReportsCertificateExpiryWithoutReturningSecret(t *testing.T) {
	expiresAt := time.Now().UTC().Add(48 * time.Hour).Truncate(time.Second)
	path := filepath.Join(t.TempDir(), "certificate.pem")
	if err := os.WriteFile(path, testCertificatePEM(t, expiresAt), 0600); err != nil {
		t.Fatal(err)
	}

	metadata, err := (FileProvider{}).Metadata(path)
	if err != nil {
		t.Fatal(err)
	}
	if metadata.ExpiresAt == nil || !metadata.ExpiresAt.Equal(expiresAt) {
		t.Fatalf("certificate expiry = %v, want %v", metadata.ExpiresAt, expiresAt)
	}
	if metadata.Size == 0 || metadata.ModifiedAt.IsZero() {
		t.Fatalf("incomplete metadata: %+v", metadata)
	}
}

func TestFileProviderRotatesExistingSecretAtomicallyAndPreservesMode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(path, []byte("old secret"), 0600); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}

	if err := (FileProvider{}).Rotate(path, []byte("new secret")); err != nil {
		t.Fatal(err)
	}
	value, err := (FileProvider{}).Read(path)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(value)
	if string(value) != "new secret" {
		t.Fatalf("rotated value = %q", value)
	}
	after, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if after.Mode().Perm() != before.Mode().Perm() {
		t.Fatalf("permissions = %v, want %v", after.Mode().Perm(), before.Mode().Perm())
	}
	if err := (FileProvider{}).Rotate(path, nil); err == nil {
		t.Fatal("empty replacement accepted")
	}
}

func testCertificatePEM(t *testing.T, expiresAt time.Time) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "lifecycle test"},
		NotBefore:    time.Now().UTC().Add(-time.Minute),
		NotAfter:     expiresAt,
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}
