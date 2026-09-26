package certstore

import (
	"crypto/x509"
	"path/filepath"
	"testing"
	"time"
)

func TestCertificateAuthorityValidityReportsLifecycle(t *testing.T) {
	now := time.Date(2026, 9, 25, 12, 0, 0, 0, time.UTC)
	ca := &CertificateAuthority{x509Cert: &x509.Certificate{
		NotBefore: now.Add(-time.Hour),
		NotAfter:  now.Add(45 * 24 * time.Hour),
	}}
	if got := ca.Validity(now); got.Status != "VALID" || got.DaysRemaining != 45 {
		t.Fatalf("valid certificate = %+v", got)
	}
	ca.x509Cert.NotAfter = now.Add(10*24*time.Hour + time.Hour)
	if got := ca.Validity(now); got.Status != "EXPIRING" || got.DaysRemaining != 11 {
		t.Fatalf("expiring certificate = %+v", got)
	}
	ca.x509Cert.NotBefore = now.Add(time.Hour)
	if got := ca.Validity(now); got.Status != "NOT_YET_VALID" {
		t.Fatalf("not-yet-valid certificate = %+v", got)
	}
	ca.x509Cert.NotBefore = now.Add(-time.Hour)
	ca.x509Cert.NotAfter = now.Add(-time.Hour)
	if got := ca.Validity(now); got.Status != "EXPIRED" || got.DaysRemaining != -1 {
		t.Fatalf("expired certificate = %+v", got)
	}
	if got := (*CertificateAuthority)(nil).Validity(now); got.Status != "UNAVAILABLE" {
		t.Fatalf("nil CA validity = %+v", got)
	}
}

func TestCertificateFileValidityReadsPublicCertificateOnly(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "panel.crt")
	keyPath := filepath.Join(dir, "panel.key")
	ca := &CertificateAuthority{}
	if err := ca.Generate(certPath, keyPath); err != nil {
		t.Fatal(err)
	}
	got := CertificateFileValidity(nil, certPath, time.Now().UTC())
	if got.Status != "VALID" || got.NotAfter.IsZero() {
		t.Fatalf("certificate file validity = %+v", got)
	}
	if got := CertificateFileValidity(nil, keyPath, time.Now().UTC()); got.Status != "UNAVAILABLE" {
		t.Fatalf("private key reported as certificate: %+v", got)
	}
}
