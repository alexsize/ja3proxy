package certstore

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestGenerateCombinedCABundleAndRotate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ca.pem")
	ca := &CertificateAuthority{}
	if err := ca.Generate(path, path); err != nil {
		t.Fatal(err)
	}
	first := append([]byte(nil), ca.X509Certificate().Raw...)
	for generation := 0; generation < 2; generation++ {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		certBlock, rest := pem.Decode(data)
		keyBlock, _ := pem.Decode(rest)
		if certBlock == nil || certBlock.Type != "CERTIFICATE" || keyBlock == nil || keyBlock.Type != "EC PRIVATE KEY" {
			t.Fatal("combined CA file does not contain a certificate and private key")
		}
		loaded := &CertificateAuthority{}
		if err := loaded.Load(path, path); err != nil {
			t.Fatalf("load combined CA generation %d: %v", generation, err)
		}
		if !bytes.Equal(loaded.X509Certificate().Raw, ca.X509Certificate().Raw) {
			t.Fatal("loaded CA differs from generated CA")
		}
		if generation == 0 {
			if err := ca.Generate(path, path); err != nil {
				t.Fatal(err)
			}
		}
	}
	if bytes.Equal(first, ca.X509Certificate().Raw) {
		t.Fatal("CA bundle did not rotate")
	}
}

func TestFailedCombinedCAGenerationKeepsLoadedCA(t *testing.T) {
	ca := &CertificateAuthority{}
	path := filepath.Join(t.TempDir(), "ca.pem")
	if err := ca.Generate(path, path); err != nil {
		t.Fatal(err)
	}
	previous := append([]byte(nil), ca.X509Certificate().Raw...)
	if err := ca.Generate(filepath.Dir(path), filepath.Dir(path)); err == nil {
		t.Fatal("expected CA bundle publication failure")
	}
	if !bytes.Equal(previous, ca.X509Certificate().Raw) {
		t.Fatal("failed CA publication changed the active CA")
	}
}

func TestCAReloadKeepsIssuerAndSignerTogether(t *testing.T) {
	dir := t.TempDir()
	paths := []string{filepath.Join(dir, "first.pem"), filepath.Join(dir, "second.pem")}
	issuers := make([]*x509.Certificate, len(paths))
	for index, path := range paths {
		generated := &CertificateAuthority{}
		if err := generated.Generate(path, path); err != nil {
			t.Fatal(err)
		}
		issuers[index] = generated.X509Certificate()
	}
	active := &CertificateAuthority{}
	if err := active.Load(paths[0], paths[0]); err != nil {
		t.Fatal(err)
	}
	session := SessionKeyHelper{}
	if err := session.Generate(); err != nil {
		t.Fatal(err)
	}
	var group sync.WaitGroup
	group.Add(2)
	go func() {
		defer group.Done()
		for index := 0; index < 40; index++ {
			path := paths[index%len(paths)]
			if err := active.Load(path, path); err != nil {
				t.Errorf("reload CA: %v", err)
				return
			}
		}
	}()
	go func() {
		defer group.Done()
		for index := 0; index < 40; index++ {
			certificate, err := active.GenerateCertificate(session, "example.com")
			if err != nil {
				t.Errorf("issue certificate during reload: %v", err)
				return
			}
			leaf, err := x509.ParseCertificate(certificate.Certificate[0])
			if err != nil {
				t.Errorf("parse issued certificate: %v", err)
				return
			}
			if leaf.CheckSignatureFrom(issuers[0]) != nil && leaf.CheckSignatureFrom(issuers[1]) != nil {
				t.Error("issued certificate matches neither CA; issuer and signer were mixed")
				return
			}
		}
	}()
	group.Wait()
}

func TestGenerateCertificateMissingSessionKeyReturnsError(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "ca.pem")
	keyPath := filepath.Join(dir, "ca-key.pem")

	ca := CertificateAuthority{}
	if err := ca.Generate(certPath, keyPath); err != nil {
		t.Fatalf("CertificateAuthority.Generate() error = %v", err)
	}
	session := SessionKeyHelper{}

	if _, err := ca.GenerateCertificate(session, "example.com:443"); err == nil {
		t.Fatal("CertificateAuthority.GenerateCertificate() error = nil, want missing session key error")
	}
}

func TestGenerateCertificateMissingCAReturnsError(t *testing.T) {
	ca := CertificateAuthority{}
	session := SessionKeyHelper{}
	if err := session.Generate(); err != nil {
		t.Fatalf("SessionKeyHelper.Generate() error = %v", err)
	}

	if _, err := ca.GenerateCertificate(session, "example.com:443"); err == nil {
		t.Fatal("CertificateAuthority.GenerateCertificate() error = nil, want missing CA error")
	}
}

func TestLoadExistingCAMissingFilesReturnsError(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "missing-ca.pem")
	keyPath := filepath.Join(dir, "missing-key.pem")

	ca := CertificateAuthority{}
	if err := ca.Load(certPath, keyPath); err == nil {
		t.Fatal("CertificateAuthority.Load() error = nil, want missing file error")
	}
}

func TestGenerateCAAndCertificate(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "ca.pem")
	keyPath := filepath.Join(dir, "ca-key.pem")

	ca := CertificateAuthority{}
	if err := ca.Generate(certPath, keyPath); err != nil {
		t.Fatalf("CertificateAuthority.Generate() error = %v", err)
	}

	if _, err := os.Stat(certPath); err != nil {
		t.Fatalf("expected generated CA cert file: %v", err)
	}
	if _, err := os.Stat(keyPath); err != nil {
		t.Fatalf("expected generated CA key file: %v", err)
	}
	if ca.x509Cert == nil {
		t.Fatal("expected CA.x509Cert to be set")
	}

	ca = CertificateAuthority{}
	if err := ca.Load(certPath, keyPath); err != nil {
		t.Fatalf("CertificateAuthority.Load() error = %v", err)
	}
	if ca.x509Cert == nil {
		t.Fatal("expected CertificateAuthority.Load to populate CA.x509Cert")
	}

	session := SessionKeyHelper{}
	if err := session.Generate(); err != nil {
		t.Fatalf("SessionKeyHelper.Generate() error = %v", err)
	}
	if session.privateKey == nil {
		t.Fatal("expected SessionKey.privateKey to be set")
	}
	if len(session.PEMBlock) == 0 {
		t.Fatal("expected SessionKey.PEMBlock to be set")
	}

	cert, err := ca.GenerateCertificate(session, "example.com:443")
	if err != nil {
		t.Fatalf("CertificateAuthority.GenerateCertificate() error = %v", err)
	}
	if len(cert.Certificate) == 0 {
		t.Fatal("expected generated certificate chain")
	}

	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatalf("ParseCertificate() error = %v", err)
	}
	if leaf.Subject.CommonName != "example.com" {
		t.Fatalf("generated certificate CN = %q, want %q", leaf.Subject.CommonName, "example.com")
	}
	if len(leaf.DNSNames) != 1 || leaf.DNSNames[0] != "example.com" {
		t.Fatalf("generated certificate DNSNames = %v, want [example.com]", leaf.DNSNames)
	}
}

func TestGenerateCACreatesParentDirectories(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "credentials", "cert.pem")
	keyPath := filepath.Join(dir, "credentials", "key.pem")

	ca := CertificateAuthority{}
	if err := ca.Generate(certPath, keyPath); err != nil {
		t.Fatalf("CertificateAuthority.Generate() error = %v", err)
	}

	if _, err := os.Stat(certPath); err != nil {
		t.Fatalf("expected generated CA cert file: %v", err)
	}
	if _, err := os.Stat(keyPath); err != nil {
		t.Fatalf("expected generated CA key file: %v", err)
	}
}

func TestGenerateCAWithRootRelativePaths(t *testing.T) {
	oldWd, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd() error = %v", err)
	}
	dir := t.TempDir()
	t.Cleanup(func() {
		if err := os.Chdir(oldWd); err != nil {
			t.Fatalf("Chdir(%q) error = %v", oldWd, err)
		}
	})

	if err := os.Chdir(dir); err != nil {
		t.Fatalf("Chdir(%q) error = %v", dir, err)
	}

	ca := CertificateAuthority{}
	if err := ca.Generate("cert.pem", "key.pem"); err != nil {
		t.Fatalf("CertificateAuthority.Generate() error = %v", err)
	}

	if _, err := os.Stat("cert.pem"); err != nil {
		t.Fatalf("expected generated root-relative CA cert file: %v", err)
	}
	if _, err := os.Stat("key.pem"); err != nil {
		t.Fatalf("expected generated root-relative CA key file: %v", err)
	}
}
