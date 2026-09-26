package certstore

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	cfconfig "github.com/cloudflare/cfssl/config"
	cfsr "github.com/cloudflare/cfssl/csr"
	"github.com/cloudflare/cfssl/initca"
	cfsigner "github.com/cloudflare/cfssl/signer"
	"github.com/cloudflare/cfssl/signer/local"
	"github.com/lylemi/ja3proxy/internal/ja3proxy/netutil"
	"github.com/lylemi/ja3proxy/internal/ja3proxy/secrets"
)

type CertificateAuthority struct {
	mu       sync.RWMutex
	tlsCert  tls.Certificate
	x509Cert *x509.Certificate
}

const CAExpiryWarningPeriod = 30 * 24 * time.Hour

type CertificateValidity struct {
	Status        string
	NotBefore     time.Time
	NotAfter      time.Time
	DaysRemaining int64
}

type SessionKeyHelper struct {
	privateKey *ecdsa.PrivateKey
	PEMBlock   []byte
}

func (ca *CertificateAuthority) X509Certificate() *x509.Certificate {
	if ca == nil {
		return nil
	}
	ca.mu.RLock()
	defer ca.mu.RUnlock()
	return ca.x509Cert
}

func (ca *CertificateAuthority) Generate(certPath, keyPath string) error {
	tlsCert, x509Cert, certPEM, keyPEM, err := generateCACertificate()
	if err != nil {
		return err
	}
	defer clear(keyPEM)
	if filepath.Clean(certPath) == filepath.Clean(keyPath) {
		bundle := append(append([]byte(nil), certPEM...), keyPEM...)
		defer clear(bundle)
		if err := writePEMFileAtomic(certPath, bundle); err != nil {
			return err
		}
	} else {
		if err := writePEMFile(certPath, certPEM, 0666); err != nil {
			return err
		}
		if err := writePEMFile(keyPath, keyPEM, 0600); err != nil {
			return err
		}
	}
	ca.mu.Lock()
	ca.tlsCert = tlsCert
	ca.x509Cert = x509Cert
	ca.mu.Unlock()
	return nil
}

func generateCACertificate() (tls.Certificate, *x509.Certificate, []byte, []byte, error) {
	csr := cfsr.CertificateRequest{
		CN:         "ja3proxy CA",
		KeyRequest: cfsr.NewKeyRequest(),
	}

	certPEM, _, keyPEM, err := initca.New(&csr)
	if err != nil {
		return tls.Certificate{}, nil, nil, nil, err
	}

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, nil, nil, nil, err
	}

	x509Cert, err := x509.ParseCertificate(tlsCert.Certificate[0])
	if err != nil {
		return tls.Certificate{}, nil, nil, nil, err
	}

	return tlsCert, x509Cert, certPEM, keyPEM, nil
}

func writePEMFile(path string, data []byte, perm os.FileMode) error {
	if err := ensureParentDir(path); err != nil {
		return err
	}
	out, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, perm)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = out.Write(data)
	if err != nil {
		return err
	}
	return nil
}

func ensureParentDir(path string) error {
	dir := filepath.Dir(path)
	if dir == "." || dir == "" {
		return nil
	}
	return os.MkdirAll(dir, 0700)
}

func (session *SessionKeyHelper) Generate() error {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}

	derBytes, err := x509.MarshalECPrivateKey(privKey)
	if err != nil {
		return err
	}

	PEMBlock := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: derBytes})

	session.privateKey = privKey
	session.PEMBlock = PEMBlock

	return nil
}

func (ca *CertificateAuthority) GenerateCertificate(session SessionKeyHelper, sni string) (tls.Certificate, error) {
	if session.privateKey == nil || len(session.PEMBlock) == 0 {
		return tls.Certificate{}, fmt.Errorf("session key has not been generated")
	}
	if ca == nil {
		return tls.Certificate{}, fmt.Errorf("CA certificate has not been loaded")
	}
	ca.mu.RLock()
	issuer := ca.x509Cert
	privateKey := ca.tlsCert.PrivateKey
	ca.mu.RUnlock()
	if issuer == nil {
		return tls.Certificate{}, fmt.Errorf("CA certificate has not been loaded")
	}
	cryptoSigner, ok := privateKey.(crypto.Signer)
	if !ok {
		return tls.Certificate{}, fmt.Errorf("CA private key is not a crypto signer")
	}

	hostname := netutil.StripPort(sni)
	request := &cfsr.CertificateRequest{
		CN:         hostname,
		Hosts:      []string{hostname},
		KeyRequest: cfsr.NewKeyRequest(),
	}

	csrBytes, err := cfsr.Generate(session.privateKey, request)
	if err != nil {
		return tls.Certificate{}, err
	}

	profile := cfconfig.DefaultConfig()
	policy := &cfconfig.Signing{
		Default: profile,
	}

	signer, err := local.NewSigner(cryptoSigner, issuer, cfsigner.DefaultSigAlgo(cryptoSigner), policy)
	if err != nil {
		return tls.Certificate{}, err
	}

	signRequest := cfsigner.SignRequest{
		Request: string(csrBytes),
		Subject: &cfsigner.Subject{
			CN: request.CN,
		},
		Hosts: request.Hosts,
	}

	certBytes, err := signer.Sign(signRequest)
	if err != nil {
		return tls.Certificate{}, err
	}

	tlsCert, err := tls.X509KeyPair(certBytes, session.PEMBlock)
	return tlsCert, err
}

func (ca *CertificateAuthority) Load(certPath, keyPath string) error {
	return ca.LoadWithProvider(secrets.FileProvider{}, certPath, keyPath)
}

func writePEMFileAtomic(path string, data []byte) error {
	if err := ensureParentDir(path); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".ca-bundle-*")
	if err != nil {
		return err
	}
	defer func() {
		_ = tmp.Close()
		_ = os.Remove(tmp.Name())
	}()
	if err := tmp.Chmod(0600); err != nil {
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

func (ca *CertificateAuthority) Validity(now time.Time) CertificateValidity {
	if ca == nil {
		return CertificateValidity{Status: "UNAVAILABLE"}
	}
	ca.mu.RLock()
	certificate := ca.x509Cert
	ca.mu.RUnlock()
	return ValidityForCertificate(certificate, now)
}

func ValidityForCertificate(certificate *x509.Certificate, now time.Time) CertificateValidity {
	if certificate == nil {
		return CertificateValidity{Status: "UNAVAILABLE"}
	}
	if now.IsZero() {
		now = time.Now()
	}
	now = now.UTC()
	remaining := certificate.NotAfter.Sub(now)
	days := int64(remaining / (24 * time.Hour))
	if remaining > 0 && remaining%(24*time.Hour) != 0 {
		days++
	}
	if remaining < 0 {
		days = -int64((-remaining + 24*time.Hour - 1) / (24 * time.Hour))
	}
	result := CertificateValidity{Status: "VALID", NotBefore: certificate.NotBefore.UTC(), NotAfter: certificate.NotAfter.UTC(), DaysRemaining: days}
	switch {
	case now.Before(certificate.NotBefore):
		result.Status = "NOT_YET_VALID"
	case !now.Before(certificate.NotAfter):
		result.Status = "EXPIRED"
	case remaining <= CAExpiryWarningPeriod:
		result.Status = "EXPIRING"
	}
	return result
}

func CertificateFileValidity(provider secrets.Provider, reference string, now time.Time) CertificateValidity {
	if strings.TrimSpace(reference) == "" {
		return CertificateValidity{Status: "UNAVAILABLE"}
	}
	data, err := secrets.Read(provider, reference)
	if err != nil {
		return CertificateValidity{Status: "UNAVAILABLE"}
	}
	defer clear(data)
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" {
		return CertificateValidity{Status: "UNAVAILABLE"}
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return CertificateValidity{Status: "UNAVAILABLE"}
	}
	return ValidityForCertificate(certificate, now)
}

func (ca *CertificateAuthority) LoadWithProvider(provider secrets.Provider, certPath, keyPath string) error {
	tlsCert, err := secrets.LoadKeyPair(provider, certPath, keyPath)
	if err != nil {
		return err
	}
	x509Cert, err := x509.ParseCertificate(tlsCert.Certificate[0])
	if err != nil {
		return err
	}

	ca.mu.Lock()
	ca.tlsCert = tlsCert
	ca.x509Cert = x509Cert
	ca.mu.Unlock()

	return nil
}
