package certstore

import (
	"errors"
	"path/filepath"

	"github.com/lylemi/ja3proxy/internal/ja3proxy/secrets"
)

// RotateCertificateAuthority creates and activates a new local CA after
// atomically replacing its combined certificate/key bundle. Separate paths
// are rejected because replacing two files cannot keep the pair consistent.
func RotateCertificateAuthority(ca *CertificateAuthority, provider secrets.LifecycleProvider, certificateReference, keyReference string) error {
	if ca == nil || provider == nil {
		return errors.New("CA and lifecycle provider are required")
	}
	if certificateReference == "" || keyReference == "" || filepath.Clean(certificateReference) != filepath.Clean(keyReference) {
		return errors.New("CA rotation requires a combined certificate/key bundle")
	}

	tlsCert, x509Cert, certificatePEM, keyPEM, err := generateCACertificate()
	if err != nil {
		return err
	}
	defer clear(keyPEM)
	bundle := append(append([]byte(nil), certificatePEM...), keyPEM...)
	defer clear(bundle)
	ca.mu.Lock()
	defer ca.mu.Unlock()
	if err := provider.Rotate(certificateReference, bundle); err != nil {
		return err
	}
	ca.tlsCert = tlsCert
	ca.x509Cert = x509Cert
	return nil
}
