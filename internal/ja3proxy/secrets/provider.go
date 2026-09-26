// Package secrets centralizes access to externally stored secret material.
// Secret bytes are resolved at runtime and are never copied into application
// configuration snapshots or exported profile data.
package secrets

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

const MaxFileSecretSize = 1 << 20

var ErrInvalidReference = errors.New("secret reference must name a regular file")

// Provider resolves a secret reference into a fresh byte slice owned by the
// caller. Implementations must not include secret values in returned errors.
type Provider interface {
	Read(reference string) ([]byte, error)
}

// FileProvider resolves local file references. Existing path-based CLI
// configuration remains compatible and can be migrated without moving keys.
type FileProvider struct{}

func (FileProvider) Read(reference string) ([]byte, error) {
	reference = strings.TrimSpace(reference)
	if reference == "" {
		return nil, ErrInvalidReference
	}
	file, err := os.Open(reference)
	if err != nil {
		return nil, fmt.Errorf("open secret reference: %w", err)
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat secret reference: %w", err)
	}
	if !info.Mode().IsRegular() || info.Size() > MaxFileSecretSize {
		return nil, ErrInvalidReference
	}
	value, err := io.ReadAll(io.LimitReader(file, MaxFileSecretSize+1))
	if err != nil {
		clear(value)
		return nil, fmt.Errorf("read secret reference: %w", err)
	}
	if len(value) > MaxFileSecretSize {
		clear(value)
		return nil, ErrInvalidReference
	}
	return value, nil
}

func Read(provider Provider, reference string) ([]byte, error) {
	reference = strings.TrimSpace(reference)
	if reference == "" {
		return nil, ErrInvalidReference
	}
	if provider == nil {
		provider = FileProvider{}
	}
	value, err := provider.Read(reference)
	if err != nil {
		clear(value)
		return nil, err
	}
	if len(value) > MaxFileSecretSize {
		clear(value)
		return nil, ErrInvalidReference
	}
	return value, nil
}

func LoadKeyPair(provider Provider, certificateReference, keyReference string) (tls.Certificate, error) {
	certificatePEM, err := Read(provider, certificateReference)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("load TLS certificate: %w", err)
	}
	defer clear(certificatePEM)
	// A combined PEM bundle is one secret snapshot. Reading the same reference
	// twice could straddle an atomic file replacement and mix two generations.
	if strings.TrimSpace(certificateReference) == strings.TrimSpace(keyReference) {
		certificate, err := tls.X509KeyPair(certificatePEM, certificatePEM)
		if err != nil {
			return tls.Certificate{}, fmt.Errorf("parse TLS key pair: %w", err)
		}
		return certificate, nil
	}
	privateKeyPEM, err := Read(provider, keyReference)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("load TLS private key: %w", err)
	}
	defer clear(privateKeyPEM)
	certificate, err := tls.X509KeyPair(certificatePEM, privateKeyPEM)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("parse TLS key pair: %w", err)
	}
	return certificate, nil
}
