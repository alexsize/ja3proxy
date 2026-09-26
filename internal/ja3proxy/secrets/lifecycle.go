package secrets

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Metadata describes non-secret lifecycle information for a stored secret.
// ExpiresAt is nil when the file does not contain a parseable X.509 certificate.
type Metadata struct {
	Size       int64
	ModifiedAt time.Time
	ExpiresAt  *time.Time
}

// LifecycleProvider is an optional extension for providers that can report
// secret metadata and atomically replace an existing secret reference. It is
// separate from Provider so read-only and remote implementations remain
// compatible.
type LifecycleProvider interface {
	Provider
	Metadata(reference string) (Metadata, error)
	Rotate(reference string, value []byte) error
}

// Metadata reports file timestamps and, for certificate PEM files, the
// certificate expiration time. Secret contents are never returned.
func (FileProvider) Metadata(reference string) (Metadata, error) {
	reference = strings.TrimSpace(reference)
	if reference == "" {
		return Metadata{}, ErrInvalidReference
	}
	info, err := os.Stat(reference)
	if err != nil {
		return Metadata{}, fmt.Errorf("stat secret reference: %w", err)
	}
	if !info.Mode().IsRegular() || info.Size() > MaxFileSecretSize {
		return Metadata{}, ErrInvalidReference
	}
	metadata := Metadata{Size: info.Size(), ModifiedAt: info.ModTime().UTC()}
	value, err := (FileProvider{}).Read(reference)
	if err != nil {
		return Metadata{}, err
	}
	defer clear(value)
	for block, rest := pem.Decode(value); block != nil; block, rest = pem.Decode(rest) {
		if block.Type != "CERTIFICATE" {
			continue
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return Metadata{}, errors.New("parse secret certificate metadata")
		}
		expiresAt := certificate.NotAfter.UTC()
		metadata.ExpiresAt = &expiresAt
		break
	}
	return metadata, nil
}

// Rotate atomically replaces an existing regular-file secret, preserving its
// permissions. Pair validation remains the responsibility of the caller; a
// combined certificate/key bundle can be replaced as one reference.
func (FileProvider) Rotate(reference string, value []byte) error {
	reference = strings.TrimSpace(reference)
	if reference == "" || len(value) == 0 || len(value) > MaxFileSecretSize {
		return ErrInvalidReference
	}
	info, err := os.Lstat(reference)
	if err != nil {
		return fmt.Errorf("stat secret reference for rotation: %w", err)
	}
	if !info.Mode().IsRegular() {
		return ErrInvalidReference
	}
	dir := filepath.Dir(reference)
	temporary, err := os.CreateTemp(dir, ".ja3proxy-secret-rotation-*")
	if err != nil {
		return fmt.Errorf("create secret rotation file: %w", err)
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(info.Mode().Perm()); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("set secret rotation permissions: %w", err)
	}
	if _, err := temporary.Write(value); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("write secret rotation file: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("sync secret rotation file: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close secret rotation file: %w", err)
	}
	if err := os.Rename(temporaryPath, reference); err != nil {
		return fmt.Errorf("publish secret rotation: %w", err)
	}
	return nil
}
