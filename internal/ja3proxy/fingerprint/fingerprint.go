package fingerprint

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/lylemi/ja3proxy/internal/ja3proxy/logutil"
	utls "github.com/refraction-networking/utls"
)

type TLSFingerprint struct {
	Client        string `json:"client"`
	Version       string `json:"version"`
	HandshakeType string `json:"handshake_type,omitempty"`
}

type TLSFingerprintStore struct {
	mu      sync.RWMutex
	current *TLSFingerprint
}

func (s *TLSFingerprintStore) Get() (TLSFingerprint, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.current == nil {
		return TLSFingerprint{}, false
	}
	return *s.current, true
}

func (s *TLSFingerprintStore) Set(fingerprint TLSFingerprint) {
	s.mu.Lock()
	defer s.mu.Unlock()

	f := normalizeTLSFingerprint(fingerprint)
	s.current = &f
}

func normalizeTLSFingerprint(fingerprint TLSFingerprint) TLSFingerprint {
	if fingerprint.HandshakeType == "" {
		fingerprint.HandshakeType = handshakeTypeForVersion(fingerprint.Version)
	}
	return fingerprint
}

func handshakeTypeForVersion(version string) string {
	if strings.Contains(strings.ToUpper(version), "PSK") {
		return "PSK"
	}
	return "FULL"
}

func IsPSK(fingerprint TLSFingerprint) bool {
	return normalizeTLSFingerprint(fingerprint).HandshakeType == "PSK"
}

func (s *TLSFingerprintStore) SetValidated(fingerprint TLSFingerprint) error {
	if fingerprint.Client == "" {
		return fmt.Errorf("fingerprint client is required")
	}
	if fingerprint.Version == "" {
		return fmt.Errorf("fingerprint version is required")
	}
	if err := validateTLSFingerprint(fingerprint); err != nil {
		return err
	}

	s.Set(fingerprint)
	return nil
}

func (s *TLSFingerprintStore) Reset() {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.current = nil
}

func validateTLSFingerprint(fingerprint TLSFingerprint) error {
	clientHelloID := utls.ClientHelloID{
		Client:  fingerprint.Client,
		Version: fingerprint.Version,
	}
	if clientHelloID.Client == utls.HelloGolang.Client {
		if clientHelloID.Version != utls.HelloGolang.Version {
			return unsupportedTLSFingerprintError(fingerprint, nil)
		}
		return nil
	}
	if _, err := utls.UTLSIdToSpec(clientHelloID); err != nil {
		return unsupportedTLSFingerprintError(fingerprint, err)
	}
	return nil
}

func ValidateTLSFingerprint(fingerprint TLSFingerprint) error {
	return validateTLSFingerprint(fingerprint)
}

func loadTLSFingerprintFile(path string) (TLSFingerprint, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return TLSFingerprint{}, err
	}

	var fingerprint TLSFingerprint
	if err := json.Unmarshal(data, &fingerprint); err != nil {
		return TLSFingerprint{}, err
	}
	if fingerprint.Client == "" {
		return TLSFingerprint{}, fmt.Errorf("fingerprint client is required")
	}
	if fingerprint.Version == "" {
		return TLSFingerprint{}, fmt.Errorf("fingerprint version is required")
	}
	return fingerprint, nil
}

func (s *TLSFingerprintStore) ApplyFile(path string) error {
	fingerprint, err := loadTLSFingerprintFile(path)
	if err != nil {
		return err
	}
	if err := s.SetValidated(fingerprint); err != nil {
		return err
	}

	logutil.Info(
		"fingerprint",
		"loaded TLS fingerprint",
		"client", fingerprint.Client,
		"version", fingerprint.Version,
		"path", path,
	)
	return nil
}

type tlsFingerprintFileState struct {
	path    string
	modTime time.Time
	size    int64
}

func newTLSFingerprintFileState(path string) (tlsFingerprintFileState, error) {
	stat, err := os.Stat(path)
	if err != nil {
		return tlsFingerprintFileState{}, err
	}
	return tlsFingerprintFileState{
		path:    path,
		modTime: stat.ModTime(),
		size:    stat.Size(),
	}, nil
}

func (state tlsFingerprintFileState) changed(stat os.FileInfo) bool {
	return stat.ModTime().After(state.modTime) || stat.Size() != state.size
}

func (state *tlsFingerprintFileState) update(stat os.FileInfo) {
	state.modTime = stat.ModTime()
	state.size = stat.Size()
}

func (s *TLSFingerprintStore) WatchFile(ctx context.Context, path string, interval time.Duration) error {
	if interval <= 0 {
		return fmt.Errorf("fingerprint reload interval must be positive")
	}
	if err := s.ApplyFile(path); err != nil {
		return err
	}

	state, err := newTLSFingerprintFileState(path)
	if err != nil {
		return err
	}

	go s.watchFile(ctx, interval, state)
	return nil
}

func (s *TLSFingerprintStore) watchFile(ctx context.Context, interval time.Duration, state tlsFingerprintFileState) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.reloadFileIfChanged(&state)
		}
	}
}

func (s *TLSFingerprintStore) reloadFileIfChanged(state *tlsFingerprintFileState) {
	stat, err := os.Stat(state.path)
	if err != nil {
		logutil.Error("fingerprint", "check TLS fingerprint config failed", "path", state.path, "err", err)
		return
	}
	if !state.changed(stat) {
		return
	}

	if err := s.ApplyFile(state.path); err != nil {
		logutil.Error("fingerprint", "reload TLS fingerprint config failed", "path", state.path, "err", err)
		return
	}
	state.update(stat)
}
