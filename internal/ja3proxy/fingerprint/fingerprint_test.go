package fingerprint

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lylemi/ja3proxy/internal/ja3proxy/state"
)

func TestSetTLSFingerprintValidatesRequiredFields(t *testing.T) {
	store := &TLSFingerprintStore{}

	if err := store.SetValidated(TLSFingerprint{Version: "106"}); err == nil {
		t.Fatal("TLSFingerprintStore.SetValidated() error = nil, want missing client error")
	}
	if err := store.SetValidated(TLSFingerprint{Client: "Chrome"}); err == nil {
		t.Fatal("TLSFingerprintStore.SetValidated() error = nil, want missing version error")
	}
	if err := store.SetValidated(TLSFingerprint{Client: "NoSuchClient", Version: "999"}); err == nil {
		t.Fatal("TLSFingerprintStore.SetValidated() error = nil, want unsupported fingerprint error")
	}
}

func TestTLSFingerprintStorePersistsAndRestoresSQLiteSnapshot(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	database, err := state.OpenSQLite(path)
	if err != nil {
		t.Fatal(err)
	}
	store := &TLSFingerprintStore{}
	if found, err := store.BindState(database); err != nil || found {
		t.Fatalf("initial BindState() = found %v, err %v", found, err)
	}
	if err := store.SetValidated(TLSFingerprint{Client: "Firefox", Version: "105"}); err != nil {
		t.Fatal(err)
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}
	database, err = state.OpenSQLite(path)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	restored := &TLSFingerprintStore{}
	if found, err := restored.BindState(database); err != nil || !found {
		t.Fatalf("restored BindState() = found %v, err %v", found, err)
	}
	if got, found := restored.Get(); !found || got.Client != "Firefox" || got.Version != "105" {
		t.Fatalf("restored TLS fingerprint = %+v, found %v", got, found)
	}
}

func TestValidateTLSFingerprintReturnsCatalogSuggestions(t *testing.T) {
	err := validateTLSFingerprint(TLSFingerprint{Client: "Chrome", Version: "999"})
	if err == nil {
		t.Fatal("validateTLSFingerprint() error = nil, want unsupported version error")
	}
	if !strings.Contains(err.Error(), "available Chrome versions") {
		t.Fatalf("error = %q, want available Chrome versions", err)
	}
	if !strings.Contains(err.Error(), "--list-tls-fingerprints") {
		t.Fatalf("error = %q, want list fingerprints hint", err)
	}

	err = validateTLSFingerprint(TLSFingerprint{Client: "Golang", Version: "999"})
	if err == nil {
		t.Fatal("validateTLSFingerprint() error = nil, want unsupported Golang version error")
	}
	if !strings.Contains(err.Error(), "available Golang versions") {
		t.Fatalf("error = %q, want available Golang versions", err)
	}
}

func TestLoadTLSFingerprintFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fingerprint.json")
	if err := os.WriteFile(path, []byte(`{"client":"Chrome","version":"106"}`), 0o600); err != nil {
		t.Fatalf("write fingerprint file: %v", err)
	}

	got, err := loadTLSFingerprintFile(path)
	if err != nil {
		t.Fatalf("loadTLSFingerprintFile() error = %v", err)
	}
	if got.Client != "Chrome" || got.Version != "106" {
		t.Fatalf("loadTLSFingerprintFile() = %+v, want Chrome 106", got)
	}
}

func TestWatchTLSFingerprintFileReloadsChanges(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fingerprint.json")
	if err := os.WriteFile(path, []byte(`{"client":"Chrome","version":"106"}`), 0o600); err != nil {
		t.Fatalf("write initial fingerprint file: %v", err)
	}

	store := &TLSFingerprintStore{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := store.WatchFile(ctx, path, 10*time.Millisecond); err != nil {
		t.Fatalf("TLSFingerprintStore.WatchFile() error = %v", err)
	}

	got, ok := store.Get()
	if !ok {
		t.Fatal("TLSFingerprintStore.Get() ok = false, want loaded fingerprint")
	}
	if got.Client != "Chrome" || got.Version != "106" {
		t.Fatalf("initial TLSFingerprintStore.Get() = %+v, want Chrome 106", got)
	}

	if err := os.WriteFile(path, []byte(`{"client":"Firefox","version":"105"}`), 0o600); err != nil {
		t.Fatalf("write updated fingerprint file: %v", err)
	}
	if err := os.Chtimes(path, time.Now().Add(time.Second), time.Now().Add(time.Second)); err != nil {
		t.Fatalf("touch updated fingerprint file: %v", err)
	}

	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		got, ok = store.Get()
		if ok && got.Client == "Firefox" && got.Version == "105" {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}

	t.Fatalf("TLSFingerprintStore.Get() = %+v, want reloaded Firefox 105", got)
}
