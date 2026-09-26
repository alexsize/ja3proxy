package recorder

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestReloadSpoolKeyPreservesPendingRecordsAndSurvivesRestart(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "key")
	oldKey, newKey := bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32)
	writeKey := func(key []byte) {
		t.Helper()
		if err := os.WriteFile(keyPath, key, 0600); err != nil {
			t.Fatal(err)
		}
	}
	writeKey(oldKey)
	r, err := New(Options{SpoolPath: filepath.Join(dir, "spool"), SpoolKeyPath: keyPath})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if err := r.spool.append("old", []byte(`{"value":1}`)); err != nil {
		t.Fatal(err)
	}
	writeKey(newKey)
	if err := r.ReloadSpoolKey(); !errors.Is(err, ErrSpoolPending) {
		t.Fatalf("pending rotation: %v", err)
	}
	seen := 0
	if err := r.spool.replay(func(id string, payload []byte) error {
		seen++
		if id != "old" || string(payload) != `{"value":1}` {
			t.Errorf("pending record changed: %s %s", id, payload)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if seen != 1 {
		t.Fatalf("replayed %d records", seen)
	}
	writeKey([]byte("invalid"))
	if err := r.ReloadSpoolKey(); err == nil {
		t.Fatal("invalid key accepted")
	}
	if !bytes.Equal(r.spool.key, oldKey) {
		t.Fatal("invalid key replaced active key")
	}
	writeKey(newKey)
	if err := r.ReloadSpoolKey(); err != nil {
		t.Fatal(err)
	}
	if err := r.spool.append("new", []byte(`{"value":2}`)); err != nil {
		t.Fatal(err)
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	if err := r.ReloadSpoolKey(); !errors.Is(err, ErrSpoolUnavailable) {
		t.Fatalf("closed recorder: %v", err)
	}
	reopened, err := openSpool(r.opts.SpoolPath, keyPath, 0)
	if err != nil {
		t.Fatal(err)
	}
	seen = 0
	if err := reopened.replay(func(id string, payload []byte) error {
		seen++
		if id != "new" || string(payload) != `{"value":2}` {
			t.Errorf("rotated record changed: %s %s", id, payload)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if seen != 1 {
		t.Fatalf("replayed %d rotated records", seen)
	}
}

func TestSpoolKeyExpiryIsAdvisoryAndPersistsAcrossRestart(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "key")
	key := bytes.Repeat([]byte{0x6a}, 32)
	if err := os.WriteFile(keyPath, key, 0600); err != nil {
		t.Fatal(err)
	}
	spoolPath := filepath.Join(dir, "spool")
	store, err := openSpoolWithPolicy(spoolPath, keyPath, 0, nil, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	status, activatedAt, expiresAt := store.keyExpiryStatus(time.Now().UTC())
	if status != "VALID" || activatedAt == nil || expiresAt == nil || !expiresAt.Equal(activatedAt.Add(time.Hour)) {
		t.Fatalf("initial key status = %q, %v, %v", status, activatedAt, expiresAt)
	}
	status, _, _ = store.keyExpiryStatus(time.Now().UTC().Add(59 * time.Minute))
	if status != "EXPIRING" {
		t.Fatalf("near-expiry key status = %q, want EXPIRING", status)
	}
	oldActivation := time.Now().UTC().Add(-2 * time.Hour).Truncate(time.Second)
	digest := sha256.Sum256(key)
	marker, err := json.Marshal(spoolKeyMarker{KeyID: hex.EncodeToString(digest[:]), ActivatedAt: &oldActivation})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(spoolPath, spoolKeyIDFile), marker, 0600); err != nil {
		t.Fatal(err)
	}
	expired, err := openSpoolWithPolicy(spoolPath, keyPath, 0, nil, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	status, _, _ = expired.keyExpiryStatus(time.Now().UTC())
	if status != "EXPIRED" {
		t.Fatalf("expired key status = %q", status)
	}
	if err := expired.append("still-usable", []byte(`{"ok":true}`)); err != nil {
		t.Fatalf("expiry blocked spool write: %v", err)
	}
	reopened, err := openSpoolWithPolicy(spoolPath, keyPath, 0, nil, time.Hour)
	if err != nil {
		t.Fatalf("expiry blocked restart/replay: %v", err)
	}
	status, _, _ = reopened.keyExpiryStatus(time.Now().UTC())
	if status != "EXPIRED" {
		t.Fatalf("persisted status = %q", status)
	}
}

func TestLegacyPendingSpoolKeyExpiryRemainsUnknown(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "key")
	if err := os.WriteFile(keyPath, bytes.Repeat([]byte{0x6b}, 32), 0600); err != nil {
		t.Fatal(err)
	}
	spoolPath := filepath.Join(dir, "spool")
	store, err := openSpool(spoolPath, keyPath, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.append("legacy", []byte(`{"ok":true}`)); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(spoolPath, spoolKeyIDFile)); err != nil {
		t.Fatal(err)
	}
	migrated, err := openSpoolWithPolicy(spoolPath, keyPath, 0, nil, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	status, activatedAt, expiresAt := migrated.keyExpiryStatus(time.Now().UTC())
	if status != "UNKNOWN" || activatedAt != nil || expiresAt != nil {
		t.Fatalf("legacy key status = %q, %v, %v; want unknown", status, activatedAt, expiresAt)
	}
}

func TestRecorderStatsExposeSpoolKeyExpiry(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "key")
	if err := os.WriteFile(keyPath, bytes.Repeat([]byte{0x6c}, 32), 0600); err != nil {
		t.Fatal(err)
	}
	recorder, err := New(Options{
		SpoolPath: filepath.Join(dir, "spool"), SpoolKeyPath: keyPath,
		SpoolKeyMaxAge: 24 * time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer recorder.Close()
	stats := recorder.Stats()
	if stats.SpoolKeyStatus != "VALID" || stats.SpoolKeyActivatedAt == nil || stats.SpoolKeyExpiresAt == nil {
		t.Fatalf("spool key expiry missing from recorder stats: %+v", stats)
	}
}

func TestSpoolRotationPublicationFailureKeepsOldKey(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "key")
	oldKey := bytes.Repeat([]byte{3}, 32)
	if err := os.WriteFile(keyPath, oldKey, 0600); err != nil {
		t.Fatal(err)
	}
	s, err := openSpool(filepath.Join(dir, "spool"), keyPath, 0)
	if err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(s.dir, spoolKeyIDFile)
	if err := os.Remove(marker); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(marker, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, bytes.Repeat([]byte{4}, 32), 0600); err != nil {
		t.Fatal(err)
	}
	if err := s.rotateKey(keyPath, nil); err == nil {
		t.Fatal("unwritable marker accepted")
	}
	if !bytes.Equal(s.key, oldKey) {
		t.Fatal("publication failure replaced active key")
	}
}

func TestSpoolRotationSerializesWithAppend(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "key")
	if err := os.WriteFile(keyPath, bytes.Repeat([]byte{5}, 32), 0600); err != nil {
		t.Fatal(err)
	}
	s, err := openSpool(filepath.Join(dir, "spool"), keyPath, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, bytes.Repeat([]byte{6}, 32), 0600); err != nil {
		t.Fatal(err)
	}
	var group sync.WaitGroup
	group.Add(2)
	go func() {
		defer group.Done()
		for i := 0; i < 20; i++ {
			if err := s.rotateKey(keyPath, nil); err != nil && !errors.Is(err, ErrSpoolPending) {
				t.Errorf("rotate: %v", err)
				return
			}
		}
	}()
	go func() {
		defer group.Done()
		if err := s.append("concurrent", []byte(`{"value":3}`)); err != nil {
			t.Errorf("append: %v", err)
		}
	}()
	group.Wait()
	seen := 0
	if err := s.replay(func(string, []byte) error { seen++; return nil }); err != nil {
		t.Fatal(err)
	}
	if seen != 1 {
		t.Fatalf("concurrent record was not recoverable: %d", seen)
	}
}
