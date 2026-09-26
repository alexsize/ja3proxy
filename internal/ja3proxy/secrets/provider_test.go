package secrets

import (
	"os"
	"path/filepath"
	"testing"
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
