package audit

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestAppendQueryReopenAndRedact(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	store, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	for index := 0; index < 3; index++ {
		err := store.Append(Event{
			Timestamp: time.Date(2026, 9, 24, 10, index, 0, 0, time.UTC),
			Actor:     "operator",
			Action:    "update",
			Object:    "/api/config",
			NewValue:  json.RawMessage(`{"proxyPassword":"do-not-store","tlsFingerprint":"Chrome@120"}`),
			Result:    "success",
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	page, err := store.Query(2, "")
	if err != nil || len(page.Items) != 2 || page.NextCursor == "" {
		t.Fatalf("first page = %#v, err=%v", page, err)
	}
	if strings.Contains(string(page.Items[0].NewValue), "do-not-store") || !strings.Contains(string(page.Items[0].NewValue), "[REDACTED]") {
		t.Fatalf("audit value was not redacted: %s", page.Items[0].NewValue)
	}
	if page.Items[0].Hash == "" || page.Items[1].Hash == "" || page.Items[0].PrevHash != page.Items[1].Hash {
		t.Fatalf("audit integrity chain is invalid: newest=%+v older=%+v", page.Items[0], page.Items[1])
	}
	next, err := store.Query(2, page.NextCursor)
	if err != nil || len(next.Items) != 1 || next.NextCursor != "" {
		t.Fatalf("second page = %#v, err=%v", next, err)
	}
}

func TestOpenRejectsTamperedIntegrityChain(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	store, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Append(Event{Actor: "operator", Action: "put", Object: "/api/config", Result: "success"}); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lineEnd := bytes.IndexByte(data, '\n')
	if lineEnd < 0 {
		t.Fatal("audit file has no event line")
	}
	var event Event
	if err := json.Unmarshal(data[:lineEnd], &event); err != nil {
		t.Fatal(err)
	}
	event.Actor = "tampered"
	line, err := json.Marshal(event)
	if err != nil {
		t.Fatal(err)
	}
	data = append(append(line, '\n'), data[lineEnd+1:]...)
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}

	if _, err := Open(path); err == nil || !strings.Contains(err.Error(), "integrity") {
		t.Fatalf("Open() error = %v, want integrity error", err)
	}
}

func TestQueryRejectsExpiredCursor(t *testing.T) {
	store, err := Open("")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if _, err := store.Query(10, "missing"); err != ErrCursorNotFound {
		t.Fatalf("cursor error = %v", err)
	}
}

func TestSQLiteAuditReopenQueryAndIntegrity(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.sqlite")
	store, err := OpenSQLite(path)
	if err != nil {
		t.Fatal(err)
	}
	for index := 0; index < 3; index++ {
		if err := store.Append(Event{
			Timestamp: time.Date(2026, 9, 24, 11, index, 0, 0, time.UTC),
			Actor:     "operator",
			Action:    "update",
			Object:    "/api/config",
			NewValue:  json.RawMessage(`{"token":"do-not-store","enabled":true}`),
			Result:    "success",
		}); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = OpenSQLite(path)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	page, err := store.Query(2, "")
	if err != nil || len(page.Items) != 2 || page.NextCursor == "" {
		t.Fatalf("first sqlite page = %#v, err=%v", page, err)
	}
	if strings.Contains(string(page.Items[0].NewValue), "do-not-store") || !strings.Contains(string(page.Items[0].NewValue), "[REDACTED]") {
		t.Fatalf("sqlite audit value was not redacted: %s", page.Items[0].NewValue)
	}
	if page.Items[0].Hash == "" || page.Items[1].Hash == "" || page.Items[0].PrevHash != page.Items[1].Hash {
		t.Fatalf("sqlite audit integrity chain is invalid: newest=%+v older=%+v", page.Items[0], page.Items[1])
	}
	next, err := store.Query(2, page.NextCursor)
	if err != nil || len(next.Items) != 1 || next.NextCursor != "" {
		t.Fatalf("second sqlite page = %#v, err=%v", next, err)
	}
}

func TestSQLiteAuditImportsLegacyLogAndThenUsesDatabaseAsPrimary(t *testing.T) {
	dir := t.TempDir()
	legacyPath := filepath.Join(dir, "audit.jsonl")
	databasePath := filepath.Join(dir, "control.db")
	legacy, err := Open(legacyPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, action := range []string{"create", "update"} {
		if err := legacy.Append(Event{Actor: "operator", Action: action, Object: "profile", Result: "success"}); err != nil {
			t.Fatal(err)
		}
	}
	if err := legacy.Close(); err != nil {
		t.Fatal(err)
	}

	store, err := OpenSQLiteWithLegacy(databasePath, legacyPath)
	if err != nil {
		t.Fatal(err)
	}
	page, err := store.Query(10, "")
	if err != nil || len(page.Items) != 2 || page.Items[0].Action != "update" || page.Items[1].Action != "create" {
		t.Fatalf("imported audit page = %+v, err = %v", page, err)
	}
	if page.Items[0].PrevHash != page.Items[1].Hash || page.Items[0].Hash == "" {
		t.Fatalf("imported audit chain is invalid: %+v", page.Items)
	}
	if err := os.WriteFile(legacyPath, []byte("invalid legacy data"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = OpenSQLiteWithLegacy(databasePath, legacyPath)
	if err != nil {
		t.Fatalf("SQLite should be authoritative after import: %v", err)
	}
	defer store.Close()
	page, err = store.Query(10, "")
	if err != nil || len(page.Items) != 2 {
		t.Fatalf("restored SQLite audit events = %+v, err = %v", page, err)
	}
}
