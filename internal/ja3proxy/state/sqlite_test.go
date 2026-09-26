package state

import (
	"bytes"
	"database/sql"
	"path/filepath"
	"testing"
)

func TestSQLiteStorePersistsSnapshotsAndHistory(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	store, err := OpenSQLite(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SaveSnapshot("routes", "routes/1", 1, []byte(`{"revision":1}`)); err != nil {
		t.Fatal(err)
	}
	if err := store.SaveSnapshot("routes", "routes/1", 2, []byte(`{"revision":2}`)); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	store, err = OpenSQLite(path)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	document, found, err := store.Load("routes")
	if err != nil {
		t.Fatal(err)
	}
	if !found || document.Revision != 2 || !bytes.Equal(document.Payload, []byte(`{"revision":2}`)) {
		t.Fatalf("loaded document = %#v, found %v", document, found)
	}
	history, err := store.History("routes")
	if err != nil {
		t.Fatal(err)
	}
	if len(history) != 2 || !bytes.Equal(history[0], []byte(`{"revision":1}`)) || !bytes.Equal(history[1], []byte(`{"revision":2}`)) {
		t.Fatalf("history = %q", history)
	}
}

func TestSQLiteStoreMigrationIsIdempotent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	for range 2 {
		store, err := OpenSQLite(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := store.Close(); err != nil {
			t.Fatal(err)
		}
	}
}

func TestSQLiteStoreSnapshotFailureRollsBackAndKeepsDatabaseHealthy(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	store, err := OpenSQLite(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SaveSnapshot("routes", "routes/1", ^uint64(0), []byte(`{"route":true}`)); err == nil {
		t.Fatal("expected out-of-range revision to fail")
	}
	if _, found, err := store.Load("routes"); err != nil || found {
		t.Fatalf("failed snapshot left a document: found=%v err=%v", found, err)
	}
	if history, err := store.History("routes"); err != nil || len(history) != 0 {
		t.Fatalf("failed snapshot left history: %q err=%v", history, err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var integrity string
	if err := db.QueryRow(`PRAGMA integrity_check`).Scan(&integrity); err != nil || integrity != "ok" {
		t.Fatalf("sqlite integrity_check = %q, err=%v", integrity, err)
	}
}
