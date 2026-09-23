package recorder

import (
	"database/sql"
	"path/filepath"
	"testing"

	"github.com/lylemi/ja3proxy/internal/ja3proxy/capture/tlshello"
)

func TestSQLitePersistenceReopenAndRetention(t *testing.T) {
	path := filepath.Join(t.TempDir(), "recorder.db")
	r, err := New(Options{Raw: true, RecentLimit: 2, SQLitePath: path, SQLiteRetention: 2})
	if err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= 3; i++ {
		if !r.TryCapture(Meta{ConnectionID: string(rune('0' + i)), CapturePoint: "CLIENT_IN"}, sample()) {
			t.Fatalf("enqueue %d", i)
		}
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}

	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM observations`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 2 {
		t.Fatalf("sqlite retention count = %d, want 2", count)
	}
	var migrations int
	if err := db.QueryRow(`SELECT COUNT(*) FROM recorder_schema_migrations WHERE version = 1`).Scan(&migrations); err != nil {
		t.Fatal(err)
	}
	if migrations != 1 {
		t.Fatalf("migration rows = %d, want 1", migrations)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := New(Options{Raw: true, RecentLimit: 2, SQLitePath: path, SQLiteRetention: 2})
	if err != nil {
		t.Fatal(err)
	}
	items := reopened.Snapshot()
	if len(items) != 2 || items[0].ConnectionID != "3" || items[1].ConnectionID != "2" {
		t.Fatalf("reopened observations = %+v", items)
	}
	if len(items[0].Raw) == 0 || len(items[1].Raw) == 0 {
		t.Fatal("raw payload was not restored with explicit raw policy")
	}
	if err := reopened.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestSQLitePreservesPrivacyPolicyAcrossReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "metadata.db")
	r, err := New(Options{SQLitePath: path, SQLiteRetention: 4})
	if err != nil {
		t.Fatal(err)
	}
	if !r.TryCapture(Meta{ConnectionID: "metadata"}, tlshello.Capture{Status: "complete", Raw: sample().Raw, Records: sample().Records}) {
		t.Fatal("enqueue")
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := New(Options{SQLitePath: path, SQLiteRetention: 4})
	if err != nil {
		t.Fatal(err)
	}
	items := reopened.Snapshot()
	if len(items) != 1 || len(items[0].Raw) != 0 || len(items[0].Records) != 0 {
		t.Fatalf("privacy policy was not preserved: %+v", items)
	}
	if err := reopened.Close(); err != nil {
		t.Fatal(err)
	}
}
