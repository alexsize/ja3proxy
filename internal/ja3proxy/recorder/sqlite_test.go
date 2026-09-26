package recorder

import (
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	"github.com/lylemi/ja3proxy/internal/ja3proxy/capture/tlshello"
)

func TestSQLiteBackupCreatesStandaloneSnapshot(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "recorder.db")
	backup := filepath.Join(dir, "backup.db")
	r, err := New(Options{SQLitePath: path, SQLiteRetention: 10})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if !r.TryCapture(Meta{ConnectionID: "backup"}, sample()) {
		t.Fatal("enqueue")
	}
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) && len(r.Snapshot()) == 0 {
		time.Sleep(time.Millisecond)
	}
	if len(r.Snapshot()) != 1 {
		t.Fatal("observation was not processed")
	}
	if err := r.BackupSQLite(backup); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", backup)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM observations`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("backup observation count = %d, want 1", count)
	}
}

func TestSQLitePersistenceReopenAndRetention(t *testing.T) {
	path := filepath.Join(t.TempDir(), "recorder.db")
	r, err := New(Options{Raw: true, RecentLimit: 2, SQLitePath: path, SQLiteRetention: 2})
	if err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= 3; i++ {
		meta := Meta{ConnectionID: string(rune('0' + i)), CapturePoint: "CLIENT_IN"}
		if i == 3 {
			meta.IdentitySource = "proxy_username"
			meta.IdentityValue = "iphone017"
			meta.Confidence = "exact"
		}
		if !r.TryCapture(meta, sample()) {
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
	if err := db.QueryRow(`SELECT COUNT(*) FROM recorder_schema_migrations WHERE version IN (1, 2)`).Scan(&migrations); err != nil {
		t.Fatal(err)
	}
	if migrations != 2 {
		t.Fatalf("migration rows = %d, want 2", migrations)
	}
	var identityValue string
	if err := db.QueryRow(`SELECT identity_value FROM observations WHERE identity_source = 'proxy_username'`).Scan(&identityValue); err != nil {
		t.Fatal(err)
	}
	if identityValue != "iphone017" {
		t.Fatalf("identity value = %q, want iphone017", identityValue)
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

func TestSQLiteMigratesV1SchemaToV2(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(`
CREATE TABLE recorder_schema_migrations (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL);
CREATE TABLE observations (
    id TEXT PRIMARY KEY,
    captured_at TEXT NOT NULL,
    processed_at TEXT NOT NULL,
    connection_id TEXT NOT NULL,
    capture_point TEXT NOT NULL,
    direction TEXT NOT NULL,
    byte_source TEXT NOT NULL,
    mode TEXT NOT NULL,
    destination TEXT NOT NULL,
    source TEXT NOT NULL,
    completeness TEXT NOT NULL,
    analysis_revision INTEGER NOT NULL,
    analysis_parent_id TEXT,
    payload BLOB NOT NULL
);
INSERT INTO recorder_schema_migrations(version, applied_at) VALUES (1, '2026-09-23T00:00:00Z');
`)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	store, err := openSQLiteStore(path, 10)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.close(); err != nil {
		t.Fatal(err)
	}
	db, err = sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var migrations int
	if err := db.QueryRow(`SELECT COUNT(*) FROM recorder_schema_migrations`).Scan(&migrations); err != nil {
		t.Fatal(err)
	}
	if migrations != 4 {
		t.Fatalf("migrations = %d, want 4", migrations)
	}
	var identityColumns int
	if err := db.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('observations') WHERE name IN ('identity_source', 'identity_value', 'confidence', 'resolved_device_id')`).Scan(&identityColumns); err != nil {
		t.Fatal(err)
	}
	if identityColumns != 4 {
		t.Fatalf("identity columns = %d, want 4", identityColumns)
	}
	var evidenceColumns int
	if err := db.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('observations') WHERE name IN ('destination_host', 'destination_ip', 'destination_port', 'error_stage')`).Scan(&evidenceColumns); err != nil {
		t.Fatal(err)
	}
	if evidenceColumns != 4 {
		t.Fatalf("evidence columns = %d, want 4", evidenceColumns)
	}
	var applicationColumns int
	if err := db.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('observations') WHERE name IN ('application', 'application_id', 'application_version')`).Scan(&applicationColumns); err != nil {
		t.Fatal(err)
	}
	if applicationColumns != 3 {
		t.Fatalf("application columns = %d, want 3", applicationColumns)
	}
}

func TestSQLiteHistoricalQueryUsesStableCursorAndFilters(t *testing.T) {
	path := filepath.Join(t.TempDir(), "history.db")
	r, err := New(Options{Raw: true, RecentLimit: 1, SQLitePath: path, SQLiteRetention: 10})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if !r.TryCapture(Meta{
			ConnectionID:       "history-" + string(rune('0'+i)),
			Application:        "Example",
			ApplicationID:      "example",
			ApplicationVersion: "1.2.0",
		}, sample()) {
			t.Fatal("enqueue")
		}
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	historical, err := New(Options{Raw: true, RecentLimit: 1, SQLitePath: path, SQLiteRetention: 10})
	if err != nil {
		t.Fatal(err)
	}
	defer historical.Close()

	page, err := historical.QueryStored(StoredQuery{Limit: 2, ApplicationID: "example", Search: "history-"})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Items) != 2 || page.NextCursor == "" {
		t.Fatalf("first historical page = %+v", page)
	}
	next, err := historical.QueryStored(StoredQuery{Limit: 2, ApplicationID: "example", Search: "history-", Cursor: page.NextCursor})
	if err != nil {
		t.Fatal(err)
	}
	if len(next.Items) != 1 || next.Items[0].ConnectionID == page.Items[0].ConnectionID || next.NextCursor != "" {
		t.Fatalf("second historical page = %+v", next)
	}
	stored, err := historical.Stored(page.Items[0].ID)
	if err != nil || stored.ID != page.Items[0].ID {
		t.Fatalf("stored observation = %+v, err=%v", stored, err)
	}
}
