// Package state persists control-plane snapshots in the application's SQLite database.
package state

import (
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

type SQLiteStore struct {
	db *sql.DB
}

type Document struct {
	SchemaVersion string
	Revision      uint64
	Payload       []byte
}

func OpenSQLite(path string) (*SQLiteStore, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, errors.New("sqlite state path is empty")
	}
	if path != ":memory:" && !strings.HasPrefix(path, "file:") {
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			return nil, fmt.Errorf("create sqlite state directory: %w", err)
		}
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open sqlite state database: %w", err)
	}
	db.SetMaxOpenConns(1)
	store := &SQLiteStore{db: db}
	if err := store.migrate(); err != nil {
		_ = db.Close()
		return nil, err
	}
	return store, nil
}

func (s *SQLiteStore) migrate() error {
	if _, err := s.db.Exec(`PRAGMA busy_timeout = 5000; PRAGMA foreign_keys = ON; PRAGMA synchronous = NORMAL;`); err != nil {
		return fmt.Errorf("configure sqlite state database: %w", err)
	}
	if _, err := s.db.Exec(`
CREATE TABLE IF NOT EXISTS control_state_schema_migrations (
    version INTEGER PRIMARY KEY,
    applied_at TEXT NOT NULL
);`); err != nil {
		return fmt.Errorf("create control state migration table: %w", err)
	}
	var version int
	if err := s.db.QueryRow(`SELECT COALESCE(MAX(version), 0) FROM control_state_schema_migrations`).Scan(&version); err != nil {
		return fmt.Errorf("read control state schema version: %w", err)
	}
	if version > 1 {
		return fmt.Errorf("unsupported control state schema version %d", version)
	}
	if version == 0 {
		tx, err := s.db.Begin()
		if err != nil {
			return fmt.Errorf("begin control state migration: %w", err)
		}
		defer func() { _ = tx.Rollback() }()
		if _, err := tx.Exec(`
CREATE TABLE control_state_documents (
    entity TEXT PRIMARY KEY,
    schema_version TEXT NOT NULL,
    revision INTEGER NOT NULL,
    payload BLOB NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE TABLE control_state_history (
    entity TEXT NOT NULL,
    revision INTEGER NOT NULL,
    payload BLOB NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY(entity, revision)
);
INSERT INTO control_state_schema_migrations(version, applied_at) VALUES (1, ?);`, time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
			return fmt.Errorf("apply control state migration 1: %w", err)
		}
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("commit control state migration: %w", err)
		}
	}
	return nil
}

func (s *SQLiteStore) Load(entity string) (Document, bool, error) {
	if s == nil || s.db == nil {
		return Document{}, false, errors.New("sqlite state store is unavailable")
	}
	var document Document
	err := s.db.QueryRow(`SELECT schema_version, revision, payload FROM control_state_documents WHERE entity = ?`, entity).
		Scan(&document.SchemaVersion, &document.Revision, &document.Payload)
	if errors.Is(err, sql.ErrNoRows) {
		return Document{}, false, nil
	}
	if err != nil {
		return Document{}, false, fmt.Errorf("load control state %q: %w", entity, err)
	}
	return document, true, nil
}

func (s *SQLiteStore) Save(entity, schemaVersion string, revision uint64, payload []byte) error {
	if s == nil || s.db == nil {
		return errors.New("sqlite state store is unavailable")
	}
	_, err := s.db.Exec(`
INSERT INTO control_state_documents(entity, schema_version, revision, payload, updated_at)
VALUES (?, ?, ?, ?, ?)
ON CONFLICT(entity) DO UPDATE SET
    schema_version = excluded.schema_version,
    revision = excluded.revision,
    payload = excluded.payload,
    updated_at = excluded.updated_at`,
		entity, schemaVersion, revision, payload, time.Now().UTC().Format(time.RFC3339Nano))
	if err != nil {
		return fmt.Errorf("save control state %q: %w", entity, err)
	}
	return nil
}

func (s *SQLiteStore) SaveSnapshot(entity, schemaVersion string, revision uint64, payload []byte) error {
	return s.SaveSnapshots(entity, schemaVersion, []Document{{SchemaVersion: schemaVersion, Revision: revision, Payload: payload}})
}

func (s *SQLiteStore) SaveSnapshots(entity, schemaVersion string, snapshots []Document) error {
	if s == nil || s.db == nil {
		return errors.New("sqlite state store is unavailable")
	}
	if len(snapshots) == 0 {
		return nil
	}
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin control state snapshot: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	for _, snapshot := range snapshots {
		now := time.Now().UTC().Format(time.RFC3339Nano)
		if _, err := tx.Exec(`INSERT OR IGNORE INTO control_state_history(entity, revision, payload, created_at) VALUES (?, ?, ?, ?)`, entity, snapshot.Revision, snapshot.Payload, now); err != nil {
			return fmt.Errorf("save control state history %q: %w", entity, err)
		}
	}
	latest := snapshots[len(snapshots)-1]
	if _, err := tx.Exec(`
INSERT INTO control_state_documents(entity, schema_version, revision, payload, updated_at)
VALUES (?, ?, ?, ?, ?)
ON CONFLICT(entity) DO UPDATE SET
    schema_version = excluded.schema_version,
    revision = excluded.revision,
    payload = excluded.payload,
    updated_at = excluded.updated_at`, entity, schemaVersion, latest.Revision, latest.Payload, time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
		return fmt.Errorf("save control state snapshot %q: %w", entity, err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit control state snapshot %q: %w", entity, err)
	}
	return nil
}

func (s *SQLiteStore) History(entity string) ([][]byte, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("sqlite state store is unavailable")
	}
	rows, err := s.db.Query(`SELECT payload FROM control_state_history WHERE entity = ? ORDER BY revision`, entity)
	if err != nil {
		return nil, fmt.Errorf("query control state history %q: %w", entity, err)
	}
	defer rows.Close()
	var history [][]byte
	for rows.Next() {
		var payload []byte
		if err := rows.Scan(&payload); err != nil {
			return nil, fmt.Errorf("scan control state history %q: %w", entity, err)
		}
		history = append(history, append([]byte(nil), payload...))
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate control state history %q: %w", entity, err)
	}
	return history, nil
}

func (s *SQLiteStore) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}
