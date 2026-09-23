package recorder

import (
	"database/sql"
	"errors"
	"fmt"
	"time"

	_ "modernc.org/sqlite"
)

const (
	defaultSQLiteRetention = 100000
	maxSQLiteRetention     = 1000000
)

type sqliteStore struct {
	db        *sql.DB
	retention int
}

func openSQLiteStore(path string, retention int) (*sqliteStore, error) {
	if path == "" {
		return nil, errors.New("sqlite path is empty")
	}
	if retention == 0 {
		retention = defaultSQLiteRetention
	}
	if retention < 1 || retention > maxSQLiteRetention {
		return nil, errors.New("invalid sqlite retention")
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open sqlite recorder database: %w", err)
	}
	store := &sqliteStore{db: db, retention: retention}
	if err := store.migrate(); err != nil {
		_ = db.Close()
		return nil, err
	}
	return store, nil
}

func (s *sqliteStore) migrate() error {
	if _, err := s.db.Exec(`PRAGMA busy_timeout = 5000; PRAGMA foreign_keys = ON; PRAGMA synchronous = NORMAL;`); err != nil {
		return fmt.Errorf("configure sqlite recorder database: %w", err)
	}
	if _, err := s.db.Exec(`
CREATE TABLE IF NOT EXISTS recorder_schema_migrations (
    version INTEGER PRIMARY KEY,
    applied_at TEXT NOT NULL
);`); err != nil {
		return fmt.Errorf("create recorder migration table: %w", err)
	}
	const version = 1
	var applied int
	if err := s.db.QueryRow(`SELECT COALESCE(MAX(version), 0) FROM recorder_schema_migrations`).Scan(&applied); err != nil {
		return fmt.Errorf("read recorder schema version: %w", err)
	}
	if applied > version {
		return fmt.Errorf("unsupported recorder schema version %d", applied)
	}
	if applied >= version {
		return nil
	}
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin recorder migration: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.Exec(`
CREATE TABLE IF NOT EXISTS observations (
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
CREATE INDEX IF NOT EXISTS idx_observations_captured_at
    ON observations(captured_at);
CREATE INDEX IF NOT EXISTS idx_observations_connection_id
    ON observations(connection_id);
CREATE INDEX IF NOT EXISTS idx_observations_capture_point
    ON observations(capture_point);
`); err != nil {
		return fmt.Errorf("create recorder observation schema: %w", err)
	}
	if _, err := tx.Exec(`INSERT OR IGNORE INTO recorder_schema_migrations(version, applied_at) VALUES (?, ?)`, version, time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
		return fmt.Errorf("record recorder migration: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit recorder migration: %w", err)
	}
	return nil
}

func (s *sqliteStore) insert(o Observation, payload []byte) error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin recorder observation insert: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	_, err = tx.Exec(`
INSERT INTO observations(
    id, captured_at, processed_at, connection_id, capture_point, direction,
    byte_source, mode, destination, source, completeness, analysis_revision,
    analysis_parent_id, payload
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		o.ID, o.CapturedAt.UTC().Format(time.RFC3339Nano), o.PersistedAt.UTC().Format(time.RFC3339Nano),
		o.ConnectionID, o.CapturePoint, o.Direction, o.ByteSource, o.Mode,
		o.Destination, o.Source, o.Completeness, o.AnalysisRevision, o.AnalysisParentID, payload)
	if err != nil {
		return fmt.Errorf("insert recorder observation: %w", err)
	}
	var count int
	if err := tx.QueryRow(`SELECT COUNT(*) FROM observations`).Scan(&count); err != nil {
		return fmt.Errorf("count recorder observations: %w", err)
	}
	if excess := count - s.retention; excess > 0 {
		if _, err := tx.Exec(`DELETE FROM observations WHERE rowid IN (SELECT rowid FROM observations ORDER BY captured_at ASC, rowid ASC LIMIT ?)`, excess); err != nil {
			return fmt.Errorf("apply recorder retention: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit recorder observation: %w", err)
	}
	return nil
}

func (s *sqliteStore) recent(limit int) ([][]byte, error) {
	rows, err := s.db.Query(`SELECT payload FROM observations ORDER BY captured_at DESC, rowid DESC LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("load recorder observations: %w", err)
	}
	defer rows.Close()
	var newestFirst [][]byte
	for rows.Next() {
		var payload []byte
		if err := rows.Scan(&payload); err != nil {
			return nil, fmt.Errorf("scan recorder observation: %w", err)
		}
		newestFirst = append(newestFirst, append([]byte(nil), payload...))
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate recorder observations: %w", err)
	}
	for left, right := 0, len(newestFirst)-1; left < right; left, right = left+1, right-1 {
		newestFirst[left], newestFirst[right] = newestFirst[right], newestFirst[left]
	}
	return newestFirst, nil
}

func (s *sqliteStore) close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}
