package recorder

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

const (
	defaultSQLiteRetention = 100000
	maxSQLiteRetention     = 1000000
)

type sqliteStore struct {
	db        *sql.DB
	path      string
	retention int
	writeMu   sync.Mutex
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
	store := &sqliteStore{db: db, path: path, retention: retention}
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
	const version = 4
	var applied int
	if err := s.db.QueryRow(`SELECT COALESCE(MAX(version), 0) FROM recorder_schema_migrations`).Scan(&applied); err != nil {
		return fmt.Errorf("read recorder schema version: %w", err)
	}
	if applied > version {
		return fmt.Errorf("unsupported recorder schema version %d", applied)
	}
	if applied < 1 {
		if err := s.applyMigration(1, `
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
			return err
		}
		applied = 1
	}
	if applied < 2 {
		if err := s.applyMigration(2, `
ALTER TABLE observations ADD COLUMN identity_source TEXT;
ALTER TABLE observations ADD COLUMN identity_value TEXT;
ALTER TABLE observations ADD COLUMN confidence TEXT;
ALTER TABLE observations ADD COLUMN resolved_device_id TEXT;
CREATE INDEX IF NOT EXISTS idx_observations_identity
    ON observations(identity_source, identity_value);
`); err != nil {
			return err
		}
	}
	if applied < 3 {
		if err := s.applyMigration(3, `
ALTER TABLE observations ADD COLUMN destination_host TEXT;
ALTER TABLE observations ADD COLUMN destination_ip TEXT;
ALTER TABLE observations ADD COLUMN destination_port INTEGER;
ALTER TABLE observations ADD COLUMN error_stage TEXT;
CREATE INDEX IF NOT EXISTS idx_observations_destination
    ON observations(destination_host, destination_ip, destination_port);
`); err != nil {
			return err
		}
	}
	if applied < 4 {
		if err := s.applyMigration(4, `
ALTER TABLE observations ADD COLUMN application TEXT;
ALTER TABLE observations ADD COLUMN application_id TEXT;
ALTER TABLE observations ADD COLUMN application_version TEXT;
CREATE INDEX IF NOT EXISTS idx_observations_application
    ON observations(application_id, application_version);
`); err != nil {
			return err
		}
	}
	return nil
}

func (s *sqliteStore) applyMigration(version int, statements string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin recorder migration %d: %w", version, err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.Exec(statements); err != nil {
		return fmt.Errorf("apply recorder migration %d: %w", version, err)
	}
	if _, err := tx.Exec(`INSERT OR IGNORE INTO recorder_schema_migrations(version, applied_at) VALUES (?, ?)`, version, time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
		return fmt.Errorf("record recorder migration %d: %w", version, err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit recorder migration %d: %w", version, err)
	}
	return nil
}

func (s *sqliteStore) insert(o Observation, payload []byte) error {
	return s.insertBatch([]persistedObservation{{observation: o, payload: payload}})
}

func (s *sqliteStore) insertBatch(batch []persistedObservation) error {
	if len(batch) == 0 {
		return nil
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin recorder observation batch insert: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	statement, err := tx.Prepare(`
INSERT OR IGNORE INTO observations(
    id, captured_at, processed_at, connection_id, capture_point, direction,
    byte_source, mode, destination, destination_host, destination_ip, destination_port,
    source, completeness, error_stage, analysis_revision,
    analysis_parent_id, identity_source, identity_value, confidence,
    resolved_device_id, application, application_id, application_version, payload
)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return fmt.Errorf("prepare recorder observation batch insert: %w", err)
	}
	defer statement.Close()
	inserted := 0
	for _, item := range batch {
		o := item.observation
		result, err := statement.Exec(
			o.ID, o.CapturedAt.UTC().Format(time.RFC3339Nano), o.PersistedAt.UTC().Format(time.RFC3339Nano),
			o.ConnectionID, o.CapturePoint, o.Direction, o.ByteSource, o.Mode,
			o.Destination, o.DestinationHost, o.DestinationIP, o.DestinationPort,
			o.Source, o.Completeness, o.ErrorStage, o.AnalysisRevision, o.AnalysisParentID,
			o.IdentitySource, o.IdentityValue, o.Confidence, o.ResolvedDeviceID,
			o.Application, o.ApplicationID, o.ApplicationVersion, item.payload)
		if err != nil {
			return fmt.Errorf("insert recorder observation %s: %w", o.ID, err)
		}
		rows, err := result.RowsAffected()
		if err != nil {
			return fmt.Errorf("inspect recorder observation %s insert: %w", o.ID, err)
		}
		inserted += int(rows)
	}
	if inserted > 0 {
		var count int
		if err := tx.QueryRow(`SELECT COUNT(*) FROM observations`).Scan(&count); err != nil {
			return fmt.Errorf("count recorder observations: %w", err)
		}
		if excess := count - s.retention; excess > 0 {
			if _, err := tx.Exec(`DELETE FROM observations WHERE rowid IN (SELECT rowid FROM observations ORDER BY captured_at ASC, rowid ASC LIMIT ?)`, excess); err != nil {
				return fmt.Errorf("apply recorder retention: %w", err)
			}
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit recorder observation batch: %w", err)
	}
	return nil
}

func (s *sqliteStore) get(id string) (Observation, error) {
	var payload []byte
	err := s.db.QueryRow(`SELECT payload FROM observations WHERE id = ?`, id).Scan(&payload)
	if errors.Is(err, sql.ErrNoRows) {
		return Observation{}, ErrObservationNotFound
	}
	if err != nil {
		return Observation{}, fmt.Errorf("load stored observation: %w", err)
	}
	var observation Observation
	if err := json.Unmarshal(payload, &observation); err != nil {
		return Observation{}, fmt.Errorf("decode stored observation: %w", err)
	}
	return observation, nil
}

func (s *sqliteStore) query(query StoredQuery) (StoredPage, error) {
	limit := query.Limit
	if limit == 0 {
		limit = 50
	}
	if limit < 1 || limit > 100 {
		return StoredPage{}, errors.New("stored query limit must be 1..100")
	}

	where := []string{"1 = 1"}
	args := make([]any, 0, 16)
	addEqual := func(column, value string) {
		if value != "" {
			where = append(where, column+" = ?")
			args = append(args, value)
		}
	}
	addEqual("resolved_device_id", strings.TrimSpace(query.DeviceID))
	if query.AnalysisRevision > 0 {
		where = append(where, "analysis_revision = ?")
		args = append(args, query.AnalysisRevision)
	}
	addApplicationEqual := func(column, key, value string) {
		value = strings.TrimSpace(value)
		if value == "" {
			return
		}
		where = append(where, "(LOWER("+column+") = LOWER(?) OR LOWER(CAST(payload AS TEXT)) LIKE ?)")
		args = append(args, value, "%\""+key+"\":\""+strings.ToLower(value)+"\"%")
	}
	addApplicationEqual("application", "application", query.Application)
	addApplicationEqual("application_id", "application_id", query.ApplicationID)
	addApplicationEqual("application_version", "application_version", query.ApplicationVersion)
	if query.From != nil {
		where = append(where, "captured_at >= ?")
		args = append(args, query.From.UTC().Format(time.RFC3339Nano))
	}
	if query.To != nil {
		where = append(where, "captured_at < ?")
		args = append(args, query.To.UTC().Format(time.RFC3339Nano))
	}
	if search := strings.ToLower(strings.TrimSpace(query.Search)); search != "" {
		pattern := "%" + search + "%"
		where = append(where, "(LOWER(id) LIKE ? OR LOWER(connection_id) LIKE ? OR LOWER(destination) LIKE ? OR LOWER(destination_host) LIKE ? OR LOWER(source) LIKE ? OR LOWER(CAST(payload AS TEXT)) LIKE ?)")
		for i := 0; i < 6; i++ {
			args = append(args, pattern)
		}
	}
	if cursor := strings.TrimSpace(query.Cursor); cursor != "" {
		var capturedAt string
		var rowID int64
		if err := s.db.QueryRow(`SELECT captured_at, rowid FROM observations WHERE id = ?`, cursor).Scan(&capturedAt, &rowID); errors.Is(err, sql.ErrNoRows) {
			return StoredPage{}, ErrHistoricalCursor
		} else if err != nil {
			return StoredPage{}, fmt.Errorf("resolve stored cursor: %w", err)
		} else {
			where = append(where, "(captured_at < ? OR (captured_at = ? AND rowid < ?))")
			args = append(args, capturedAt, capturedAt, rowID)
		}
	}

	args = append(args, limit+1)
	rows, err := s.db.Query(`SELECT payload FROM observations WHERE `+strings.Join(where, " AND ")+` ORDER BY captured_at DESC, rowid DESC LIMIT ?`, args...)
	if err != nil {
		return StoredPage{}, fmt.Errorf("query stored observations: %w", err)
	}
	defer rows.Close()
	items := make([]Observation, 0, limit+1)
	for rows.Next() {
		var payload []byte
		if err := rows.Scan(&payload); err != nil {
			return StoredPage{}, fmt.Errorf("scan stored observation: %w", err)
		}
		var observation Observation
		if err := json.Unmarshal(payload, &observation); err != nil {
			return StoredPage{}, fmt.Errorf("decode stored observation: %w", err)
		}
		items = append(items, observation)
	}
	if err := rows.Err(); err != nil {
		return StoredPage{}, fmt.Errorf("iterate stored observations: %w", err)
	}
	page := StoredPage{Items: items}
	if len(items) > limit {
		page.Items = items[:limit]
		page.NextCursor = page.Items[len(page.Items)-1].ID
	}
	return page, nil
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

// backup creates a standalone consistent SQLite snapshot. VACUUM INTO avoids
// copying a live WAL file by hand and keeps the backup readable independently.
func (s *sqliteStore) backup(path string) error {
	if s == nil || s.db == nil {
		return ErrHistoricalUnavailable
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	path = strings.TrimSpace(path)
	if path == "" {
		return errors.New("sqlite backup path is empty")
	}
	if _, err := os.Stat(path); err == nil {
		return errors.New("sqlite backup target already exists")
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect sqlite backup target: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create sqlite backup directory: %w", err)
	}
	if _, err := s.db.Exec(`VACUUM INTO ?`, path); err != nil {
		return fmt.Errorf("create sqlite backup: %w", err)
	}
	if err := validateSQLiteBackup(path); err != nil {
		_ = os.Remove(path)
		return err
	}
	return nil
}

// restore imports observations from a validated standalone backup. Existing
// observation IDs are ignored, so retrying an import is idempotent. The live
// database file is never replaced while the recorder is running.
func (s *sqliteStore) restore(path string) (int, error) {
	if s == nil || s.db == nil {
		return 0, ErrHistoricalUnavailable
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	path = strings.TrimSpace(path)
	if path == "" {
		return 0, errors.New("sqlite restore path is empty")
	}
	sourcePath, err := filepath.Abs(path)
	if err != nil {
		return 0, fmt.Errorf("resolve sqlite restore path: %w", err)
	}
	targetPath, err := filepath.Abs(s.path)
	if err != nil {
		return 0, fmt.Errorf("resolve sqlite recorder path: %w", err)
	}
	if filepath.Clean(sourcePath) == filepath.Clean(targetPath) {
		return 0, errors.New("sqlite restore source must differ from active database")
	}
	if err := validateSQLiteBackup(path); err != nil {
		return 0, fmt.Errorf("validate sqlite restore: %w", err)
	}
	conn, err := s.db.Conn(context.Background())
	if err != nil {
		return 0, fmt.Errorf("acquire sqlite restore connection: %w", err)
	}
	defer conn.Close()
	if _, err := conn.ExecContext(context.Background(), `ATTACH DATABASE ? AS restore_source`, path); err != nil {
		return 0, fmt.Errorf("attach sqlite restore: %w", err)
	}
	detached := false
	defer func() {
		if !detached {
			_, _ = conn.ExecContext(context.Background(), `DETACH DATABASE restore_source`)
		}
	}()

	tx, err := conn.BeginTx(context.Background(), nil)
	if err != nil {
		return 0, fmt.Errorf("begin sqlite restore: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	result, err := tx.Exec(`
INSERT OR IGNORE INTO observations(
    id, captured_at, processed_at, connection_id, capture_point, direction,
    byte_source, mode, destination, destination_host, destination_ip, destination_port,
    source, completeness, error_stage, analysis_revision,
    analysis_parent_id, identity_source, identity_value, confidence,
    resolved_device_id, application, application_id, application_version, payload
)
SELECT
    id, captured_at, processed_at, connection_id, capture_point, direction,
    byte_source, mode, destination, destination_host, destination_ip, destination_port,
    source, completeness, error_stage, analysis_revision,
    analysis_parent_id, identity_source, identity_value, confidence,
    resolved_device_id, application, application_id, application_version, payload
FROM restore_source.observations`)
	if err != nil {
		return 0, fmt.Errorf("import sqlite observations: %w", err)
	}
	imported, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("count imported sqlite observations: %w", err)
	}
	var count int
	if err := tx.QueryRow(`SELECT COUNT(*) FROM observations`).Scan(&count); err != nil {
		return 0, fmt.Errorf("count restored observations: %w", err)
	}
	if excess := count - s.retention; excess > 0 {
		if _, err := tx.Exec(`DELETE FROM observations WHERE rowid IN (SELECT rowid FROM observations ORDER BY captured_at ASC, rowid ASC LIMIT ?)`, excess); err != nil {
			return 0, fmt.Errorf("apply restore retention: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("commit sqlite restore: %w", err)
	}
	if _, err := conn.ExecContext(context.Background(), `DETACH DATABASE restore_source`); err != nil {
		return 0, fmt.Errorf("detach sqlite restore: %w", err)
	}
	detached = true
	return int(imported), nil
}

func validateSQLiteBackup(path string) error {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return fmt.Errorf("open sqlite backup: %w", err)
	}
	defer db.Close()
	var result string
	if err := db.QueryRow(`PRAGMA integrity_check`).Scan(&result); err != nil {
		return fmt.Errorf("check sqlite backup integrity: %w", err)
	}
	if !strings.EqualFold(strings.TrimSpace(result), "ok") {
		return fmt.Errorf("sqlite backup integrity check failed: %s", result)
	}
	var applied int
	if err := db.QueryRow(`SELECT COALESCE(MAX(version), 0) FROM recorder_schema_migrations`).Scan(&applied); err != nil {
		return fmt.Errorf("read sqlite backup schema: %w", err)
	}
	if applied > 4 {
		return fmt.Errorf("unsupported sqlite recorder schema version %d", applied)
	}
	return nil
}
