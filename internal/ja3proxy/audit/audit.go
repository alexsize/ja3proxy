// Package audit stores append-only control-plane audit events.
package audit

import (
	"bufio"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

const (
	SchemaVersion = "audit-event/1"
	maxFileBytes  = 16 << 20
	defaultMemory = 10000
	sqliteDriver  = "sqlite"
)

var (
	ErrCursorNotFound = errors.New("audit cursor not found")
	ErrClosed         = errors.New("audit store is closed")
)

type Event struct {
	SchemaVersion string          `json:"schema_version"`
	ID            string          `json:"id"`
	Timestamp     time.Time       `json:"timestamp"`
	Actor         string          `json:"actor"`
	Action        string          `json:"action"`
	Object        string          `json:"object"`
	OldValue      json.RawMessage `json:"old_value,omitempty"`
	NewValue      json.RawMessage `json:"new_value,omitempty"`
	SourceIP      string          `json:"source_ip,omitempty"`
	Result        string          `json:"result"`
	PrevHash      string          `json:"prev_hash,omitempty"`
	Hash          string          `json:"hash,omitempty"`
}

type Page struct {
	Items      []Event `json:"items"`
	NextCursor string  `json:"next_cursor,omitempty"`
}

type Store struct {
	mu       sync.RWMutex
	file     *os.File
	db       *sql.DB
	path     string
	limit    int
	events   []Event
	lastHash string
	closed   bool
}

// OpenSQLite opens the durable SQLite audit backend. The audit chain is
// validated from oldest to newest before the store becomes available.
func OpenSQLite(path string) (*Store, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, errors.New("sqlite audit path is empty")
	}
	db, err := sql.Open(sqliteDriver, path)
	if err != nil {
		return nil, fmt.Errorf("open sqlite audit database: %w", err)
	}
	store := &Store{db: db, path: path, limit: defaultMemory, events: make([]Event, 0)}
	if err := store.configureSQLite(); err != nil {
		_ = db.Close()
		return nil, err
	}
	if err := store.migrateSQLite(); err != nil {
		_ = db.Close()
		return nil, err
	}
	if err := store.loadSQLite(); err != nil {
		_ = db.Close()
		return nil, err
	}
	return store, nil
}

// OpenSQLiteWithLegacy imports a legacy JSONL audit file once, atomically, when
// the SQLite audit table is empty. After import, SQLite is authoritative.
func OpenSQLiteWithLegacy(databasePath, legacyPath string) (*Store, error) {
	store, err := OpenSQLite(databasePath)
	if err != nil {
		return nil, err
	}
	legacyPath = strings.TrimSpace(legacyPath)
	if legacyPath == "" {
		return store, nil
	}
	var existing int
	if err := store.db.QueryRow(`SELECT COUNT(*) FROM audit_events`).Scan(&existing); err != nil {
		_ = store.Close()
		return nil, fmt.Errorf("check SQLite audit import state: %w", err)
	}
	if existing > 0 {
		return store, nil
	}
	if _, err := os.Stat(legacyPath); errors.Is(err, os.ErrNotExist) {
		return store, nil
	} else if err != nil {
		_ = store.Close()
		return nil, fmt.Errorf("inspect legacy audit log: %w", err)
	}
	legacy, err := Open(legacyPath)
	if err != nil {
		_ = store.Close()
		return nil, fmt.Errorf("open legacy audit log for SQLite import: %w", err)
	}
	defer legacy.Close()
	if len(legacy.events) == 0 {
		return store, nil
	}
	tx, err := store.db.Begin()
	if err != nil {
		_ = store.Close()
		return nil, fmt.Errorf("begin legacy audit import: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	imported := make([]Event, 0, len(legacy.events))
	previousHash := ""
	for _, old := range legacy.events {
		event := prepareEvent(old, previousHash)
		if _, err := tx.Exec(`INSERT INTO audit_events (schema_version, id, timestamp, actor, action, object, old_value, new_value, source_ip, result, prev_hash, hash) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			event.SchemaVersion, event.ID, event.Timestamp.Format(time.RFC3339Nano), event.Actor, event.Action, event.Object, nullableJSON(event.OldValue), nullableJSON(event.NewValue), event.SourceIP, event.Result, event.PrevHash, event.Hash); err != nil {
			_ = tx.Rollback()
			_ = store.Close()
			return nil, fmt.Errorf("import legacy audit event %q: %w", event.ID, err)
		}
		imported = append(imported, event)
		previousHash = event.Hash
	}
	if err := tx.Commit(); err != nil {
		_ = store.Close()
		return nil, fmt.Errorf("commit legacy audit import: %w", err)
	}
	store.events = imported
	if len(imported) > store.limit {
		store.events = append([]Event(nil), imported[len(imported)-store.limit:]...)
	}
	store.lastHash = previousHash
	return store, nil
}

func (s *Store) configureSQLite() error {
	for _, statement := range []string{
		`PRAGMA busy_timeout = 5000`,
		`PRAGMA journal_mode = WAL`,
		`PRAGMA synchronous = FULL`,
	} {
		if _, err := s.db.Exec(statement); err != nil {
			return fmt.Errorf("configure sqlite audit database: %w", err)
		}
	}
	return nil
}

func (s *Store) migrateSQLite() error {
	const schema = `
CREATE TABLE IF NOT EXISTS audit_events (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    schema_version TEXT NOT NULL,
    id TEXT NOT NULL UNIQUE,
    timestamp TEXT NOT NULL,
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    object TEXT NOT NULL,
    old_value BLOB,
    new_value BLOB,
    source_ip TEXT NOT NULL,
    result TEXT NOT NULL,
    prev_hash TEXT NOT NULL,
    hash TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_events_id ON audit_events(id);
CREATE INDEX IF NOT EXISTS idx_audit_events_timestamp ON audit_events(timestamp DESC, seq DESC);
`
	if _, err := s.db.Exec(schema); err != nil {
		return fmt.Errorf("migrate sqlite audit database: %w", err)
	}
	return nil
}

func (s *Store) loadSQLite() error {
	rows, err := s.db.Query(`SELECT schema_version, id, timestamp, actor, action, object, old_value, new_value, source_ip, result, prev_hash, hash FROM audit_events ORDER BY seq ASC`)
	if err != nil {
		return fmt.Errorf("read sqlite audit database: %w", err)
	}
	defer rows.Close()
	previousHash := ""
	for rows.Next() {
		event, err := scanEvent(rows)
		if err != nil {
			return fmt.Errorf("decode sqlite audit event: %w", err)
		}
		if err := validateEvent(event); err != nil {
			return err
		}
		if event.Hash == "" || event.PrevHash != previousHash || event.Hash != hashEvent(event) {
			return errors.New("sqlite audit log integrity check failed")
		}
		previousHash = event.Hash
		s.events = append(s.events, event)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("read sqlite audit database: %w", err)
	}
	if len(s.events) > s.limit {
		s.events = append([]Event(nil), s.events[len(s.events)-s.limit:]...)
	}
	s.lastHash = previousHash
	return nil
}

func Open(path string) (*Store, error) {
	store := &Store{path: strings.TrimSpace(path), limit: defaultMemory, events: make([]Event, 0)}
	if store.path == "" {
		return store, nil
	}
	file, err := os.OpenFile(store.path, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open audit log: %w", err)
	}
	if info, statErr := file.Stat(); statErr != nil || info.Size() > maxFileBytes {
		_ = file.Close()
		return nil, errors.New("audit log exceeds 16 MiB or is unavailable")
	}
	store.file = file
	if err := store.load(file); err != nil {
		_ = file.Close()
		return nil, err
	}
	return store, nil
}

func (s *Store) load(file *os.File) error {
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("seek audit log: %w", err)
	}
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64<<10), 1<<20)
	previousHash := ""
	for scanner.Scan() {
		var event Event
		if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
			return fmt.Errorf("decode audit log: %w", err)
		}
		if err := validateEvent(event); err != nil {
			return fmt.Errorf("audit log contains an unsupported event: %w", err)
		}
		if event.Hash == "" {
			if event.PrevHash != "" {
				return errors.New("audit log contains an invalid integrity link")
			}
			// Events written before the integrity chain was introduced remain
			// readable. Their calculated digest anchors the first new event.
			previousHash = hashEvent(event)
		} else {
			if event.PrevHash != previousHash || event.Hash != hashEvent(event) {
				return errors.New("audit log integrity check failed")
			}
			previousHash = event.Hash
		}
		s.events = append(s.events, event)
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("read audit log: %w", err)
	}
	if len(s.events) > s.limit {
		s.events = append([]Event(nil), s.events[len(s.events)-s.limit:]...)
	}
	if _, err := file.Seek(0, io.SeekEnd); err != nil {
		return fmt.Errorf("seek audit log end: %w", err)
	}
	s.lastHash = previousHash
	return nil
}

func (s *Store) Append(event Event) error {
	if s == nil {
		return ErrClosed
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrClosed
	}
	event = prepareEvent(event, s.lastHash)
	data, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("encode audit event: %w", err)
	}
	data = append(data, '\n')
	if s.db != nil {
		if err := s.appendSQLiteLocked(event); err != nil {
			return err
		}
	} else if s.file != nil {
		info, statErr := s.file.Stat()
		if statErr != nil {
			return fmt.Errorf("stat audit log: %w", statErr)
		}
		if info.Size()+int64(len(data)) > maxFileBytes {
			return errors.New("audit log size limit reached")
		}
		if _, err := s.file.Write(data); err != nil {
			return fmt.Errorf("write audit log: %w", err)
		}
		if err := s.file.Sync(); err != nil {
			return fmt.Errorf("sync audit log: %w", err)
		}
	}
	s.events = append(s.events, event)
	s.lastHash = event.Hash
	if len(s.events) > s.limit {
		s.events = append([]Event(nil), s.events[len(s.events)-s.limit:]...)
	}
	return nil
}

func (s *Store) Query(limit int, cursor string) (Page, error) {
	if s == nil {
		return Page{}, ErrClosed
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		return Page{}, ErrClosed
	}
	if limit == 0 {
		limit = 50
	}
	if limit < 1 || limit > 100 {
		return Page{}, errors.New("audit query limit must be 1..100")
	}
	if s.db != nil {
		return s.querySQLiteLocked(limit, cursor)
	}
	end := len(s.events)
	if cursor != "" {
		end = -1
		for index := len(s.events) - 1; index >= 0; index-- {
			if s.events[index].ID == cursor {
				end = index
				break
			}
		}
		if end < 0 {
			return Page{}, ErrCursorNotFound
		}
	}
	items := make([]Event, 0, limit+1)
	for index := end - 1; index >= 0 && len(items) <= limit; index-- {
		items = append(items, cloneEvent(s.events[index]))
	}
	page := Page{Items: items}
	if len(items) > limit {
		page.Items = items[:limit]
		page.NextCursor = page.Items[len(page.Items)-1].ID
	}
	return page, nil
}

func (s *Store) Close() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	if s.db != nil {
		return s.db.Close()
	}
	if s.file == nil {
		return nil
	}
	if err := s.file.Sync(); err != nil {
		_ = s.file.Close()
		return err
	}
	return s.file.Close()
}

func prepareEvent(event Event, previousHash string) Event {
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now().UTC()
	} else {
		event.Timestamp = event.Timestamp.UTC()
	}
	if event.ID == "" {
		event.ID = newID(event.Timestamp)
	}
	event.SchemaVersion = SchemaVersion
	event.Actor = bounded(strings.TrimSpace(event.Actor), 128)
	event.Action = bounded(strings.TrimSpace(event.Action), 128)
	event.Object = bounded(strings.TrimSpace(event.Object), 512)
	event.SourceIP = bounded(strings.TrimSpace(event.SourceIP), 128)
	event.Result = bounded(strings.TrimSpace(event.Result), 32)
	event.OldValue = sanitizeRaw(event.OldValue)
	event.NewValue = sanitizeRaw(event.NewValue)
	event.PrevHash = previousHash
	event.Hash = hashEvent(event)
	return event
}

func validateEvent(event Event) error {
	if event.SchemaVersion != SchemaVersion || event.ID == "" || event.Timestamp.IsZero() {
		return errors.New("audit event has unsupported schema or missing identity")
	}
	return nil
}

func (s *Store) appendSQLiteLocked(event Event) error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin sqlite audit transaction: %w", err)
	}
	_, err = tx.Exec(`INSERT INTO audit_events (schema_version, id, timestamp, actor, action, object, old_value, new_value, source_ip, result, prev_hash, hash) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		event.SchemaVersion, event.ID, event.Timestamp.Format(time.RFC3339Nano), event.Actor, event.Action, event.Object, nullableJSON(event.OldValue), nullableJSON(event.NewValue), event.SourceIP, event.Result, event.PrevHash, event.Hash)
	if err != nil {
		_ = tx.Rollback()
		return fmt.Errorf("write sqlite audit event: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit sqlite audit event: %w", err)
	}
	return nil
}

func nullableJSON(value json.RawMessage) any {
	if len(value) == 0 {
		return nil
	}
	return []byte(value)
}

func (s *Store) querySQLiteLocked(limit int, cursor string) (Page, error) {
	args := []any{}
	where := ""
	if cursor != "" {
		var seq int64
		if err := s.db.QueryRow(`SELECT seq FROM audit_events WHERE id = ?`, cursor).Scan(&seq); errors.Is(err, sql.ErrNoRows) {
			return Page{}, ErrCursorNotFound
		} else if err != nil {
			return Page{}, fmt.Errorf("find sqlite audit cursor: %w", err)
		} else {
			where = "WHERE seq < ?"
			args = append(args, seq)
		}
	}
	args = append(args, limit+1)
	rows, err := s.db.Query(`SELECT schema_version, id, timestamp, actor, action, object, old_value, new_value, source_ip, result, prev_hash, hash FROM audit_events `+where+` ORDER BY seq DESC LIMIT ?`, args...)
	if err != nil {
		return Page{}, fmt.Errorf("query sqlite audit events: %w", err)
	}
	defer rows.Close()
	items := make([]Event, 0, limit+1)
	for rows.Next() {
		event, err := scanEvent(rows)
		if err != nil {
			return Page{}, fmt.Errorf("decode sqlite audit event: %w", err)
		}
		items = append(items, event)
	}
	if err := rows.Err(); err != nil {
		return Page{}, fmt.Errorf("read sqlite audit events: %w", err)
	}
	page := Page{Items: items}
	if len(items) > limit {
		page.Items = items[:limit]
		page.NextCursor = page.Items[len(page.Items)-1].ID
	}
	return page, nil
}

type eventScanner interface {
	Scan(dest ...any) error
}

func scanEvent(scanner eventScanner) (Event, error) {
	var event Event
	var timestamp string
	var oldValue, newValue []byte
	if err := scanner.Scan(&event.SchemaVersion, &event.ID, &timestamp, &event.Actor, &event.Action, &event.Object, &oldValue, &newValue, &event.SourceIP, &event.Result, &event.PrevHash, &event.Hash); err != nil {
		return Event{}, err
	}
	parsed, err := time.Parse(time.RFC3339Nano, timestamp)
	if err != nil {
		return Event{}, err
	}
	event.Timestamp = parsed.UTC()
	event.OldValue = json.RawMessage(append([]byte(nil), oldValue...))
	event.NewValue = json.RawMessage(append([]byte(nil), newValue...))
	return event, nil
}

func newID(timestamp time.Time) string {
	var random [8]byte
	if _, err := rand.Read(random[:]); err != nil {
		return fmt.Sprintf("%d", timestamp.UnixNano())
	}
	return fmt.Sprintf("%d-%s", timestamp.UnixNano(), hex.EncodeToString(random[:]))
}

func bounded(value string, max int) string {
	if len(value) <= max {
		return value
	}
	return value[:max]
}

func cloneEvent(event Event) Event {
	event.OldValue = append(json.RawMessage(nil), event.OldValue...)
	event.NewValue = append(json.RawMessage(nil), event.NewValue...)
	return event
}

func hashEvent(event Event) string {
	event.Hash = ""
	data, _ := json.Marshal(event)
	digest := sha256.Sum256(append([]byte("ja3proxy-audit-event/1\x00"), data...))
	return hex.EncodeToString(digest[:])
}

func sanitizeRaw(raw json.RawMessage) json.RawMessage {
	if len(raw) == 0 {
		return nil
	}
	var value any
	if json.Unmarshal(raw, &value) != nil {
		return nil
	}
	data, err := json.Marshal(sanitizeValue(value))
	if err != nil {
		return nil
	}
	return data
}

func sanitizeValue(value any) any {
	switch typed := value.(type) {
	case map[string]any:
		result := make(map[string]any, len(typed))
		for key, item := range typed {
			if sensitiveKey(key) {
				result[key] = "[REDACTED]"
				continue
			}
			result[key] = sanitizeValue(item)
		}
		return result
	case []any:
		result := make([]any, len(typed))
		for index, item := range typed {
			result[index] = sanitizeValue(item)
		}
		return result
	default:
		return value
	}
}

func sensitiveKey(key string) bool {
	lower := strings.ToLower(strings.ReplaceAll(key, "-", "_"))
	for _, marker := range []string{"password", "passwd", "token", "secret", "authorization", "proxy_authorization", "private_key", "raw", "ticket", "binder"} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}
