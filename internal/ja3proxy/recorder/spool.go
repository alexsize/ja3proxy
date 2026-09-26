package recorder

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/lylemi/ja3proxy/internal/ja3proxy/secrets"
)

const (
	spoolVersion       = 1
	defaultSpoolBytes  = 512 << 20
	maxSpoolBytes      = 4 << 30
	spoolFileExtension = ".evt"
	spoolKeyIDFile     = "key.id"
)

var errSpoolFull = errors.New("recorder spool quota exceeded")

var ErrSpoolPending = errors.New("recorder spool has pending records")
var ErrSpoolUnavailable = errors.New("recorder spool is unavailable")

type spoolStore struct {
	dir         string
	key         []byte
	maxBytes    int64
	mu          sync.Mutex
	bytes       int64
	quarantined uint64
}

type spoolEnvelope struct {
	Version    int    `json:"version"`
	Nonce      string `json:"nonce"`
	Ciphertext string `json:"ciphertext"`
	Checksum   string `json:"checksum"`
}

type spoolPayload struct {
	EventID string          `json:"event_id"`
	Payload json.RawMessage `json:"payload"`
}

func openSpool(dir, keyPath string, maxBytes int64) (*spoolStore, error) {
	return openSpoolWithProvider(dir, keyPath, maxBytes, nil)
}

func openSpoolWithProvider(dir, keyPath string, maxBytes int64, provider secrets.Provider) (*spoolStore, error) {
	dir = strings.TrimSpace(dir)
	keyPath = strings.TrimSpace(keyPath)
	if dir == "" || keyPath == "" {
		return nil, errors.New("spool directory and key file are required together")
	}
	if maxBytes == 0 {
		maxBytes = defaultSpoolBytes
	}
	if maxBytes < 1 || maxBytes > maxSpoolBytes {
		return nil, fmt.Errorf("spool max bytes must be between 1 and %d", maxSpoolBytes)
	}
	key, err := secrets.Read(provider, keyPath)
	if err != nil {
		return nil, fmt.Errorf("read recorder spool key: %w", err)
	}
	defer clear(key)
	if len(key) != 32 {
		return nil, errors.New("recorder spool key must contain exactly 32 raw bytes")
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("create recorder spool directory: %w", err)
	}
	store := &spoolStore{dir: dir, key: append([]byte(nil), key...), maxBytes: maxBytes}
	files, err := store.files()
	if err != nil {
		return nil, err
	}
	for _, path := range files {
		info, statErr := os.Stat(path)
		if statErr != nil {
			return nil, fmt.Errorf("stat recorder spool record: %w", statErr)
		}
		store.bytes += info.Size()
	}
	if store.bytes > store.maxBytes {
		return nil, errSpoolFull
	}
	if err := store.checkKeyID(files); err != nil {
		return nil, err
	}
	return store, nil
}

func (s *spoolStore) checkKeyID(files []string) error {
	marker := filepath.Join(s.dir, spoolKeyIDFile)
	digest := sha256.Sum256(s.key)
	want := hex.EncodeToString(digest[:])
	data, err := os.ReadFile(marker)
	if err == nil {
		if strings.TrimSpace(string(data)) == want {
			return nil
		}
		if len(files) != 0 {
			return errors.New("recorder spool key changed while pending records exist; restore the previous key before replay")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("read recorder spool key ID: %w", err)
	} else if len(files) != 0 {
		// Legacy spools have no marker. Verify that the supplied key decrypts at
		// least one record before binding this directory to that key.
		valid := false
		for _, path := range files {
			record, readErr := os.ReadFile(path)
			if readErr != nil {
				return fmt.Errorf("read legacy recorder spool record: %w", readErr)
			}
			if _, _, decodeErr := s.decode(record); decodeErr == nil {
				valid = true
				break
			}
		}
		if !valid {
			return errors.New("cannot verify recorder spool key for legacy pending records; records were left unchanged")
		}
	}
	return s.writeKeyID(marker, want)
}

func (s *spoolStore) writeKeyID(marker, keyID string) error {
	tmp, err := os.CreateTemp(s.dir, ".spool-key-id-*")
	if err != nil {
		return fmt.Errorf("create recorder spool key ID: %w", err)
	}
	defer func() {
		_ = tmp.Close()
		_ = os.Remove(tmp.Name())
	}()
	if err := tmp.Chmod(0600); err != nil {
		return err
	}
	if _, err := tmp.WriteString(keyID + "\n"); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), marker); err != nil {
		return fmt.Errorf("publish recorder spool key ID: %w", err)
	}
	return nil
}

func (s *spoolStore) rotateKey(keyPath string, provider secrets.Provider) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	files, err := s.files()
	if err != nil {
		return err
	}
	if len(files) != 0 {
		return ErrSpoolPending
	}
	key, err := secrets.Read(provider, keyPath)
	if err != nil {
		return fmt.Errorf("read recorder spool key: %w", err)
	}
	defer clear(key)
	if len(key) != 32 {
		return errors.New("recorder spool key must contain exactly 32 raw bytes")
	}
	previous := s.key
	s.key = append([]byte(nil), key...)
	if err := s.checkKeyID(files); err != nil {
		clear(s.key)
		s.key = previous
		return err
	}
	clear(previous)
	return nil
}

func (s *spoolStore) append(eventID string, payload []byte) error {
	if s == nil {
		return errors.New("recorder spool is unavailable")
	}
	if strings.TrimSpace(eventID) == "" {
		return errors.New("recorder spool event ID is empty")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	path := s.eventPath(eventID)
	if _, err := os.Stat(path); err == nil {
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			return fmt.Errorf("read existing recorder spool record: %w", readErr)
		}
		existingID, _, decodeErr := s.decode(data)
		if decodeErr == nil && existingID == eventID {
			return nil
		}
		if decodeErr == nil {
			return errors.New("recorder spool event ID does not match its file name")
		}
		if quarantineErr := s.quarantine(path); quarantineErr != nil {
			return fmt.Errorf("quarantine replaced recorder spool record: %w", quarantineErr)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("check recorder spool record: %w", err)
	}

	block, err := aes.NewCipher(s.key)
	if err != nil {
		return fmt.Errorf("create recorder spool cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("create recorder spool AEAD: %w", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return fmt.Errorf("generate recorder spool nonce: %w", err)
	}
	plain, err := json.Marshal(spoolPayload{EventID: eventID, Payload: append([]byte(nil), payload...)})
	if err != nil {
		return fmt.Errorf("encode recorder spool payload: %w", err)
	}
	ciphertext := gcm.Seal(nil, nonce, plain, []byte("ja3proxy-recorder-spool/1"))
	digest := sha256.Sum256(payload)
	envelope, err := json.Marshal(spoolEnvelope{
		Version: spoolVersion, Nonce: hex.EncodeToString(nonce),
		Ciphertext: hex.EncodeToString(ciphertext), Checksum: hex.EncodeToString(digest[:]),
	})
	if err != nil {
		return fmt.Errorf("encode recorder spool envelope: %w", err)
	}
	envelope = append(envelope, '\n')
	if s.bytes+int64(len(envelope)) > s.maxBytes {
		return errSpoolFull
	}
	tmp, err := os.CreateTemp(s.dir, ".recorder-spool-*")
	if err != nil {
		return fmt.Errorf("create recorder spool temporary record: %w", err)
	}
	tmpName := tmp.Name()
	defer func() {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
	}()
	if err := tmp.Chmod(0600); err != nil {
		return fmt.Errorf("protect recorder spool temporary record: %w", err)
	}
	if _, err := tmp.Write(envelope); err != nil {
		return fmt.Errorf("write recorder spool record: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		return fmt.Errorf("sync recorder spool record: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close recorder spool record: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("publish recorder spool record: %w", err)
	}
	s.bytes += int64(len(envelope))
	return nil
}

func (s *spoolStore) replay(consume func(eventID string, payload []byte) error) error {
	if s == nil || consume == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	files, err := s.files()
	if err != nil {
		return err
	}
	sort.Strings(files)
	for _, path := range files {
		data, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read recorder spool record: %w", err)
		}
		recordSize := int64(len(data))
		eventID, payload, err := s.decode(data)
		if err != nil {
			if quarantineErr := s.quarantine(path); quarantineErr != nil {
				return fmt.Errorf("quarantine corrupt recorder spool record: %w", quarantineErr)
			}
			continue
		}
		if err := consume(eventID, payload); err != nil {
			continue
		}
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("remove replayed recorder spool record: %w", err)
		}
		s.bytes -= recordSize
		if s.bytes < 0 {
			s.bytes = 0
		}
	}
	return nil
}

func (s *spoolStore) decode(data []byte) (string, []byte, error) {
	var envelope spoolEnvelope
	if err := json.Unmarshal(data, &envelope); err != nil || envelope.Version != spoolVersion {
		return "", nil, errors.New("invalid recorder spool envelope")
	}
	nonce, err := hex.DecodeString(envelope.Nonce)
	if err != nil {
		return "", nil, errors.New("invalid recorder spool nonce")
	}
	ciphertext, err := hex.DecodeString(envelope.Ciphertext)
	if err != nil {
		return "", nil, errors.New("invalid recorder spool ciphertext")
	}
	block, err := aes.NewCipher(s.key)
	if err != nil {
		return "", nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil || len(nonce) != gcm.NonceSize() {
		return "", nil, errors.New("invalid recorder spool nonce size")
	}
	plain, err := gcm.Open(nil, nonce, ciphertext, []byte("ja3proxy-recorder-spool/1"))
	if err != nil {
		return "", nil, errors.New("recorder spool authentication failed")
	}
	var record spoolPayload
	if err := json.Unmarshal(plain, &record); err != nil || record.EventID == "" {
		return "", nil, errors.New("invalid recorder spool payload")
	}
	digest := sha256.Sum256(record.Payload)
	if !strings.EqualFold(envelope.Checksum, hex.EncodeToString(digest[:])) {
		return "", nil, errors.New("recorder spool checksum mismatch")
	}
	return record.EventID, append([]byte(nil), record.Payload...), nil
}

func (s *spoolStore) quarantine(path string) error {
	dir := filepath.Join(s.dir, "quarantine")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	name := filepath.Base(path) + "." + time.Now().UTC().Format("20060102T150405.000000000Z") + ".bad"
	if err := os.Rename(path, filepath.Join(dir, name)); err != nil {
		return err
	}
	if info, err := os.Stat(filepath.Join(dir, name)); err == nil {
		s.bytes -= info.Size()
	}
	s.quarantined++
	return nil
}

func (s *spoolStore) files() ([]string, error) {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return nil, fmt.Errorf("list recorder spool: %w", err)
	}
	files := make([]string, 0, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), spoolFileExtension) {
			files = append(files, filepath.Join(s.dir, entry.Name()))
		}
	}
	return files, nil
}

func (s *spoolStore) eventPath(eventID string) string {
	digest := sha256.Sum256([]byte(eventID))
	return filepath.Join(s.dir, hex.EncodeToString(digest[:])+spoolFileExtension)
}

func (s *spoolStore) stats() (int64, int, uint64) {
	if s == nil {
		return 0, 0, 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	files, err := s.files()
	if err != nil {
		return s.bytes, 0, s.quarantined
	}
	return s.bytes, len(files), s.quarantined
}
