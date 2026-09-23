package tlsprofile

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"
)

const maxLibraryLogBytes = 16 << 20

type Store struct {
	mu      sync.RWMutex
	path    string
	library Library
	history map[string][]Template
}

func Open(path string) (*Store, error) {
	store := &Store{path: path, library: Library{SchemaVersion: SchemaVersion, Templates: []Template{}}, history: map[string][]Template{}}
	if path == "" {
		return store, nil
	}
	file, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return store, nil
	}
	if err != nil {
		return nil, err
	}
	defer file.Close()
	if info, statErr := file.Stat(); statErr != nil || info.Size() > maxLibraryLogBytes {
		return nil, errors.New("журнал TLS-профилей превышает 16 МиБ или недоступен")
	}
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64<<10), 4<<20)
	var latest Library
	for scanner.Scan() {
		var candidate Library
		if err := json.Unmarshal(scanner.Bytes(), &candidate); err != nil {
			return nil, fmt.Errorf("повреждён журнал TLS-профилей: %w", err)
		}
		if candidate.SchemaVersion != SchemaVersion {
			return nil, fmt.Errorf("неподдерживаемая схема TLS-профилей %q", candidate.SchemaVersion)
		}
		for _, template := range candidate.Templates {
			store.recordHistoryLocked(template)
		}
		latest = candidate
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if latest.SchemaVersion != "" {
		store.library = latest
	}
	return store, nil
}

func (s *Store) History(id string) []Template {
	if s == nil {
		return []Template{}
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	data, _ := json.Marshal(s.history[id])
	var history []Template
	_ = json.Unmarshal(data, &history)
	if history == nil {
		return []Template{}
	}
	return history
}

func (s *Store) Snapshot() Library {
	if s == nil {
		return Library{SchemaVersion: SchemaVersion, Templates: []Template{}}
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	data, _ := json.Marshal(s.library)
	var out Library
	_ = json.Unmarshal(data, &out)
	return out
}

func (s *Store) Get(id string) (Template, bool) {
	library := s.Snapshot()
	for _, template := range library.Templates {
		if template.ID == id {
			return template, true
		}
	}
	return Template{}, false
}

func (s *Store) Resolve(host string) (Template, bool) {
	template, _, ok := s.ResolveWithVersion(host)
	return template, ok
}

func (s *Store) ResolveWithVersion(host string) (Template, uint64, bool) {
	library := s.Snapshot()
	activeIDs := library.ActiveIDs
	if len(activeIDs) == 0 && library.ActiveID != "" {
		activeIDs = []string{library.ActiveID}
	}
	if len(activeIDs) == 0 {
		return Template{}, library.ConfigVersion, false
	}
	var best Template
	bestScore := -1
	bestOrder := len(activeIDs)
	for order, activeID := range activeIDs {
		for _, template := range library.Templates {
			if template.ID != activeID || !template.Enabled || template.Replayability.Status == "UNSUPPORTED" {
				continue
			}
			score := templateHostScore(template, host)
			if score < 0 || score < bestScore || (score == bestScore && order >= bestOrder) {
				continue
			}
			best = template
			bestScore = score
			bestOrder = order
		}
	}
	if bestScore < 0 {
		return Template{}, library.ConfigVersion, false
	}
	return best, library.ConfigVersion, true
}

func templateHostScore(template Template, host string) int {
	best := -1
	for _, pattern := range template.HostPatterns {
		if !hostMatches(pattern, host) {
			continue
		}
		score := 1
		if strings.TrimSuffix(strings.ToLower(strings.TrimSpace(pattern)), ".") == strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".") {
			score = 2
		}
		if score > best {
			best = score
		}
	}
	if best >= 0 {
		return best
	}
	if len(template.HostPatterns) == 0 {
		return 0
	}
	return -1
}

func (s *Store) Create(template Template, expectedConfigVersion uint64) (Template, Library, error) {
	return s.mutate(expectedConfigVersion, func(library *Library) (Template, error) {
		if len(library.Templates) >= 100 {
			return Template{}, errors.New("достигнут лимит 100 TLS-профилей")
		}
		now := time.Now().UTC()
		id, err := newID()
		if err != nil {
			return Template{}, err
		}
		template.ID = id
		template.SchemaVersion = SchemaVersion
		template.Version = 1
		template.CreatedAt = now
		template.UpdatedAt = now
		preview, err := Preview(template)
		if err != nil {
			return Template{}, err
		}
		library.Templates = append(library.Templates, preview)
		return preview, nil
	})
}

func (s *Store) Update(id string, template Template, expectedConfigVersion uint64) (Template, Library, error) {
	return s.mutate(expectedConfigVersion, func(library *Library) (Template, error) {
		index := slices.IndexFunc(library.Templates, func(candidate Template) bool { return candidate.ID == id })
		if index < 0 {
			return Template{}, os.ErrNotExist
		}
		previous := library.Templates[index]
		template.ID = previous.ID
		template.SchemaVersion = SchemaVersion
		template.Version = previous.Version + 1
		template.BasedOnVersion = previous.Version
		template.CreatedAt = previous.CreatedAt
		template.UpdatedAt = time.Now().UTC()
		preview, err := Preview(template)
		if err != nil {
			return Template{}, err
		}
		library.Templates[index] = preview
		return preview, nil
	})
}

func (s *Store) Rollback(id string, targetVersion uint64, expectedConfigVersion uint64) (Template, Library, error) {
	return s.mutate(expectedConfigVersion, func(library *Library) (Template, error) {
		index := slices.IndexFunc(library.Templates, func(candidate Template) bool { return candidate.ID == id })
		if index < 0 {
			return Template{}, os.ErrNotExist
		}
		var target Template
		for _, version := range s.history[id] {
			if version.Version == targetVersion {
				target = version
				break
			}
		}
		if target.ID == "" {
			return Template{}, errors.New("запрошенная версия TLS-профиля не найдена")
		}
		previous := library.Templates[index]
		target.ID = previous.ID
		target.SchemaVersion = SchemaVersion
		target.Version = previous.Version + 1
		target.BasedOnVersion = targetVersion
		target.CreatedAt = previous.CreatedAt
		target.UpdatedAt = time.Now().UTC()
		preview, err := Preview(target)
		if err != nil {
			return Template{}, err
		}
		library.Templates[index] = preview
		return preview, nil
	})
}

func (s *Store) Delete(id string, expectedConfigVersion uint64) (Library, error) {
	_, library, err := s.mutate(expectedConfigVersion, func(library *Library) (Template, error) {
		if library.ActiveID == id || slices.Contains(library.ActiveIDs, id) {
			return Template{}, errors.New("сначала отключите активный TLS-профиль")
		}
		index := slices.IndexFunc(library.Templates, func(candidate Template) bool { return candidate.ID == id })
		if index < 0 {
			return Template{}, os.ErrNotExist
		}
		removed := library.Templates[index]
		library.Templates = append(library.Templates[:index], library.Templates[index+1:]...)
		return removed, nil
	})
	return library, err
}

func (s *Store) Activate(id string, expectedConfigVersion uint64) (Library, error) {
	_, library, err := s.mutate(expectedConfigVersion, func(library *Library) (Template, error) {
		if id == "" {
			library.ActiveID = ""
			library.ActiveIDs = nil
			return Template{}, nil
		}
		for _, template := range library.Templates {
			if template.ID == id {
				if !template.Enabled || template.Replayability.Status == "UNSUPPORTED" {
					return Template{}, errors.New("профиль выключен или невоспроизводим")
				}
				library.ActiveID = id
				library.ActiveIDs = nil
				return template, nil
			}
		}
		return Template{}, os.ErrNotExist
	})
	return library, err
}

func (s *Store) ActivateMany(ids []string, expectedConfigVersion uint64) (Library, error) {
	return s.mutateLibrary(expectedConfigVersion, func(library *Library) error {
		if len(ids) == 0 {
			library.ActiveID = ""
			library.ActiveIDs = nil
			return nil
		}
		seen := make(map[string]struct{}, len(ids))
		for _, id := range ids {
			if id == "" {
				return errors.New("TLS-профиль в active_ids не может быть пустым")
			}
			if _, exists := seen[id]; exists {
				return fmt.Errorf("TLS-профиль %q указан более одного раза", id)
			}
			seen[id] = struct{}{}
			found := false
			for _, template := range library.Templates {
				if template.ID == id {
					if !template.Enabled || template.Replayability.Status == "UNSUPPORTED" {
						return errors.New("профиль выключен или невоспроизводим")
					}
					found = true
					break
				}
			}
			if !found {
				return os.ErrNotExist
			}
		}
		library.ActiveID = ""
		library.ActiveIDs = append([]string(nil), ids...)
		if len(ids) == 1 {
			library.ActiveID = ids[0]
			library.ActiveIDs = nil
		}
		return nil
	})
}

func (s *Store) mutateLibrary(expectedVersion uint64, apply func(*Library) error) (Library, error) {
	if s == nil {
		return Library{}, errors.New("библиотека TLS-профилей недоступна")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if expectedVersion != s.library.ConfigVersion {
		return s.library, ErrVersionConflict
	}
	candidate := s.library
	candidate.Templates = append([]Template(nil), s.library.Templates...)
	candidate.ActiveIDs = append([]string(nil), s.library.ActiveIDs...)
	if err := apply(&candidate); err != nil {
		return s.library, err
	}
	candidate.SchemaVersion = SchemaVersion
	candidate.ConfigVersion++
	if err := s.append(candidate); err != nil {
		return s.library, err
	}
	s.library = candidate
	return s.library, nil
}

func (s *Store) mutate(expectedVersion uint64, apply func(*Library) (Template, error)) (Template, Library, error) {
	if s == nil {
		return Template{}, Library{}, errors.New("библиотека TLS-профилей недоступна")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if expectedVersion != s.library.ConfigVersion {
		return Template{}, s.library, ErrVersionConflict
	}
	candidate := s.library
	candidate.Templates = append([]Template(nil), s.library.Templates...)
	result, err := apply(&candidate)
	if err != nil {
		return Template{}, s.library, err
	}
	candidate.SchemaVersion = SchemaVersion
	candidate.ConfigVersion++
	if err := s.append(candidate); err != nil {
		return Template{}, s.library, err
	}
	s.library = candidate
	s.recordHistoryLocked(result)
	return result, s.library, nil
}

func (s *Store) recordHistoryLocked(template Template) {
	if template.ID == "" || template.Version == 0 {
		return
	}
	versions := s.history[template.ID]
	if slices.ContainsFunc(versions, func(candidate Template) bool { return candidate.Version == template.Version }) {
		return
	}
	s.history[template.ID] = append(versions, template)
}

func (s *Store) append(library Library) error {
	if s.path == "" {
		return nil
	}
	data, err := json.Marshal(library)
	if err != nil {
		return err
	}
	if len(data) > 4<<20 {
		return errors.New("snapshot TLS-профилей превышает 4 МиБ")
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0700); err != nil {
		return err
	}
	file, err := os.OpenFile(s.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer file.Close()
	if info, statErr := file.Stat(); statErr != nil || info.Size()+int64(len(data)+1) > maxLibraryLogBytes {
		return errors.New("журнал TLS-профилей достиг лимита 16 МиБ")
	}
	if _, err := file.Write(append(data, '\n')); err != nil {
		return err
	}
	return file.Sync()
}

func newID() (string, error) {
	var value [16]byte
	if _, err := io.ReadFull(rand.Reader, value[:]); err != nil {
		return "", fmt.Errorf("создание ID TLS-профиля: %w", err)
	}
	return strings.ToLower(hex.EncodeToString(value[:])), nil
}
