// Package device provides the explicit, operator-maintained device mapping
// used to resolve recorder identity evidence.
package device

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const (
	SchemaVersion = "device-registry/1"
	maxFileBytes  = 4 << 20
)

var (
	ErrVersionConflict = errors.New("device registry version conflict")
	ErrDeviceNotFound  = errors.New("device not found")
	ErrPersistence     = errors.New("device registry persistence error")
)

type Device struct {
	ID            string   `json:"id"`
	Name          string   `json:"name"`
	Description   string   `json:"description,omitempty"`
	ProxyUsername string   `json:"proxy_username,omitempty"`
	SourceIPs     []string `json:"source_ips,omitempty"`
	Tags          []string `json:"tags,omitempty"`
	Platform      string   `json:"platform,omitempty"`
	AppName       string   `json:"app_name,omitempty"`
	AppVersion    string   `json:"app_version,omitempty"`
	OSName        string   `json:"os_name,omitempty"`
	OSVersion     string   `json:"os_version,omitempty"`
	Hardware      string   `json:"hardware,omitempty"`
	CreatedAt     string   `json:"created_at,omitempty"`
	LastSeenAt    string   `json:"last_seen_at,omitempty"`
	Enabled       bool     `json:"enabled"`
}

type Registry struct {
	SchemaVersion string   `json:"schema_version"`
	ConfigVersion uint64   `json:"config_version"`
	Devices       []Device `json:"devices"`
}

type Resolution struct {
	DeviceID  string
	Ambiguous bool
}

type Store struct {
	mu       sync.RWMutex
	registry Registry
	path     string
}

func Open(path string) (*Store, error) {
	store := &Store{path: path, registry: Registry{SchemaVersion: SchemaVersion, Devices: []Device{}}}
	if path == "" {
		return store, nil
	}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return store, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read device registry: %w", err)
	}
	if len(data) > maxFileBytes {
		return nil, errors.New("device registry exceeds 4 MiB")
	}
	var registry Registry
	if err := json.Unmarshal(data, &registry); err != nil {
		return nil, fmt.Errorf("decode device registry: %w", err)
	}
	if registry.SchemaVersion != SchemaVersion {
		return nil, fmt.Errorf("unsupported device registry schema %q", registry.SchemaVersion)
	}
	if err := validate(registry); err != nil {
		return nil, err
	}
	store.registry = cloneRegistry(registry)
	return store, nil
}

func (s *Store) Get(id string) (Device, bool) {
	if s == nil {
		return Device{}, false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, candidate := range s.registry.Devices {
		if candidate.ID == id {
			return cloneDevice(candidate), true
		}
	}
	return Device{}, false
}

func (s *Store) Create(candidate Device, expectedVersion uint64) (Device, Registry, error) {
	if s == nil {
		return Device{}, Registry{}, errors.New("device registry is unavailable")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.registry.ConfigVersion != expectedVersion {
		return Device{}, cloneRegistry(s.registry), ErrVersionConflict
	}
	if candidate.ID == "" {
		candidate.ID = newID()
	}
	if candidate.CreatedAt == "" {
		candidate.CreatedAt = time.Now().UTC().Format(time.RFC3339)
	}
	if err := validateDevice(candidate); err != nil {
		return Device{}, cloneRegistry(s.registry), err
	}
	for _, existing := range s.registry.Devices {
		if existing.ID == candidate.ID {
			return Device{}, cloneRegistry(s.registry), fmt.Errorf("duplicate device id %q", candidate.ID)
		}
	}
	next := cloneRegistry(s.registry)
	next.Devices = append(next.Devices, cloneDevice(candidate))
	next.ConfigVersion++
	if err := s.persist(next); err != nil {
		return Device{}, cloneRegistry(s.registry), fmt.Errorf("%w: %v", ErrPersistence, err)
	}
	s.registry = next
	return cloneDevice(candidate), cloneRegistry(next), nil
}

func (s *Store) Update(id string, candidate Device, expectedVersion uint64) (Device, Registry, error) {
	if s == nil {
		return Device{}, Registry{}, errors.New("device registry is unavailable")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.registry.ConfigVersion != expectedVersion {
		return Device{}, cloneRegistry(s.registry), ErrVersionConflict
	}
	next := cloneRegistry(s.registry)
	index := -1
	for i, existing := range next.Devices {
		if existing.ID == id {
			index = i
			if candidate.CreatedAt == "" {
				candidate.CreatedAt = existing.CreatedAt
			}
			if candidate.LastSeenAt == "" {
				candidate.LastSeenAt = existing.LastSeenAt
			}
			break
		}
	}
	if index < 0 {
		return Device{}, cloneRegistry(s.registry), ErrDeviceNotFound
	}
	candidate.ID = id
	if err := validateDevice(candidate); err != nil {
		return Device{}, cloneRegistry(s.registry), err
	}
	next.Devices[index] = cloneDevice(candidate)
	next.ConfigVersion++
	if err := s.persist(next); err != nil {
		return Device{}, cloneRegistry(s.registry), fmt.Errorf("%w: %v", ErrPersistence, err)
	}
	s.registry = next
	return cloneDevice(candidate), cloneRegistry(next), nil
}

func (s *Store) Delete(id string, expectedVersion uint64) (Registry, error) {
	if s == nil {
		return Registry{}, errors.New("device registry is unavailable")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.registry.ConfigVersion != expectedVersion {
		return cloneRegistry(s.registry), ErrVersionConflict
	}
	next := cloneRegistry(s.registry)
	index := -1
	for i, candidate := range next.Devices {
		if candidate.ID == id {
			index = i
			break
		}
	}
	if index < 0 {
		return cloneRegistry(s.registry), ErrDeviceNotFound
	}
	next.Devices = append(next.Devices[:index], next.Devices[index+1:]...)
	next.ConfigVersion++
	if err := s.persist(next); err != nil {
		return cloneRegistry(s.registry), fmt.Errorf("%w: %v", ErrPersistence, err)
	}
	s.registry = next
	return cloneRegistry(next), nil
}

func (s *Store) Snapshot() Registry {
	if s == nil {
		return Registry{SchemaVersion: SchemaVersion, Devices: []Device{}}
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return cloneRegistry(s.registry)
}

func (s *Store) Resolve(proxyUsername, sourceIP string) Resolution {
	if s == nil {
		return Resolution{}
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if proxyUsername != "" {
		matches := s.matchUsername(proxyUsername)
		if len(matches) == 1 {
			return Resolution{DeviceID: matches[0]}
		}
		if len(matches) > 1 {
			return Resolution{Ambiguous: true}
		}
	}
	if ip := net.ParseIP(sourceIP); ip != nil {
		matches := s.matchIP(ip.String())
		if len(matches) == 1 {
			return Resolution{DeviceID: matches[0]}
		}
		if len(matches) > 1 {
			return Resolution{Ambiguous: true}
		}
	}
	return Resolution{}
}

func (s *Store) matchUsername(username string) []string {
	var matches []string
	for _, candidate := range s.registry.Devices {
		if candidate.Enabled && candidate.ProxyUsername == username {
			matches = append(matches, candidate.ID)
		}
	}
	return matches
}

func (s *Store) matchIP(ip string) []string {
	var matches []string
	for _, candidate := range s.registry.Devices {
		if !candidate.Enabled {
			continue
		}
		for _, sourceIP := range candidate.SourceIPs {
			if sourceIP == ip {
				matches = append(matches, candidate.ID)
				break
			}
		}
	}
	return matches
}

func validate(registry Registry) error {
	seen := map[string]struct{}{}
	for _, candidate := range registry.Devices {
		if err := validateDevice(candidate); err != nil {
			return err
		}
		if _, exists := seen[candidate.ID]; exists {
			return fmt.Errorf("duplicate device id %q", candidate.ID)
		}
		seen[candidate.ID] = struct{}{}
	}
	return nil
}

func validateDevice(candidate Device) error {
	if candidate.ID == "" || candidate.Name == "" {
		return errors.New("device id and name are required")
	}
	for _, sourceIP := range candidate.SourceIPs {
		if net.ParseIP(sourceIP) == nil {
			return fmt.Errorf("device %q has invalid source IP %q", candidate.ID, sourceIP)
		}
	}
	return nil
}

func (s *Store) persist(registry Registry) error {
	if s.path == "" {
		return nil
	}
	data, err := json.MarshalIndent(registry, "", "  ")
	if err != nil {
		return fmt.Errorf("encode device registry: %w", err)
	}
	if dir := filepath.Dir(s.path); dir != "." {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return fmt.Errorf("create device registry directory: %w", err)
		}
	}
	if err := os.WriteFile(s.path, append(data, '\n'), 0600); err != nil {
		return fmt.Errorf("write device registry: %w", err)
	}
	return nil
}

func newID() string {
	var raw [8]byte
	if _, err := rand.Read(raw[:]); err == nil {
		return fmt.Sprintf("device-%x", raw[:])
	}
	return fmt.Sprintf("device-%d", time.Now().UnixNano())
}

func cloneRegistry(registry Registry) Registry {
	cloned := registry
	cloned.Devices = make([]Device, len(registry.Devices))
	for i, candidate := range registry.Devices {
		cloned.Devices[i] = cloneDevice(candidate)
	}
	return cloned
}

func cloneDevice(candidate Device) Device {
	candidate.SourceIPs = append([]string(nil), candidate.SourceIPs...)
	candidate.Tags = append([]string(nil), candidate.Tags...)
	return candidate
}
