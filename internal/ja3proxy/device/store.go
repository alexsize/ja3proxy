// Package device provides the explicit, operator-maintained device mapping
// used to resolve recorder identity evidence.
package device

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"sync"
)

const (
	SchemaVersion = "device-registry/1"
	maxFileBytes  = 4 << 20
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
}

func Open(path string) (*Store, error) {
	store := &Store{registry: Registry{SchemaVersion: SchemaVersion, Devices: []Device{}}}
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
		if candidate.ID == "" || candidate.Name == "" {
			return errors.New("device id and name are required")
		}
		if _, exists := seen[candidate.ID]; exists {
			return fmt.Errorf("duplicate device id %q", candidate.ID)
		}
		seen[candidate.ID] = struct{}{}
		for _, sourceIP := range candidate.SourceIPs {
			if net.ParseIP(sourceIP) == nil {
				return fmt.Errorf("device %q has invalid source IP %q", candidate.ID, sourceIP)
			}
		}
	}
	return nil
}

func cloneRegistry(registry Registry) Registry {
	cloned := registry
	cloned.Devices = make([]Device, len(registry.Devices))
	for i, candidate := range registry.Devices {
		cloned.Devices[i] = candidate
		cloned.Devices[i].SourceIPs = append([]string(nil), candidate.SourceIPs...)
		cloned.Devices[i].Tags = append([]string(nil), candidate.Tags...)
	}
	return cloned
}
