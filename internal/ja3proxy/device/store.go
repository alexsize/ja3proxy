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
	ErrVersionConflict           = errors.New("device registry version conflict")
	ErrDeviceNotFound            = errors.New("device not found")
	ErrDeviceHasAssignments      = errors.New("device has application assignments")
	ErrPersistence               = errors.New("device registry persistence error")
	ErrAssignmentNotFound        = errors.New("device application assignment not found")
	ErrApplicationNotFound       = errors.New("application not found")
	ErrApplicationHasAssignments = errors.New("application has assignments")
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

type ApplicationAssignment struct {
	ID            string `json:"id"`
	DeviceID      string `json:"device_id"`
	ApplicationID string `json:"application_id,omitempty"`
	Application   string `json:"application"`
	Version       string `json:"version"`
	ValidFrom     string `json:"valid_from"`
	ValidTo       string `json:"valid_to,omitempty"`
}

type Application struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Publisher   string `json:"publisher,omitempty"`
	Platform    string `json:"platform,omitempty"`
	Package     string `json:"package,omitempty"`
	Description string `json:"description,omitempty"`
	CreatedAt   string `json:"created_at,omitempty"`
	Enabled     bool   `json:"enabled"`
}

type Registry struct {
	SchemaVersion string                  `json:"schema_version"`
	ConfigVersion uint64                  `json:"config_version"`
	Devices       []Device                `json:"devices"`
	Assignments   []ApplicationAssignment `json:"assignments,omitempty"`
	Applications  []Application           `json:"applications,omitempty"`
}

type Resolution struct {
	DeviceID            string
	Application         string
	ApplicationVersion  string
	ApplicationID       string
	AssignmentID        string
	Ambiguous           bool
	AssignmentAmbiguous bool
}

type Store struct {
	mu       sync.RWMutex
	registry Registry
	path     string
}

func Open(path string) (*Store, error) {
	store := &Store{path: path, registry: Registry{SchemaVersion: SchemaVersion, Devices: []Device{}, Assignments: []ApplicationAssignment{}, Applications: []Application{}}}
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
	for _, assignment := range next.Assignments {
		if assignment.DeviceID == id {
			return cloneRegistry(s.registry), fmt.Errorf("%w: %q", ErrDeviceHasAssignments, assignment.ID)
		}
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
		return Registry{SchemaVersion: SchemaVersion, Devices: []Device{}, Assignments: []ApplicationAssignment{}, Applications: []Application{}}
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return cloneRegistry(s.registry)
}

func (s *Store) Resolve(proxyUsername, sourceIP string) Resolution {
	return s.ResolveAt(proxyUsername, sourceIP, time.Now().UTC())
}

func (s *Store) ResolveAt(proxyUsername, sourceIP string, at time.Time) Resolution {
	if s == nil {
		return Resolution{}
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if proxyUsername != "" {
		matches := s.matchUsername(proxyUsername)
		if len(matches) == 1 {
			return s.resolveAssignment(Resolution{DeviceID: matches[0]}, at)
		}
		if len(matches) > 1 {
			return Resolution{Ambiguous: true}
		}
	}
	if ip := net.ParseIP(sourceIP); ip != nil {
		matches := s.matchIP(ip.String())
		if len(matches) == 1 {
			return s.resolveAssignment(Resolution{DeviceID: matches[0]}, at)
		}
		if len(matches) > 1 {
			return Resolution{Ambiguous: true}
		}
	}
	return Resolution{}
}

func (s *Store) resolveAssignment(resolution Resolution, at time.Time) Resolution {
	var matches []ApplicationAssignment
	for _, assignment := range s.registry.Assignments {
		if assignment.DeviceID == resolution.DeviceID && assignmentActive(assignment, at) {
			matches = append(matches, assignment)
		}
	}
	if len(matches) != 1 {
		if len(matches) > 1 {
			resolution.AssignmentAmbiguous = true
		}
		return resolution
	}
	resolution.Application = matches[0].Application
	resolution.ApplicationVersion = matches[0].Version
	resolution.ApplicationID = matches[0].ApplicationID
	resolution.AssignmentID = matches[0].ID
	return resolution
}

func (s *Store) CreateAssignment(candidate ApplicationAssignment, expectedVersion uint64) (ApplicationAssignment, Registry, error) {
	if s == nil {
		return ApplicationAssignment{}, Registry{}, errors.New("device registry is unavailable")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.registry.ConfigVersion != expectedVersion {
		return ApplicationAssignment{}, cloneRegistry(s.registry), ErrVersionConflict
	}
	if candidate.ID == "" {
		candidate.ID = newID()
	}
	if candidate.ApplicationID != "" {
		application, found := findApplication(s.registry.Applications, candidate.ApplicationID)
		if !found {
			return ApplicationAssignment{}, cloneRegistry(s.registry), ErrApplicationNotFound
		}
		if candidate.Application == "" {
			candidate.Application = application.Name
		}
	}
	if err := validateAssignment(candidate, s.registry); err != nil {
		return ApplicationAssignment{}, cloneRegistry(s.registry), err
	}
	for _, existing := range s.registry.Assignments {
		if existing.ID == candidate.ID {
			return ApplicationAssignment{}, cloneRegistry(s.registry), fmt.Errorf("duplicate assignment id %q", candidate.ID)
		}
	}
	next := cloneRegistry(s.registry)
	next.Assignments = append(next.Assignments, candidate)
	next.ConfigVersion++
	if err := s.persist(next); err != nil {
		return ApplicationAssignment{}, cloneRegistry(s.registry), fmt.Errorf("%w: %v", ErrPersistence, err)
	}
	s.registry = next
	return candidate, cloneRegistry(next), nil
}

func (s *Store) UpdateAssignment(id string, candidate ApplicationAssignment, expectedVersion uint64) (ApplicationAssignment, Registry, error) {
	if s == nil {
		return ApplicationAssignment{}, Registry{}, errors.New("device registry is unavailable")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.registry.ConfigVersion != expectedVersion {
		return ApplicationAssignment{}, cloneRegistry(s.registry), ErrVersionConflict
	}
	next := cloneRegistry(s.registry)
	index := -1
	for i, existing := range next.Assignments {
		if existing.ID == id {
			index = i
			break
		}
	}
	if index < 0 {
		return ApplicationAssignment{}, cloneRegistry(s.registry), ErrAssignmentNotFound
	}
	candidate.ID = id
	if candidate.ApplicationID != "" {
		application, found := findApplication(next.Applications, candidate.ApplicationID)
		if !found {
			return ApplicationAssignment{}, cloneRegistry(s.registry), ErrApplicationNotFound
		}
		if candidate.Application == "" {
			candidate.Application = application.Name
		}
	}
	next.Assignments[index] = candidate
	if err := validateAssignment(candidate, next); err != nil {
		return ApplicationAssignment{}, cloneRegistry(s.registry), err
	}
	next.ConfigVersion++
	if err := s.persist(next); err != nil {
		return ApplicationAssignment{}, cloneRegistry(s.registry), fmt.Errorf("%w: %v", ErrPersistence, err)
	}
	s.registry = next
	return candidate, cloneRegistry(next), nil
}

func (s *Store) DeleteAssignment(id string, expectedVersion uint64) (Registry, error) {
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
	for i, assignment := range next.Assignments {
		if assignment.ID == id {
			index = i
			break
		}
	}
	if index < 0 {
		return cloneRegistry(s.registry), ErrAssignmentNotFound
	}
	next.Assignments = append(next.Assignments[:index], next.Assignments[index+1:]...)
	next.ConfigVersion++
	if err := s.persist(next); err != nil {
		return cloneRegistry(s.registry), fmt.Errorf("%w: %v", ErrPersistence, err)
	}
	s.registry = next
	return cloneRegistry(next), nil
}

func (s *Store) GetAssignment(id string) (ApplicationAssignment, bool) {
	if s == nil {
		return ApplicationAssignment{}, false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, assignment := range s.registry.Assignments {
		if assignment.ID == id {
			return assignment, true
		}
	}
	return ApplicationAssignment{}, false
}

func (s *Store) GetApplication(id string) (Application, bool) {
	if s == nil {
		return Application{}, false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return findApplication(s.registry.Applications, id)
}

func (s *Store) CreateApplication(candidate Application, expectedVersion uint64) (Application, Registry, error) {
	if s == nil {
		return Application{}, Registry{}, errors.New("device registry is unavailable")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.registry.ConfigVersion != expectedVersion {
		return Application{}, cloneRegistry(s.registry), ErrVersionConflict
	}
	if candidate.ID == "" {
		candidate.ID = newID()
	}
	if candidate.CreatedAt == "" {
		candidate.CreatedAt = time.Now().UTC().Format(time.RFC3339)
	}
	if err := validateApplication(candidate); err != nil {
		return Application{}, cloneRegistry(s.registry), err
	}
	if _, found := findApplication(s.registry.Applications, candidate.ID); found {
		return Application{}, cloneRegistry(s.registry), fmt.Errorf("duplicate application id %q", candidate.ID)
	}
	next := cloneRegistry(s.registry)
	next.Applications = append(next.Applications, candidate)
	next.ConfigVersion++
	if err := s.persist(next); err != nil {
		return Application{}, cloneRegistry(s.registry), fmt.Errorf("%w: %v", ErrPersistence, err)
	}
	s.registry = next
	return candidate, cloneRegistry(next), nil
}

func (s *Store) UpdateApplication(id string, candidate Application, expectedVersion uint64) (Application, Registry, error) {
	if s == nil {
		return Application{}, Registry{}, errors.New("device registry is unavailable")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.registry.ConfigVersion != expectedVersion {
		return Application{}, cloneRegistry(s.registry), ErrVersionConflict
	}
	next := cloneRegistry(s.registry)
	index := -1
	for i, existing := range next.Applications {
		if existing.ID == id {
			index = i
			if candidate.CreatedAt == "" {
				candidate.CreatedAt = existing.CreatedAt
			}
			break
		}
	}
	if index < 0 {
		return Application{}, cloneRegistry(s.registry), ErrApplicationNotFound
	}
	candidate.ID = id
	if err := validateApplication(candidate); err != nil {
		return Application{}, cloneRegistry(s.registry), err
	}
	next.Applications[index] = candidate
	next.ConfigVersion++
	if err := s.persist(next); err != nil {
		return Application{}, cloneRegistry(s.registry), fmt.Errorf("%w: %v", ErrPersistence, err)
	}
	s.registry = next
	return candidate, cloneRegistry(next), nil
}

func (s *Store) DeleteApplication(id string, expectedVersion uint64) (Registry, error) {
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
	for i, application := range next.Applications {
		if application.ID == id {
			index = i
			break
		}
	}
	if index < 0 {
		return cloneRegistry(s.registry), ErrApplicationNotFound
	}
	for _, assignment := range next.Assignments {
		if assignment.ApplicationID == id {
			return cloneRegistry(s.registry), fmt.Errorf("%w: %q", ErrApplicationHasAssignments, assignment.ID)
		}
	}
	next.Applications = append(next.Applications[:index], next.Applications[index+1:]...)
	next.ConfigVersion++
	if err := s.persist(next); err != nil {
		return cloneRegistry(s.registry), fmt.Errorf("%w: %v", ErrPersistence, err)
	}
	s.registry = next
	return cloneRegistry(next), nil
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
	applicationIDs := map[string]struct{}{}
	for _, application := range registry.Applications {
		if err := validateApplication(application); err != nil {
			return err
		}
		if _, exists := applicationIDs[application.ID]; exists {
			return fmt.Errorf("duplicate application id %q", application.ID)
		}
		applicationIDs[application.ID] = struct{}{}
	}
	assignmentIDs := map[string]struct{}{}
	for _, assignment := range registry.Assignments {
		if err := validateAssignment(assignment, registry); err != nil {
			return err
		}
		if _, exists := assignmentIDs[assignment.ID]; exists {
			return fmt.Errorf("duplicate assignment id %q", assignment.ID)
		}
		assignmentIDs[assignment.ID] = struct{}{}
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

func validateAssignment(candidate ApplicationAssignment, registry Registry) error {
	if candidate.ID == "" || candidate.DeviceID == "" || (candidate.Application == "" && candidate.ApplicationID == "") || candidate.Version == "" || candidate.ValidFrom == "" {
		return errors.New("assignment id, device_id, application or application_id, version and valid_from are required")
	}
	if _, found := findDevice(registry.Devices, candidate.DeviceID); !found {
		return fmt.Errorf("assignment references unknown device %q", candidate.DeviceID)
	}
	if candidate.ApplicationID != "" {
		if _, found := findApplication(registry.Applications, candidate.ApplicationID); !found {
			return fmt.Errorf("assignment references unknown application %q", candidate.ApplicationID)
		}
	}
	from, err := time.Parse(time.RFC3339, candidate.ValidFrom)
	if err != nil {
		return fmt.Errorf("assignment %q has invalid valid_from: %w", candidate.ID, err)
	}
	var to time.Time
	if candidate.ValidTo != "" {
		to, err = time.Parse(time.RFC3339, candidate.ValidTo)
		if err != nil {
			return fmt.Errorf("assignment %q has invalid valid_to: %w", candidate.ID, err)
		}
		if !from.Before(to) {
			return fmt.Errorf("assignment %q valid_from must be before valid_to", candidate.ID)
		}
	}
	for _, existing := range registry.Assignments {
		if existing.ID == candidate.ID || existing.DeviceID != candidate.DeviceID {
			continue
		}
		existingFrom, _ := time.Parse(time.RFC3339, existing.ValidFrom)
		var existingTo time.Time
		if existing.ValidTo != "" {
			existingTo, _ = time.Parse(time.RFC3339, existing.ValidTo)
		}
		if intervalsOverlap(from, to, existingFrom, existingTo) {
			return fmt.Errorf("assignment %q overlaps assignment %q", candidate.ID, existing.ID)
		}
	}
	return nil
}

func validateApplication(candidate Application) error {
	if candidate.ID == "" || candidate.Name == "" {
		return errors.New("application id and name are required")
	}
	return nil
}

func findDevice(devices []Device, id string) (Device, bool) {
	for _, candidate := range devices {
		if candidate.ID == id {
			return candidate, true
		}
	}
	return Device{}, false
}

func findApplication(applications []Application, id string) (Application, bool) {
	for _, candidate := range applications {
		if candidate.ID == id {
			return candidate, true
		}
	}
	return Application{}, false
}

func assignmentActive(assignment ApplicationAssignment, at time.Time) bool {
	from, err := time.Parse(time.RFC3339, assignment.ValidFrom)
	if err != nil || at.Before(from) {
		return false
	}
	if assignment.ValidTo == "" {
		return true
	}
	to, err := time.Parse(time.RFC3339, assignment.ValidTo)
	return err == nil && at.Before(to)
}

func intervalsOverlap(leftFrom, leftTo, rightFrom, rightTo time.Time) bool {
	return (leftTo.IsZero() || rightFrom.Before(leftTo)) && (rightTo.IsZero() || leftFrom.Before(rightTo))
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
	cloned.Assignments = append([]ApplicationAssignment(nil), registry.Assignments...)
	cloned.Applications = append([]Application(nil), registry.Applications...)
	return cloned
}

func cloneDevice(candidate Device) Device {
	candidate.SourceIPs = append([]string(nil), candidate.SourceIPs...)
	candidate.Tags = append([]string(nil), candidate.Tags...)
	return candidate
}
