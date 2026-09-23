package device

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestOpenAndResolveDeviceMappings(t *testing.T) {
	path := filepath.Join(t.TempDir(), "devices.json")
	data := []byte(`{"schema_version":"device-registry/1","config_version":3,"devices":[{"id":"iphone-017","name":"iPhone 017","proxy_username":"iphone017","source_ips":["192.0.2.10"],"enabled":true},{"id":"disabled","name":"Disabled","proxy_username":"iphone017","enabled":false},{"id":"lab-ip","name":"Lab IP","source_ips":["192.0.2.11"],"enabled":true}]}`)
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	store, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := store.Resolve("iphone017", "192.0.2.99"); got.DeviceID != "iphone-017" || got.Ambiguous {
		t.Fatalf("username resolution = %+v", got)
	}
	if got := store.Resolve("unknown", "192.0.2.11"); got.DeviceID != "lab-ip" || got.Ambiguous {
		t.Fatalf("IP resolution = %+v", got)
	}
}

func TestAmbiguousUsernameDoesNotFallBackToIP(t *testing.T) {
	path := filepath.Join(t.TempDir(), "devices.json")
	data := []byte(`{"schema_version":"device-registry/1","devices":[{"id":"one","name":"One","proxy_username":"shared","enabled":true},{"id":"two","name":"Two","proxy_username":"shared","enabled":true},{"id":"ip","name":"IP","source_ips":["192.0.2.20"],"enabled":true}]}`)
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	store, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := store.Resolve("shared", "192.0.2.20"); got.DeviceID != "" || !got.Ambiguous {
		t.Fatalf("ambiguous username resolution = %+v", got)
	}
}

func TestMutationsPersistAndRejectStaleVersions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "devices.json")
	store, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	created, registry, err := store.Create(Device{Name: "iPhone 017", ProxyUsername: "iphone017", Enabled: true}, 0)
	if err != nil {
		t.Fatal(err)
	}
	if created.ID == "" || registry.ConfigVersion != 1 {
		t.Fatalf("create result = %+v, registry = %+v", created, registry)
	}
	if got := store.Resolve("iphone017", ""); got.DeviceID != created.ID {
		t.Fatalf("resolve after create = %+v", got)
	}
	if _, _, err := store.Create(Device{Name: "stale"}, 0); !errors.Is(err, ErrVersionConflict) {
		t.Fatalf("stale create error = %v", err)
	}
	updated, registry, err := store.Update(created.ID, Device{Name: "iPhone 017", ProxyUsername: "iphone017-new", Enabled: true}, 1)
	if err != nil {
		t.Fatal(err)
	}
	if updated.ID != created.ID || updated.CreatedAt != created.CreatedAt || registry.ConfigVersion != 2 {
		t.Fatalf("update result = %+v, registry = %+v", updated, registry)
	}
	if _, err := store.Delete(created.ID, 1); !errors.Is(err, ErrVersionConflict) {
		t.Fatalf("stale delete error = %v", err)
	}
	if _, err := store.Delete(created.ID, 2); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot := reopened.Snapshot(); snapshot.ConfigVersion != 3 || len(snapshot.Devices) != 0 {
		t.Fatalf("reopened registry = %+v", snapshot)
	}
}

func TestApplicationAssignmentsAreTimeBound(t *testing.T) {
	store, err := Open("")
	if err != nil {
		t.Fatal(err)
	}
	created, registry, err := store.Create(Device{ID: "phone-017", Name: "Phone 017", ProxyUsername: "phone017", Enabled: true}, 0)
	if err != nil {
		t.Fatal(err)
	}
	from := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	assignment, registry, err := store.CreateAssignment(ApplicationAssignment{
		ID: "phone-017-app-1", DeviceID: created.ID, Application: "Example", Version: "1.2.0",
		ValidFrom: from.Format(time.RFC3339), ValidTo: from.Add(24 * time.Hour).Format(time.RFC3339),
	}, registry.ConfigVersion)
	if err != nil {
		t.Fatal(err)
	}
	if assignment.ID == "" || registry.ConfigVersion != 2 {
		t.Fatalf("assignment result = %+v, registry = %+v", assignment, registry)
	}
	if got := store.ResolveAt("phone017", "", from.Add(time.Hour)); got.DeviceID != created.ID || got.Application != "Example" || got.ApplicationVersion != "1.2.0" || got.AssignmentID != assignment.ID {
		t.Fatalf("active assignment resolution = %+v", got)
	}
	if got := store.ResolveAt("phone017", "", from.Add(24*time.Hour)); got.Application != "" || got.AssignmentID != "" {
		t.Fatalf("expired assignment resolution = %+v", got)
	}
	if _, err := store.Delete(created.ID, registry.ConfigVersion); !errors.Is(err, ErrDeviceHasAssignments) {
		t.Fatalf("device with assignment delete error = %v", err)
	}
	_, _, err = store.CreateAssignment(ApplicationAssignment{
		ID: "overlap", DeviceID: created.ID, Application: "Other", Version: "2.0.0",
		ValidFrom: from.Add(12 * time.Hour).Format(time.RFC3339),
	}, registry.ConfigVersion)
	if err == nil {
		t.Fatal("overlapping assignment was accepted")
	}
}
