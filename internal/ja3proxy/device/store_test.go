package device

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
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
