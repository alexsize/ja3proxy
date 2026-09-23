package device

import (
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
