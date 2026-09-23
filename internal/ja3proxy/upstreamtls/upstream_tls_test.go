package upstreamtls

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadUpstreamTLSConfigFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "upstream-tls.json")
	if err := os.WriteFile(path, []byte(`{
		"default": {"protocol": "utls", "client": "Chrome", "version": "120"},
		"routes": [
			{"host": "*.example.com", "protocol": "utls", "client": "Firefox", "version": "105"}
		]
	}`), 0o600); err != nil {
		t.Fatalf("write upstream TLS config: %v", err)
	}

	got, err := loadUpstreamTLSConfigFile(path)
	if err != nil {
		t.Fatalf("loadUpstreamTLSConfigFile() error = %v", err)
	}
	if got.Default.Protocol != "utls" || got.Default.Client != "Chrome" || got.Default.Version != "120" {
		t.Fatalf("default profile = %+v, want utls Chrome 120", got.Default)
	}
	if len(got.Routes) != 1 {
		t.Fatalf("route count = %d, want 1", len(got.Routes))
	}
	if got.Routes[0].Host != "*.example.com" || got.Routes[0].Protocol != "utls" ||
		got.Routes[0].Client != "Firefox" || got.Routes[0].Version != "105" {
		t.Fatalf("route = %+v, want *.example.com utls Firefox 105", got.Routes[0])
	}
}

func TestUpstreamTLSProfileStoreMatchesRoutes(t *testing.T) {
	store := &UpstreamTLSProfileStore{}
	if err := store.SetValidated(UpstreamTLSConfig{
		Default: UpstreamTLSProfile{Protocol: "utls", Client: "Chrome", Version: "120"},
		Routes: []UpstreamTLSRoute{
			{
				Host:               "*.example.com",
				UpstreamTLSProfile: UpstreamTLSProfile{Protocol: "utls", Client: "Firefox", Version: "105"},
			},
			{
				Host:               "api.example.com",
				UpstreamTLSProfile: UpstreamTLSProfile{Protocol: "utls", Client: "360Browser", Version: "7.5"},
			},
		},
	}); err != nil {
		t.Fatalf("SetValidated() error = %v", err)
	}

	tests := []struct {
		host       string
		wantClient string
		wantVer    string
	}{
		{host: "api.example.com", wantClient: "360Browser", wantVer: "7.5"},
		{host: "www.example.com", wantClient: "Firefox", wantVer: "105"},
		{host: "WWW.EXAMPLE.COM:443", wantClient: "Firefox", wantVer: "105"},
		{host: "example.com", wantClient: "Chrome", wantVer: "120"},
		{host: "other.test", wantClient: "Chrome", wantVer: "120"},
	}

	for _, tt := range tests {
		t.Run(tt.host, func(t *testing.T) {
			got, ok := store.Get(tt.host)
			if !ok {
				t.Fatal("Get() ok = false, want profile")
			}
			if got.Protocol != upstreamTLSProtocolUTLS || got.Client != tt.wantClient || got.Version != tt.wantVer {
				t.Fatalf("Get(%q) = %+v, want %s %s", tt.host, got, tt.wantClient, tt.wantVer)
			}
		})
	}
}

func TestUpstreamTLSRoutesUsePriorityThenHostSpecificity(t *testing.T) {
	store := &UpstreamTLSProfileStore{}
	config := UpstreamTLSConfig{
		Default: UpstreamTLSProfile{Protocol: "utls", Client: "Chrome", Version: "120"},
		Routes: []UpstreamTLSRoute{
			{Host: "*.example.com", Priority: 10, UpstreamTLSProfile: UpstreamTLSProfile{Protocol: "utls", Client: "Firefox", Version: "105"}},
			{Host: "api.example.com", Priority: 5, UpstreamTLSProfile: UpstreamTLSProfile{Protocol: "utls", Client: "360Browser", Version: "7.5"}},
		},
	}
	if err := store.SetValidated(config); err != nil {
		t.Fatal(err)
	}
	if got, ok := store.Get("api.example.com"); !ok || got.Client != "Firefox" {
		t.Fatalf("priority selection = %+v, ok=%v", got, ok)
	}
	config.Routes[1].Priority = 10
	if err := store.SetValidated(config); err != nil {
		t.Fatal(err)
	}
	if got, ok := store.Get("api.example.com"); !ok || got.Client != "360Browser" {
		t.Fatalf("exact host tie-break = %+v, ok=%v", got, ok)
	}
}

func TestUpstreamTLSStoreVersionsAreImmutableSnapshots(t *testing.T) {
	config := UpstreamTLSConfig{
		Default: UpstreamTLSProfile{Protocol: "utls", Client: "Chrome", Version: "120"},
		Routes: []UpstreamTLSRoute{{
			Host:               "*.example.com",
			UpstreamTLSProfile: UpstreamTLSProfile{Protocol: "utls", Client: "Firefox", Version: "105"},
		}},
	}
	store := &UpstreamTLSProfileStore{}
	store.Set(config)
	config.Routes[0].Client = "Safari"

	got, version, ok := store.GetWithVersion("api.example.com")
	if !ok || version != 1 || got.Client != "Firefox" {
		t.Fatalf("snapshot = %+v, version=%d, ok=%v; want Firefox, version 1", got, version, ok)
	}

	config.Routes[0].Version = "17.0"
	store.Set(config)
	got, nextVersion, ok := store.GetWithVersion("api.example.com")
	if !ok || nextVersion != 2 || got.Client != "Safari" || got.Version != "17.0" {
		t.Fatalf("updated snapshot = %+v, version=%d, ok=%v; want Safari 17.0, version 2", got, nextVersion, ok)
	}
}

func TestValidateUpstreamTLSConfigRejectsInvalidProfiles(t *testing.T) {
	tests := []struct {
		name   string
		config UpstreamTLSConfig
		want   string
	}{
		{
			name: "unsupported protocol",
			config: UpstreamTLSConfig{
				Default: UpstreamTLSProfile{Protocol: "not-a-protocol", Client: "Chrome", Version: "120"},
			},
			want: "unsupported upstream TLS protocol",
		},
		{
			name: "missing utls client",
			config: UpstreamTLSConfig{
				Default: UpstreamTLSProfile{Protocol: "utls", Version: "120"},
			},
			want: "utls client is required",
		},
		{
			name: "missing utls version",
			config: UpstreamTLSConfig{
				Default: UpstreamTLSProfile{Protocol: "utls", Client: "Chrome"},
			},
			want: "utls version is required",
		},
		{
			name: "route missing utls client",
			config: UpstreamTLSConfig{
				Default: UpstreamTLSProfile{Protocol: "utls", Client: "Chrome", Version: "120"},
				Routes: []UpstreamTLSRoute{
					{
						Host:               "*.example.com",
						UpstreamTLSProfile: UpstreamTLSProfile{Protocol: "utls", Version: "105"},
					},
				},
			},
			want: "utls client is required",
		},
		{
			name: "route missing utls version",
			config: UpstreamTLSConfig{
				Default: UpstreamTLSProfile{Protocol: "utls", Client: "Chrome", Version: "120"},
				Routes: []UpstreamTLSRoute{
					{
						Host:               "*.example.com",
						UpstreamTLSProfile: UpstreamTLSProfile{Protocol: "utls", Client: "Firefox"},
					},
				},
			},
			want: "utls version is required",
		},
		{
			name: "missing route host",
			config: UpstreamTLSConfig{
				Routes: []UpstreamTLSRoute{
					{UpstreamTLSProfile: UpstreamTLSProfile{Protocol: "utls", Client: "Chrome", Version: "120"}},
				},
			},
			want: "host is required",
		},
		{
			name: "bad wildcard",
			config: UpstreamTLSConfig{
				Routes: []UpstreamTLSRoute{
					{
						Host:               "api.*.example.com",
						UpstreamTLSProfile: UpstreamTLSProfile{Protocol: "utls", Client: "Chrome", Version: "120"},
					},
				},
			},
			want: "wildcard host must start",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateUpstreamTLSConfig(tt.config)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("validateUpstreamTLSConfig() error = %v, want %q", err, tt.want)
			}
		})
	}
}
