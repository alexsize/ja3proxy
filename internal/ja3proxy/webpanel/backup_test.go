package webpanel

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/lylemi/ja3proxy/internal/ja3proxy/device"
	"github.com/lylemi/ja3proxy/internal/ja3proxy/routing"
	"github.com/lylemi/ja3proxy/internal/ja3proxy/tlsprofile"
	"github.com/lylemi/ja3proxy/internal/ja3proxy/upstreamtls"
)

func TestConfigBackupRedactsUpstreamCredentials(t *testing.T) {
	routes := &routing.Store{}
	if err := routes.SetValidated(routing.Config{
		Default: routing.Action{Upstream: "socks5://backup-user:backup-pass@example.test:1080?token=hidden&region=eu"},
		Rules: []routing.Rule{{
			ID: "rule-1", Enabled: true, Phase: routing.PhasePreTLS,
			Match:  routing.Match{Host: "example.test"},
			Action: routing.Action{Mode: "PASSTHROUGH", Upstream: "http://route-user:route-pass@example.test:8080?password=hidden"},
		}},
	}); err != nil {
		t.Fatal(err)
	}
	h := Server{
		Routes: routes,
		Runtime: func() RuntimeStatus {
			return RuntimeStatus{Upstream: "http://runtime-user:runtime-pass@example.test:8080?secret=hidden"}
		},
	}.Handler()

	request := httptest.NewRequest(http.MethodGet, "/api/v1/export/config", nil)
	request.RemoteAddr = "127.0.0.1:54321"
	request.Host = "127.0.0.1:9090"
	response := httptest.NewRecorder()
	h.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("backup status = %d, body = %s", response.Code, response.Body.String())
	}
	var backup ConfigBackup
	if err := json.Unmarshal(response.Body.Bytes(), &backup); err != nil {
		t.Fatal(err)
	}
	data := response.Body.String()
	for _, secret := range []string{"backup-pass", "backup-user", "route-pass", "route-user", "runtime-pass", "token=hidden", "password=hidden", "secret=hidden"} {
		if strings.Contains(data, secret) {
			t.Fatalf("backup contains secret %q: %s", secret, data)
		}
	}
	if got := backup.Routes.Default.Upstream; got != "socks5://example.test:1080?region=eu" {
		t.Fatalf("redacted default upstream = %q", got)
	}
	if got := backup.Routes.Rules[0].Action.Upstream; got != "http://example.test:8080" {
		t.Fatalf("redacted route upstream = %q", got)
	}
	if got := backup.Runtime.Upstream; got != "http://example.test:8080" {
		t.Fatalf("redacted runtime upstream = %q", got)
	}
}

func TestConfigBackupZIPContainsJSON(t *testing.T) {
	h := Server{}.Handler()
	request := httptest.NewRequest(http.MethodGet, "/api/v1/export/config?format=zip", nil)
	request.RemoteAddr = "127.0.0.1:54321"
	request.Host = "127.0.0.1:9090"
	response := httptest.NewRecorder()
	h.ServeHTTP(response, request)
	if response.Code != http.StatusOK || response.Header().Get("Content-Type") != "application/zip" {
		t.Fatalf("zip response = %d %q", response.Code, response.Header().Get("Content-Type"))
	}
	archive, err := zip.NewReader(bytes.NewReader(response.Body.Bytes()), int64(response.Body.Len()))
	if err != nil {
		t.Fatal(err)
	}
	if len(archive.File) != 1 || archive.File[0].Name != "config.json" {
		t.Fatalf("zip files = %#v", archive.File)
	}
	file, err := archive.File[0].Open()
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	var backup ConfigBackup
	if err := json.NewDecoder(file).Decode(&backup); err != nil {
		t.Fatal(err)
	}
	if backup.SchemaVersion != configBackupSchemaVersion {
		t.Fatalf("backup schema = %q", backup.SchemaVersion)
	}
}

func TestConfigBackupRejectsUnknownFormat(t *testing.T) {
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/api/v1/export/config?format=tar", nil)
	request.RemoteAddr = "127.0.0.1:54321"
	request.Host = "127.0.0.1:9090"
	Server{}.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("unknown format status = %d", response.Code)
	}
}

func TestConfigBackupValidationAcceptsJSONAndZIP(t *testing.T) {
	h := Server{}.Handler()
	getBackup := func(format string) []byte {
		request := httptest.NewRequest(http.MethodGet, "/api/v1/export/config?format="+format, nil)
		request.RemoteAddr = "127.0.0.1:54321"
		request.Host = "127.0.0.1:9090"
		response := httptest.NewRecorder()
		h.ServeHTTP(response, request)
		if response.Code != http.StatusOK {
			t.Fatalf("export %s status = %d", format, response.Code)
		}
		return response.Body.Bytes()
	}
	for _, backup := range [][]byte{getBackup("json"), getBackup("zip")} {
		request := httptest.NewRequest(http.MethodPost, "/api/v1/import/config/validate", bytes.NewReader(backup))
		request.RemoteAddr = "127.0.0.1:54321"
		request.Host = "127.0.0.1:9090"
		response := httptest.NewRecorder()
		h.ServeHTTP(response, request)
		if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"valid":true`) {
			t.Fatalf("validation response = %d %s", response.Code, response.Body.String())
		}
	}
}

func TestConfigBackupImportUsesExpectedVersions(t *testing.T) {
	devices, err := device.Open("")
	if err != nil {
		t.Fatal(err)
	}
	profiles, err := tlsprofile.Open("")
	if err != nil {
		t.Fatal(err)
	}
	routes := &routing.Store{}
	upstream := &upstreamtls.UpstreamTLSProfileStore{}
	panel := Server{Devices: devices, Profiles: profiles, Routes: routes, UpstreamTLS: upstream}
	backup := panel.configBackup()
	data, err := json.Marshal(backup)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/api/v1/import/config?expected_devices_version=0&expected_tls_profiles_version=0&expected_routes_version=0&expected_upstream_tls_version=0", bytes.NewReader(data))
	request.RemoteAddr = "127.0.0.1:54321"
	request.Host = "127.0.0.1:9090"
	response := httptest.NewRecorder()
	panel.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"devices"`) || !strings.Contains(response.Body.String(), `"tls_profiles"`) {
		t.Fatalf("restore response = %d %s", response.Code, response.Body.String())
	}
	if devices.Snapshot().ConfigVersion != 1 || profiles.Snapshot().ConfigVersion != 1 {
		t.Fatalf("restore versions = devices %d profiles %d", devices.Snapshot().ConfigVersion, profiles.Snapshot().ConfigVersion)
	}

	request = httptest.NewRequest(http.MethodPost, "/api/v1/import/config?expected_devices_version=0&expected_tls_profiles_version=1&expected_routes_version=1&expected_upstream_tls_version=1", bytes.NewReader(data))
	request.RemoteAddr = "127.0.0.1:54321"
	request.Host = "127.0.0.1:9090"
	response = httptest.NewRecorder()
	panel.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusConflict {
		t.Fatalf("stale restore status = %d, body = %s", response.Code, response.Body.String())
	}
}
