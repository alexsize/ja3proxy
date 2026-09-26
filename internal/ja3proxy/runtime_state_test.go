package ja3proxy

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/lylemi/ja3proxy/internal/ja3proxy/device"
	"github.com/lylemi/ja3proxy/internal/ja3proxy/routing"
	"github.com/lylemi/ja3proxy/internal/ja3proxy/tlsprofile"
	"github.com/lylemi/ja3proxy/internal/ja3proxy/upstreamtls"
)

func TestRuntimePersistsManagedStoresInSharedSQLite(t *testing.T) {
	dir := t.TempDir()
	config := &RunningConfig{
		StateSQLite: filepath.Join(dir, "state.db"),
		Cert:        filepath.Join(dir, "credentials", "ca.pem"),
		Key:         filepath.Join(dir, "credentials", "ca-key.pem"),
		TLSClient:   "Golang",
		TLSVersion:  "0",
		TLSMode:     "MITM_REISSUE",
	}
	app := newDefaultApp()
	app.Config = config
	if err := app.configureRuntime(context.Background()); err != nil {
		t.Fatal(err)
	}
	createdDevice, _, err := app.Devices.Create(device.Device{Name: "runtime device", Enabled: true}, 0)
	if err != nil {
		t.Fatal(err)
	}
	template, err := tlsprofile.TemplateFromPreset("runtime profile", "Chrome", "120")
	if err != nil {
		t.Fatal(err)
	}
	createdProfile, _, err := app.TLSProfiles.Create(template, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := app.Routes.SetValidated(routing.Config{Rules: []routing.Rule{{
		ID: "runtime-route", Enabled: true, Phase: routing.PhasePreTLS,
		Match: routing.Match{Host: "runtime.example"}, Action: routing.Action{Mode: "PASSTHROUGH"},
	}}}); err != nil {
		t.Fatal(err)
	}
	if err := app.UpstreamTLSProfiles.SetValidated(upstreamtls.UpstreamTLSConfig{
		Default: upstreamtls.UpstreamTLSProfile{Protocol: "utls", Client: "Chrome", Version: "120"},
	}); err != nil {
		t.Fatal(err)
	}
	app.closePersistentStores()

	restarted := newDefaultApp()
	restarted.Config = config
	if err := restarted.configureRuntime(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer restarted.closePersistentStores()
	if got := restarted.Devices.Snapshot().Devices[0].ID; got != createdDevice.ID {
		t.Fatalf("runtime restored device ID = %q, want %q", got, createdDevice.ID)
	}
	if _, found := restarted.TLSProfiles.Get(createdProfile.ID); !found {
		t.Fatal("runtime did not restore TLS profile")
	}
	if routes, _, found := restarted.Routes.Snapshot(); !found || len(routes.Rules) != 1 {
		t.Fatalf("runtime did not restore route snapshot: %+v found=%v", routes, found)
	}
	if upstream, _, found := restarted.UpstreamTLSProfiles.Snapshot(); !found || upstream.Default.Client != "Chrome" {
		t.Fatalf("runtime did not restore upstream TLS snapshot: %+v found=%v", upstream, found)
	}
}
