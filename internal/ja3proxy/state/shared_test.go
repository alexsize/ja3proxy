package state_test

import (
	"path/filepath"
	"testing"

	"github.com/lylemi/ja3proxy/internal/ja3proxy/audit"
	"github.com/lylemi/ja3proxy/internal/ja3proxy/device"
	"github.com/lylemi/ja3proxy/internal/ja3proxy/recorder"
	"github.com/lylemi/ja3proxy/internal/ja3proxy/routing"
	"github.com/lylemi/ja3proxy/internal/ja3proxy/state"
	"github.com/lylemi/ja3proxy/internal/ja3proxy/tlsprofile"
	"github.com/lylemi/ja3proxy/internal/ja3proxy/upstreamtls"
)

func TestControlStoresShareOneSQLiteDatabaseAcrossRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ja3proxy.db")
	controlDB, err := state.OpenSQLite(path)
	if err != nil {
		t.Fatal(err)
	}
	devices, err := device.OpenWithState("", controlDB)
	if err != nil {
		t.Fatal(err)
	}
	createdDevice, _, err := devices.Create(device.Device{Name: "test device", Enabled: true}, 0)
	if err != nil {
		t.Fatal(err)
	}
	profiles, err := tlsprofile.OpenWithState("", controlDB)
	if err != nil {
		t.Fatal(err)
	}
	template, err := tlsprofile.TemplateFromPreset("test profile", "Chrome", "120")
	if err != nil {
		t.Fatal(err)
	}
	createdProfile, _, err := profiles.Create(template, 0)
	if err != nil {
		t.Fatal(err)
	}
	routes := &routing.Store{}
	if err := routes.RestoreWithState("", controlDB); err != nil {
		t.Fatal(err)
	}
	if err := routes.SetValidated(routing.Config{Rules: []routing.Rule{{
		ID: "route", Enabled: true, Phase: routing.PhasePreTLS,
		Match: routing.Match{Host: "example.com"}, Action: routing.Action{Mode: "PASSTHROUGH"},
	}}}); err != nil {
		t.Fatal(err)
	}
	upstreamTLS := &upstreamtls.UpstreamTLSProfileStore{}
	if err := upstreamTLS.RestoreWithState("", controlDB); err != nil {
		t.Fatal(err)
	}
	if err := upstreamTLS.SetValidated(upstreamtls.UpstreamTLSConfig{
		Default: upstreamtls.UpstreamTLSProfile{Protocol: "utls", Client: "Chrome", Version: "120"},
	}); err != nil {
		t.Fatal(err)
	}
	auditStore, err := audit.OpenSQLite(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := auditStore.Append(audit.Event{Actor: "test", Action: "write", Object: "state", Result: "success"}); err != nil {
		t.Fatal(err)
	}
	observationStore, err := recorder.New(recorder.Options{SQLitePath: path, SQLiteRetention: 10})
	if err != nil {
		t.Fatal(err)
	}
	if err := observationStore.Close(); err != nil {
		t.Fatal(err)
	}
	if err := auditStore.Close(); err != nil {
		t.Fatal(err)
	}
	if err := controlDB.Close(); err != nil {
		t.Fatal(err)
	}

	controlDB, err = state.OpenSQLite(path)
	if err != nil {
		t.Fatal(err)
	}
	defer controlDB.Close()
	devices, err = device.OpenWithState("", controlDB)
	if err != nil {
		t.Fatal(err)
	}
	if got := devices.Snapshot().Devices[0].ID; got != createdDevice.ID {
		t.Fatalf("restored device ID = %q, want %q", got, createdDevice.ID)
	}
	profiles, err = tlsprofile.OpenWithState("", controlDB)
	if err != nil {
		t.Fatal(err)
	}
	if _, found := profiles.Get(createdProfile.ID); !found || len(profiles.History(createdProfile.ID)) != 1 {
		t.Fatalf("TLS profile was not restored with history: found=%v history=%+v", found, profiles.History(createdProfile.ID))
	}
	routes = &routing.Store{}
	if err := routes.RestoreWithState("", controlDB); err != nil {
		t.Fatal(err)
	}
	if config, _, found := routes.Snapshot(); !found || len(config.Rules) != 1 {
		t.Fatalf("route snapshot was not restored: %+v found=%v", config, found)
	}
	upstreamTLS = &upstreamtls.UpstreamTLSProfileStore{}
	if err := upstreamTLS.RestoreWithState("", controlDB); err != nil {
		t.Fatal(err)
	}
	if config, _, found := upstreamTLS.Snapshot(); !found || config.Default.Client != "Chrome" {
		t.Fatalf("upstream TLS snapshot was not restored: %+v found=%v", config, found)
	}
	auditStore, err = audit.OpenSQLite(path)
	if err != nil {
		t.Fatal(err)
	}
	defer auditStore.Close()
	if page, err := auditStore.Query(10, ""); err != nil || len(page.Items) != 1 {
		t.Fatalf("audit records were not restored from shared database: %+v, %v", page, err)
	}
	observationStore, err = recorder.New(recorder.Options{SQLitePath: path, SQLiteRetention: 10})
	if err != nil {
		t.Fatal(err)
	}
	if err := observationStore.Close(); err != nil {
		t.Fatal(err)
	}
}
