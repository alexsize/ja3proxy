package ja3proxy

import (
	"path/filepath"
	"testing"
	"time"
)

func TestRecorderCLI(t *testing.T) {
	for _, args := range [][]string{{"--capture-raw"}, {"--capture-jsonl", "capture.jsonl"}, {"--capture-sqlite", "capture.db"}, {"--tls-mode", "invalid"}} {
		app := newDefaultApp()
		if err := app.parseFlags(args); err == nil {
			t.Fatalf("accepted %v", args)
		}
	}
	app := newDefaultApp()
	if err := app.parseFlags([]string{"--capture-tcp-interface", `\Device\NPF_Loopback`}); err != nil {
		t.Fatal(err)
	}
	if app.Config.CaptureTLS || app.Config.CaptureTCPInterface != `\Device\NPF_Loopback` || app.Config.CaptureSQLite != filepath.Join("state", "ja3proxy.db") {
		t.Fatalf("passive TCP capture config = %+v", app.Config)
	}
	app = newDefaultApp()
	if err := app.parseFlags([]string{"--capture-tcp-interface", "loopback", "--capture-jsonl", "packet-observations.jsonl"}); err != nil {
		t.Fatalf("JSONL output for passive capture: %v", err)
	}
	app = newDefaultApp()
	if err := app.parseFlags([]string{"--list-capture-interfaces"}); err != nil || !app.Config.ListCaptureInterfaces {
		t.Fatalf("capture interface listing config = %+v, error = %v", app.Config, err)
	}
	app = newDefaultApp()
	if err := app.parseFlags([]string{"--capture-tls", "--capture-raw", "--tls-mode", "passthrough"}); err != nil {
		t.Fatal(err)
	}
	if !app.Config.CaptureTLS || !app.Config.CaptureRaw || app.Config.TLSMode != "PASSTHROUGH" {
		t.Fatal("recorder flags")
	}
	app = newDefaultApp()
	if err := app.parseFlags([]string{"--capture-tls", "--capture-sqlite", "capture.db"}); err != nil {
		t.Fatal(err)
	}
	if app.Config.CaptureSQLite != "capture.db" {
		t.Fatalf("sqlite path = %q", app.Config.CaptureSQLite)
	}
	if app.Config.StateSQLite != "capture.db" {
		t.Fatalf("shared sqlite path = %q", app.Config.StateSQLite)
	}
	app = newDefaultApp()
	if err := app.parseFlags([]string{"--capture-tls", "--capture-sqlite", "capture.db", "--capture-sqlite-retention", "42"}); err != nil {
		t.Fatal(err)
	}
	if app.Config.CaptureSQLiteRetention != 42 {
		t.Fatalf("sqlite retention = %d", app.Config.CaptureSQLiteRetention)
	}
	app = newDefaultApp()
	if err := app.parseFlags([]string{"--audit-sqlite", "audit.db"}); err != nil {
		t.Fatal(err)
	}
	if app.Config.AuditSQLite != "audit.db" {
		t.Fatalf("audit sqlite path = %q", app.Config.AuditSQLite)
	}
	if app.Config.StateSQLite != "audit.db" {
		t.Fatalf("shared sqlite path = %q", app.Config.StateSQLite)
	}
	if err := newDefaultApp().parseFlags([]string{"--capture-tls", "--capture-sqlite", "capture.db", "--audit-sqlite", "audit.db"}); err == nil {
		t.Fatal("accepted different paths for shared SQLite stores")
	}
	app = newDefaultApp()
	if err := app.parseFlags([]string{"--audit-log", "audit.jsonl", "--audit-sqlite", "audit.db"}); err != nil {
		t.Fatalf("accepted one-time audit import into the selected shared database: %v", err)
	}
	if app.Config.StateSQLite != "audit.db" || app.Config.AuditLog != "audit.jsonl" {
		t.Fatalf("audit migration config = %+v", app.Config)
	}
	app = newDefaultApp()
	if err := app.parseFlags([]string{
		"--capture-tls", "--capture-sqlite", "capture.db",
		"--capture-spool", "capture-spool", "--capture-spool-key", "spool.key",
		"--capture-spool-max-bytes", "1048576", "--capture-spool-key-max-age", "8760h",
	}); err != nil {
		t.Fatalf("parse encrypted spool flags: %v", err)
	}
	if app.Config.CaptureSpool != "capture-spool" || app.Config.CaptureSpoolKey != "spool.key" || app.Config.CaptureSpoolMaxBytes != 1048576 || app.Config.CaptureSpoolKeyMaxAge != 8760*time.Hour {
		t.Fatalf("encrypted spool config = %#v", app.Config)
	}
	for _, args := range [][]string{
		{"--capture-tls", "--capture-sqlite", "capture.db", "--capture-spool", "capture-spool"},
		{"--capture-tls", "--capture-sqlite", "capture.db", "--capture-spool-key", "spool.key"},
		{"--capture-tls", "--capture-sqlite", "capture.db", "--capture-spool", "capture-spool", "--capture-spool-key", "spool.key", "--capture-spool-max-bytes", "0"},
		{"--capture-spool-key-max-age", "8760h"},
		{"--capture-spool-key-max-age", "-1s"},
	} {
		if err := newDefaultApp().parseFlags(args); err == nil {
			t.Fatalf("accepted invalid encrypted spool flags %v", args)
		}
	}
	app = newDefaultApp()
	if err := app.parseFlags([]string{"--device-map-file", "devices.json"}); err != nil {
		t.Fatal(err)
	}
	if app.Config.DeviceMapFile != "devices.json" {
		t.Fatalf("device map path = %q", app.Config.DeviceMapFile)
	}
	app = newDefaultApp()
	if err := app.parseFlags(nil); err != nil {
		t.Fatal(err)
	}
	if app.Config.CaptureTLS {
		t.Fatal("capture unexpectedly enabled")
	}
	if app.Config.StateSQLite != filepath.Join("state", "ja3proxy.db") {
		t.Fatalf("default shared sqlite path = %q", app.Config.StateSQLite)
	}
	app = newDefaultApp()
	if err := app.parseFlags([]string{"--capture-tls"}); err != nil {
		t.Fatal(err)
	}
	if app.Config.CaptureSQLite != filepath.Join("state", "ja3proxy.db") {
		t.Fatalf("default recorder sqlite path = %q", app.Config.CaptureSQLite)
	}
	app = newDefaultApp()
	if err := app.parseFlags([]string{"--capture-tls", "--state-sqlite", filepath.Join("custom", "state.db")}); err != nil {
		t.Fatal(err)
	}
	if app.Config.CaptureSQLite != filepath.Join("custom", "state.db") {
		t.Fatalf("recorder did not use configured shared sqlite path: %q", app.Config.CaptureSQLite)
	}
	app = newDefaultApp()
	if err := app.parseFlags([]string{"--capture-tls", "--capture-spool", "capture-spool", "--capture-spool-key", "spool.key"}); err != nil {
		t.Fatalf("spool should use default shared SQLite database: %v", err)
	}
}
