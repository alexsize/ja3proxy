package ja3proxy

import "testing"

func TestRecorderCLI(t *testing.T) {
	for _, args := range [][]string{{"--capture-raw"}, {"--capture-jsonl", "capture.jsonl"}, {"--capture-sqlite", "capture.db"}, {"--tls-mode", "invalid"}} {
		app := newDefaultApp()
		if err := app.parseFlags(args); err == nil {
			t.Fatalf("accepted %v", args)
		}
	}
	app := newDefaultApp()
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
	app = newDefaultApp()
	if err := app.parseFlags([]string{"--capture-tls", "--capture-sqlite", "capture.db", "--capture-sqlite-retention", "42"}); err != nil {
		t.Fatal(err)
	}
	if app.Config.CaptureSQLiteRetention != 42 {
		t.Fatalf("sqlite retention = %d", app.Config.CaptureSQLiteRetention)
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
}
