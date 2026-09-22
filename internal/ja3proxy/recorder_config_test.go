package ja3proxy

import "testing"

func TestRecorderCLI(t *testing.T) {
	for _, args := range [][]string{{"--capture-raw"}, {"--capture-jsonl", "capture.jsonl"}, {"--tls-mode", "invalid"}} {
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
	if err := app.parseFlags(nil); err != nil {
		t.Fatal(err)
	}
	if app.Config.CaptureTLS {
		t.Fatal("capture unexpectedly enabled")
	}
}
