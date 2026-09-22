package tlsprofile

import (
	"errors"
	"path/filepath"
	"testing"
)

func TestPresetPreviewAndJA4Editing(t *testing.T) {
	template, err := TemplateFromPreset("Chrome 120", "Chrome", "120")
	if err != nil {
		t.Fatal(err)
	}
	if template.Expected == nil || template.Expected.JA4 == "" || template.Replayability.Status == "UNSUPPORTED" {
		t.Fatalf("unexpected preview: %+v", template)
	}
	original := template.Expected.JA4
	template.Fields.ALPN = []string{"http/1.1"}
	edited, err := Preview(template)
	if err != nil {
		t.Fatal(err)
	}
	if edited.Expected == nil || edited.Expected.JA4 == original {
		t.Fatalf("JA4 did not change after ALPN edit: %q", original)
	}
}

func TestUnsupportedExtensionIsExplicit(t *testing.T) {
	template, err := TemplateFromPreset("Firefox", "Firefox", "120")
	if err != nil {
		t.Fatal(err)
	}
	template.Fields.ExtensionOrder = append(template.Fields.ExtensionOrder, 65500)
	preview, err := Preview(template)
	if err != nil {
		t.Fatal(err)
	}
	if preview.Replayability.Status != "UNSUPPORTED" || len(preview.Replayability.Unsupported) == 0 || preview.Expected != nil {
		t.Fatalf("unsupported field was hidden: %+v", preview)
	}
}

func TestMissingPolicyPathIsUnsupported(t *testing.T) {
	template, err := TemplateFromPreset("Chrome", "Chrome", "120")
	if err != nil {
		t.Fatal(err)
	}
	template.Policy.MustMatch = []string{"/missing"}
	preview, err := Preview(template)
	if err != nil {
		t.Fatal(err)
	}
	if preview.Replayability.Status != "UNSUPPORTED" || preview.Expected != nil {
		t.Fatalf("invalid policy path was accepted: %+v", preview)
	}
}

func TestConstrainALPNPreservesTemplateOrder(t *testing.T) {
	template := Template{Fields: StaticFields{ALPN: []string{"h2", "http/1.1", "h3"}}}
	effective, err := ConstrainALPN(template, []string{"http/1.1", "h2"})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"h2", "http/1.1"}
	if len(effective.Fields.ALPN) != len(want) || effective.Fields.ALPN[0] != want[0] || effective.Fields.ALPN[1] != want[1] {
		t.Fatalf("effective ALPN = %v, want %v", effective.Fields.ALPN, want)
	}
	if len(template.Fields.ALPN) != 3 {
		t.Fatal("stored template was mutated")
	}
	if _, err := ConstrainALPN(template, []string{"acme/1"}); err == nil {
		t.Fatal("disjoint ALPN was accepted")
	}
}

func TestStoreVersioningPersistenceAndRouting(t *testing.T) {
	path := filepath.Join(t.TempDir(), "profiles.jsonl")
	store, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	template, err := TemplateFromPreset("lab", "Chrome", "120")
	if err != nil {
		t.Fatal(err)
	}
	template.HostPatterns = []string{"*.example.com"}
	created, library, err := store.Create(template, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.Create(template, 0); !errors.Is(err, ErrVersionConflict) {
		t.Fatalf("stale write error = %v", err)
	}
	library, err = store.Activate(created.ID, library.ConfigVersion)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := store.Resolve("api.example.com"); !ok {
		t.Fatal("active wildcard profile did not resolve")
	}
	if _, ok := store.Resolve("example.com"); ok {
		t.Fatal("wildcard matched apex host")
	}
	reopened, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if reopened.Snapshot().ConfigVersion != library.ConfigVersion || reopened.Snapshot().ActiveID != created.ID {
		t.Fatalf("persistence mismatch: %+v", reopened.Snapshot())
	}
}
