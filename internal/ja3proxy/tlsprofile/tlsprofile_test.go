package tlsprofile

import (
	"encoding/json"
	"errors"
	"path/filepath"
	"reflect"
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

func TestTemplateConstraintsAreValidated(t *testing.T) {
	template, err := TemplateFromPreset("Chrome", "Chrome", "120")
	if err != nil {
		t.Fatal(err)
	}
	template.Policy.Constraints = []Constraint{{Path: "/legacy_version", Operator: "one_of", Values: []json.RawMessage{json.RawMessage(`771`)}}}
	preview, err := Preview(template)
	if err != nil || preview.Replayability.Status == "UNSUPPORTED" {
		t.Fatalf("valid constraint rejected: %+v, %v", preview, err)
	}
	template.Policy.Constraints = []Constraint{{Path: "/legacy_version", Operator: "unknown"}}
	if _, err := Preview(template); err == nil {
		t.Fatal("unknown constraint operator was accepted")
	}
}

func TestObservedSourceMustMatchIsCheckedBeforePublish(t *testing.T) {
	template, err := TemplateFromPreset("Chrome", "Chrome", "120")
	if err != nil {
		t.Fatal(err)
	}
	altered := append(json.RawMessage(nil), template.Expected.Normalized...)
	var normalized map[string]any
	if err := json.Unmarshal(altered, &normalized); err != nil {
		t.Fatal(err)
	}
	normalized["ciphers"] = []any{float64(4865)}
	altered, _ = json.Marshal(normalized)
	template.Source = &ObservedSource{ObservationID: "source", ServerName: "example.com", Normalized: altered, NormalizationVersion: template.Expected.NormalizationVersion}
	preview, err := Preview(template)
	if err != nil {
		t.Fatal(err)
	}
	if preview.Replayability.Status != "UNSUPPORTED" || len(preview.Replayability.Unsupported) == 0 {
		t.Fatalf("source mismatch was hidden: %+v", preview.Replayability)
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

func TestALPNPolicies(t *testing.T) {
	base := Template{Fields: StaticFields{ALPN: []string{"h2", "http/1.1"}}}
	tests := []struct {
		name    string
		policy  string
		custom  []string
		offered []string
		want    []string
	}{
		{name: "profile", policy: ALPNPolicyProfile, offered: []string{"http/1.1"}, want: []string{"h2", "http/1.1"}},
		{name: "downstream", policy: ALPNPolicyDownstream, offered: []string{"http/1.1"}, want: []string{"http/1.1"}},
		{name: "intersection", policy: ALPNPolicyIntersection, offered: []string{"http/1.1", "h2"}, want: []string{"h2", "http/1.1"}},
		{name: "custom", policy: ALPNPolicyCustom, custom: []string{"acme/1"}, offered: []string{"http/1.1"}, want: []string{"acme/1"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			template := base
			template.Fields.ALPNPolicy = tt.policy
			template.Fields.CustomALPN = tt.custom
			got, err := ConstrainALPN(template, tt.offered)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got.Fields.ALPN, tt.want) {
				t.Fatalf("effective ALPN = %v, want %v", got.Fields.ALPN, tt.want)
			}
		})
	}
	if _, err := ConstrainALPN(Template{Fields: StaticFields{ALPNPolicy: ALPNPolicyCustom, ALPN: base.Fields.ALPN}}, nil); err == nil {
		t.Fatal("CUSTOM policy without custom_alpn was accepted")
	}
	if _, err := ConstrainALPN(Template{Fields: StaticFields{ALPNPolicy: "INVALID", ALPN: base.Fields.ALPN}}, nil); err == nil {
		t.Fatal("invalid ALPN policy was accepted")
	}
}

func TestCustomALPNPolicyMaterializesConfiguredProtocols(t *testing.T) {
	template, err := TemplateFromPreset("custom-alpn", "Chrome", "120")
	if err != nil {
		t.Fatal(err)
	}
	template.Fields.ALPNPolicy = ALPNPolicyCustom
	template.Fields.CustomALPN = []string{"http/1.1"}
	preview, err := Preview(template)
	if err != nil {
		t.Fatal(err)
	}
	if preview.Expected == nil || preview.Fields.ALPNPolicy != ALPNPolicyCustom || !reflect.DeepEqual(preview.Fields.CustomALPN, []string{"http/1.1"}) {
		t.Fatalf("custom ALPN preview = %+v", preview)
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
	edited := created
	edited.Name = "lab edited"
	edited, library, err = store.Update(created.ID, edited, library.ConfigVersion)
	if err != nil || edited.Version != 2 || edited.BasedOnVersion != 1 {
		t.Fatalf("update = %+v, %+v, %v", edited, library, err)
	}
	rolledBack, library, err := store.Rollback(created.ID, 1, library.ConfigVersion)
	if err != nil || rolledBack.Version != 3 || rolledBack.BasedOnVersion != 1 || rolledBack.Name != created.Name {
		t.Fatalf("rollback = %+v, %+v, %v", rolledBack, library, err)
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
	if history := reopened.History(created.ID); len(history) != 3 || history[0].Version != 1 || history[2].Version != 3 {
		t.Fatalf("immutable history mismatch: %+v", history)
	}
}
