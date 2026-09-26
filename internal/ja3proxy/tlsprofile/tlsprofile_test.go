package tlsprofile

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/lylemi/ja3proxy/internal/ja3proxy/state"
	utls "github.com/refraction-networking/utls"
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

func TestRandomizedProfileHasNoStaticExpectedFingerprint(t *testing.T) {
	for _, test := range []struct {
		mode string
		want utls.ClientHelloID
	}{
		{RandomizedALPNAuto, utls.HelloRandomized},
		{RandomizedALPNRequired, utls.HelloRandomizedALPN},
		{RandomizedALPNDisabled, utls.HelloRandomizedNoALPN},
	} {
		template, err := TemplateFromRandomized("Случайный", test.mode)
		if err != nil {
			t.Fatalf("create randomized profile %s: %v", test.mode, err)
		}
		if template.ProfileType != ProfileTypeRandomized || template.Expected != nil || template.Replayability.Status != "NON_DETERMINISTIC" {
			t.Fatalf("unexpected randomized preview: %+v", template)
		}
		materialized, err := Materialize(template, "example.com")
		if err != nil {
			t.Fatalf("materialize randomized profile %s: %v", test.mode, err)
		}
		if materialized.RandomizedID == nil || materialized.RandomizedID.Client != test.want.Client || materialized.RandomizedID.Version != test.want.Version || materialized.RandomizedID.Weights == nil || materialized.Spec != nil {
			t.Fatalf("mode %s selected wrong uTLS generator: %+v", test.mode, materialized)
		}
	}
}

func TestRandomizedProfileRejectsUnknownALPNMode(t *testing.T) {
	_, err := TemplateFromRandomized("Случайный", "SOMETIMES")
	if err == nil {
		t.Fatal("unknown randomized ALPN mode was accepted")
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

func TestStrictProfileRejectsProtocolConflictWithoutMutation(t *testing.T) {
	template := Template{
		ProfileMode: ProfileModeStrict,
		Fields:      StaticFields{ALPN: []string{"h2", "http/1.1"}, ALPS: []string{"h2"}},
	}
	if _, _, err := ConstrainALPNAudited(template, []string{"http/1.1"}); !errors.Is(err, ErrProtocolConflict) {
		t.Fatalf("strict mode error = %v, want PROFILE_PROTOCOL_CONFLICT", err)
	}
	if !reflect.DeepEqual(template.Fields.ALPN, []string{"h2", "http/1.1"}) || !reflect.DeepEqual(template.Fields.ALPS, []string{"h2"}) {
		t.Fatalf("strict conflict mutated source template: %+v", template.Fields)
	}
	alpsConflict := Template{ProfileMode: ProfileModeStrict, Fields: StaticFields{
		ALPN: []string{"http/1.1"}, ALPS: []string{"h2"}, ALPSPolicy: ALPSPolicyIntersection,
	}}
	if _, _, err := ConstrainALPNAudited(alpsConflict, []string{"http/1.1"}); !errors.Is(err, ErrProtocolConflict) {
		t.Fatalf("strict ALPS error = %v, want PROFILE_PROTOCOL_CONFLICT", err)
	}
}

func TestStrictRandomizedProfileIsRejected(t *testing.T) {
	template, err := TemplateFromRandomized("Randomized", RandomizedALPNAuto)
	if err != nil {
		t.Fatal(err)
	}
	template.ProfileMode = ProfileModeStrict
	if _, err := Preview(template); !errors.Is(err, ErrProtocolConflict) {
		t.Fatalf("STRICT RANDOMIZED preview error = %v, want PROFILE_PROTOCOL_CONFLICT", err)
	}
	if _, err := Materialize(template, "example.test"); !errors.Is(err, ErrProtocolConflict) {
		t.Fatalf("STRICT RANDOMIZED materialization error = %v, want PROFILE_PROTOCOL_CONFLICT", err)
	}
}

func TestStrictCompatiblePresetMaterializesWithoutMutation(t *testing.T) {
	template, err := TemplateFromPreset("Chrome", "Chrome", "120")
	if err != nil {
		t.Fatal(err)
	}
	template.ProfileMode = ProfileModeStrict
	materialized, err := Materialize(template, "example.test")
	if err != nil {
		t.Fatal(err)
	}
	if len(materialized.RuntimeMutations) != 0 {
		t.Fatalf("compatible STRICT preset mutated: %+v", materialized.RuntimeMutations)
	}
}

func TestMaterializationAuditsExtensionChangeAndStrictRejectsIt(t *testing.T) {
	template, err := TemplateFromPreset("Chrome with ALPS", "Chrome", "120")
	if err != nil {
		t.Fatal(err)
	}
	if !containsALPSExtension(template.Fields.ExtensionOrder) {
		t.Fatal("test preset has no ALPS extension")
	}
	// The engine omits ApplicationSettings when there are no ALPS protocols,
	// even though the extension remains in the edited template.
	template.Fields.ALPS = nil
	materialized, err := Materialize(template, "example.test")
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, mutation := range materialized.RuntimeMutations {
		if mutation.Field == "EXTENSIONS" && len(mutation.Before) > len(mutation.After) && mutation.Reason != "" {
			found = true
		}
	}
	if !found {
		t.Fatalf("missing extension mutation: %+v", materialized.RuntimeMutations)
	}
	template.ProfileMode = ProfileModeStrict
	if _, err := Materialize(template, "example.test"); !errors.Is(err, ErrProtocolConflict) {
		t.Fatalf("STRICT materialization error = %v, want PROFILE_PROTOCOL_CONFLICT", err)
	}
}

func TestOpenRepairsLegacyHexALPSWithoutChangingSourceHistory(t *testing.T) {
	template, err := TemplateFromPreset("Chrome", "Chrome", "120")
	if err != nil {
		t.Fatal(err)
	}
	if len(template.Fields.ALPS) == 0 {
		t.Fatal("test preset has no ALPS protocols")
	}
	template.ID = "legacy-alps"
	template.Version = 1
	for i, protocol := range template.Fields.ALPS {
		template.Fields.ALPS[i] = hex.EncodeToString([]byte(protocol))
	}
	old, err := Preview(template)
	if err != nil {
		t.Fatal(err)
	}
	library := Library{SchemaVersion: SchemaVersion, ConfigVersion: 1, Templates: []Template{old}}
	encoded, err := json.Marshal(library)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "legacy-profiles.jsonl")
	original := append(encoded, '\n')
	if err := os.WriteFile(path, original, 0o600); err != nil {
		t.Fatal(err)
	}
	store, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	current := store.Snapshot().Templates[0]
	if !reflect.DeepEqual(current.Fields.ALPS, []string{"h2"}) || current.Expected == nil || old.Expected == nil || current.Expected.NormalizedSHA256 == old.Expected.NormalizedSHA256 {
		t.Fatalf("legacy ALPS was not repaired with refreshed expected fingerprint: %+v", current)
	}
	if history := store.History(template.ID); len(history) != 1 || !reflect.DeepEqual(history[0].Fields.ALPS, []string{"h2"}) {
		t.Fatalf("loaded profile history was not normalized: %+v", history)
	}
	if persisted, err := os.ReadFile(path); err != nil || !reflect.DeepEqual(persisted, original) {
		t.Fatalf("immutable legacy source was modified: %v", err)
	}
	databasePath := filepath.Join(t.TempDir(), "state.db")
	database, err := state.OpenSQLite(databasePath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenWithState(path, database); err != nil {
		t.Fatal(err)
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}
	database, err = state.OpenSQLite(databasePath)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	fromSQLite, err := OpenWithState("", database)
	if err != nil {
		t.Fatal(err)
	}
	if got := fromSQLite.Snapshot().Templates[0].Fields.ALPS; !reflect.DeepEqual(got, []string{"h2"}) {
		t.Fatalf("SQLite legacy ALPS = %v", got)
	}
}

func TestAdaptiveProfileAuditsEveryProtocolMutation(t *testing.T) {
	template := Template{
		ProfileMode: ProfileModeAdaptive,
		Fields:      StaticFields{ALPN: []string{"h2", "http/1.1"}, ALPS: []string{"h2"}},
	}
	effective, mutations, err := ConstrainALPNAudited(template, []string{"http/1.1"})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(effective.Fields.ALPN, []string{"http/1.1"}) || len(effective.Fields.ALPS) != 0 {
		t.Fatalf("effective protocols = ALPN %v ALPS %v", effective.Fields.ALPN, effective.Fields.ALPS)
	}
	if len(mutations) != 2 || mutations[0].Field != "ALPN" || mutations[1].Field != "ALPS" {
		t.Fatalf("runtime mutations = %+v", mutations)
	}
	for _, mutation := range mutations {
		if mutation.Type != "PROFILE_RUNTIME_MUTATION" || mutation.Reason == "" || mutation.Before == nil || mutation.After == nil {
			t.Fatalf("incomplete runtime mutation audit: %+v", mutation)
		}
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

func TestALPSPolicies(t *testing.T) {
	base := Template{Fields: StaticFields{ALPN: []string{"h2", "http/1.1"}, ALPS: []string{"h2"}}}
	tests := []struct {
		name    string
		policy  string
		custom  []string
		offered []string
		want    []string
	}{
		{name: "profile filters to effective ALPN", policy: ALPSPolicyProfile, offered: []string{"http/1.1"}},
		{name: "downstream", policy: ALPSPolicyDownstream, offered: []string{"h2"}, want: []string{"h2"}},
		{name: "intersection", policy: ALPSPolicyIntersection, offered: []string{"h2", "http/1.1"}, want: []string{"h2"}},
		{name: "custom", policy: ALPSPolicyCustom, custom: []string{"h2"}, offered: []string{"h2"}, want: []string{"h2"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			template := base
			template.Fields.ALPSPolicy = tt.policy
			template.Fields.CustomALPS = tt.custom
			got, err := ConstrainALPN(template, tt.offered)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got.Fields.ALPS, tt.want) {
				t.Fatalf("effective ALPS = %v, want %v", got.Fields.ALPS, tt.want)
			}
		})
	}
	if _, err := ConstrainALPN(Template{Fields: StaticFields{ALPN: []string{"http/1.1"}, ALPS: []string{"h2"}, ALPSPolicy: ALPSPolicyCustom, CustomALPS: []string{"h2"}}}, []string{"http/1.1"}); err == nil {
		t.Fatal("inconsistent CUSTOM ALPS was accepted")
	}
}

func TestALPSCannotOutliveEffectiveALPN(t *testing.T) {
	template, err := TemplateFromPreset("alps", "Chrome", "120")
	if err != nil {
		t.Fatal(err)
	}
	if len(template.Fields.ALPS) == 0 {
		t.Skip("selected uTLS preset has no ALPS extension")
	}
	effective, err := ConstrainALPN(template, []string{"http/1.1"})
	if err != nil {
		t.Fatal(err)
	}
	for _, protocol := range effective.Fields.ALPS {
		if protocol != "http/1.1" {
			t.Fatalf("ALPS protocol %q survived without matching ALPN: %v", protocol, effective.Fields.ALPS)
		}
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
	template.FamilyID = "mobile.chrome"
	created, library, err := store.Create(template, 0)
	if err != nil {
		t.Fatal(err)
	}
	if created.FamilyID != "mobile.chrome" {
		t.Fatalf("explicit family ID was not persisted on create: %+v", created)
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
	if reopened.History(created.ID)[0].FamilyID != "mobile.chrome" || reopened.History(created.ID)[1].FamilyID != "mobile.chrome" {
		t.Fatalf("family ID did not survive version history: %+v", reopened.History(created.ID))
	}
}

func TestTemplateRejectsMalformedExplicitFamilyID(t *testing.T) {
	template, err := TemplateFromPreset("family", "Chrome", "120")
	if err != nil {
		t.Fatal(err)
	}
	for _, familyID := range []string{"bad id", "семейство", "family/one", " padded "} {
		template.FamilyID = familyID
		if _, err := Preview(template); err == nil {
			t.Errorf("invalid family ID %q was accepted", familyID)
		}
	}
}

func TestOpenWithStateImportsLegacySnapshotsAndPreservesProfileHistory(t *testing.T) {
	dir := t.TempDir()
	legacyPath := filepath.Join(dir, "profiles.jsonl")
	databasePath := filepath.Join(dir, "state.db")
	legacyStore, err := Open(legacyPath)
	if err != nil {
		t.Fatal(err)
	}
	template, err := TemplateFromPreset("migration", "Chrome", "120")
	if err != nil {
		t.Fatal(err)
	}
	template.FamilyID = "migration.family"
	created, library, err := legacyStore.Create(template, 0)
	if err != nil {
		t.Fatal(err)
	}
	created.Name = "migration v2"
	if _, _, err := legacyStore.Update(created.ID, created, library.ConfigVersion); err != nil {
		t.Fatal(err)
	}

	database, err := state.OpenSQLite(databasePath)
	if err != nil {
		t.Fatal(err)
	}
	migrated, err := OpenWithState(legacyPath, database)
	if err != nil {
		t.Fatal(err)
	}
	if len(migrated.History(created.ID)) != 2 || migrated.Snapshot().ConfigVersion != 2 {
		t.Fatalf("migrated library = %+v, history = %+v", migrated.Snapshot(), migrated.History(created.ID))
	}
	if err := os.WriteFile(legacyPath, []byte("not valid JSONL"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}
	database, err = state.OpenSQLite(databasePath)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	reopened, err := OpenWithState(legacyPath, database)
	if err != nil {
		t.Fatalf("SQLite snapshots should be primary after migration: %v", err)
	}
	if history := reopened.History(created.ID); len(history) != 2 || history[0].Version != 1 || history[1].Version != 2 || history[0].FamilyID != "migration.family" || history[1].FamilyID != "migration.family" {
		t.Fatalf("restored profile history = %+v", history)
	}
}

func TestStoreResolvesMultipleActiveProfilesByHostPriority(t *testing.T) {
	store, err := Open("")
	if err != nil {
		t.Fatal(err)
	}
	wildcard, err := TemplateFromPreset("wildcard", "Chrome", "120")
	if err != nil {
		t.Fatal(err)
	}
	wildcard.HostPatterns = []string{"*.example.com"}
	wildcard, library, err := store.Create(wildcard, 0)
	if err != nil {
		t.Fatal(err)
	}
	exact, err := TemplateFromPreset("exact", "Firefox", "105")
	if err != nil {
		t.Fatal(err)
	}
	exact.HostPatterns = []string{"api.example.com"}
	exact, library, err = store.Create(exact, library.ConfigVersion)
	if err != nil {
		t.Fatal(err)
	}
	library, err = store.ActivateMany([]string{wildcard.ID, exact.ID}, library.ConfigVersion)
	if err != nil {
		t.Fatal(err)
	}
	if len(library.ActiveIDs) != 2 || library.ActiveID != "" {
		t.Fatalf("active profile set = %+v", library)
	}
	if resolved, ok := store.Resolve("api.example.com"); !ok || resolved.ID != exact.ID {
		t.Fatalf("exact route = %+v, ok=%v", resolved, ok)
	}
	if resolved, ok := store.Resolve("www.example.com"); !ok || resolved.ID != wildcard.ID {
		t.Fatalf("wildcard route = %+v, ok=%v", resolved, ok)
	}
	if resolved, version, ok := store.ResolveByID(wildcard.ID); !ok || resolved.ID != wildcard.ID || version != library.ConfigVersion {
		t.Fatalf("explicit profile route = %+v, version=%d, ok=%v", resolved, version, ok)
	}
	if _, err := store.Delete(exact.ID, library.ConfigVersion); err == nil {
		t.Fatal("active profile was deleted")
	}
}

func TestEngineCompatibilityRequiresReplayAfterUTLSUpgrade(t *testing.T) {
	store, err := Open("")
	if err != nil {
		t.Fatal(err)
	}
	template, err := TemplateFromPreset("Chrome", "Chrome", "120")
	if err != nil {
		t.Fatal(err)
	}
	created, library, err := store.Create(template, 0)
	if err != nil {
		t.Fatal(err)
	}
	if created.CreatedWithUTLS == "" || created.CompatibilityStatus != CompatibilityNotValidated {
		t.Fatalf("profile did not record creation engine: %+v", created)
	}
	created.CreatedWithUTLS = "v0.0.0-old"
	library.Templates[0] = created
	library, err = store.Replace(library, library.ConfigVersion)
	if err != nil {
		t.Fatal(err)
	}
	loaded, ok := store.Get(created.ID)
	if !ok || EngineCompatibility(loaded) != CompatibilityRevalidationRequired {
		t.Fatalf("engine upgrade was not detected: %+v", loaded)
	}
	if _, _, ok := store.ResolveByID(created.ID); ok {
		t.Fatal("profile requiring engine revalidation was resolved")
	}
	if _, err := store.Activate(created.ID, library.ConfigVersion); err == nil {
		t.Fatal("profile requiring engine revalidation was activated")
	}
	validated, _, err := store.RecordCompatibility(created.ID, created.Version, CompatibilityValidWithDifferences)
	if err != nil {
		t.Fatal(err)
	}
	if validated.LastValidatedWithUTLS == "" || EngineCompatibility(validated) != CompatibilityValidWithDifferences {
		t.Fatalf("replay result was not recorded: %+v", validated)
	}
	if _, _, ok := store.ResolveByID(created.ID); !ok {
		t.Fatal("profile validated on current engine was not resolved")
	}
}
