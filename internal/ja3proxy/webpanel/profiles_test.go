package webpanel

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/lylemi/ja3proxy/internal/ja3proxy/capture/tlshello"
	"github.com/lylemi/ja3proxy/internal/ja3proxy/recorder"
	"github.com/lylemi/ja3proxy/internal/ja3proxy/tlsprofile"
)

func profileRequest(handler http.Handler, method, path string, body any) *httptest.ResponseRecorder {
	var payload bytes.Buffer
	if body != nil {
		_ = json.NewEncoder(&payload).Encode(body)
	}
	request := httptest.NewRequest(method, "http://127.0.0.1"+path, &payload)
	request.RemoteAddr = "127.0.0.1:12000"
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func TestTLSProfileAPIWorkflow(t *testing.T) {
	store, err := tlsprofile.Open(filepath.Join(t.TempDir(), "profiles.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	handler := Server{Profiles: store}.Handler()
	response := profileRequest(handler, http.MethodPost, "/api/v1/tls/profiles/from-preset", map[string]any{
		"name": "Chrome lab", "family_id": "mobile.chrome", "base_preset": map[string]string{"client": "Chrome", "version": "120"}, "host_patterns": []string{"*.example.com"},
	})
	if response.Code != http.StatusOK {
		t.Fatal(response.Body.String())
	}
	var template tlsprofile.Template
	if err := json.Unmarshal(response.Body.Bytes(), &template); err != nil || template.Expected == nil || template.FamilyID != "mobile.chrome" {
		t.Fatal(response.Body.String())
	}
	template.Fields.ALPN = []string{"http/1.1"}
	response = profileRequest(handler, http.MethodPost, "/api/v1/tls/profiles/preview", template)
	if response.Code != http.StatusOK {
		t.Fatal(response.Body.String())
	}
	if err := json.Unmarshal(response.Body.Bytes(), &template); err != nil || template.Expected == nil {
		t.Fatal(response.Body.String())
	}
	response = profileRequest(handler, http.MethodPost, "/api/v1/tls/profiles", map[string]any{"expected_version": 0, "template": template})
	if response.Code != http.StatusCreated {
		t.Fatal(response.Body.String())
	}
	var created struct {
		Template tlsprofile.Template `json:"template"`
		Library  tlsprofile.Library  `json:"library"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	response = profileRequest(handler, http.MethodPut, "/api/v1/tls/profiles/active", map[string]any{"expected_version": created.Library.ConfigVersion, "id": created.Template.ID})
	if response.Code != http.StatusOK {
		t.Fatal(response.Body.String())
	}
	response = profileRequest(handler, http.MethodPut, "/api/v1/tls/profiles/active", map[string]any{"expected_version": 0, "id": created.Template.ID})
	if response.Code != http.StatusConflict {
		t.Fatalf("stale update status = %d: %s", response.Code, response.Body.String())
	}
	response = profileRequest(handler, http.MethodGet, "/api/v1/tls/profiles", nil)
	if response.Code != http.StatusOK || !bytes.Contains(response.Body.Bytes(), []byte(created.Template.ID)) {
		t.Fatal(response.Body.String())
	}
	response = profileRequest(handler, http.MethodDelete, "/api/v1/tls/profiles/"+created.Template.ID, map[string]any{"expected_version": created.Library.ConfigVersion + 1})
	if response.Code != http.StatusBadRequest {
		t.Fatalf("active delete status = %d: %s", response.Code, response.Body.String())
	}
	response = profileRequest(handler, http.MethodPut, "/api/v1/tls/profiles/active", map[string]any{"expected_version": created.Library.ConfigVersion + 1, "id": ""})
	if response.Code != http.StatusOK {
		t.Fatal(response.Body.String())
	}
	response = profileRequest(handler, http.MethodDelete, "/api/v1/tls/profiles/"+created.Template.ID, map[string]any{"expected_version": created.Library.ConfigVersion + 2})
	if response.Code != http.StatusOK || bytes.Contains(response.Body.Bytes(), []byte(created.Template.ID)) {
		t.Fatalf("delete response = %d: %s", response.Code, response.Body.String())
	}
}

func TestFingerprintFamiliesAPIIncludesExplicitProfileLinks(t *testing.T) {
	store, err := tlsprofile.Open("")
	if err != nil {
		t.Fatal(err)
	}
	var firstProfileID string
	for _, preset := range []struct{ client, version, name string }{
		{"Chrome", "120", "Chrome initial"}, {"Chrome", "120", "Chrome resumed"},
	} {
		template, err := tlsprofile.TemplateFromPreset(preset.name, preset.client, preset.version)
		if err != nil {
			t.Fatal(err)
		}
		template.FamilyID = "mobile.chrome"
		created, _, err := store.Create(template, store.Snapshot().ConfigVersion)
		if err != nil {
			t.Fatal(err)
		}
		if firstProfileID == "" {
			firstProfileID = created.ID
		}
	}
	r, err := recorder.New(recorder.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if !r.TryCapture(recorder.Meta{
		ConnectionID: "profile-family-observation", ResolvedDeviceID: "device-1",
		ApplicationID: "app-1", Application: "Example", CapturePoint: "CLIENT_IN",
		Direction: "inbound", ProfileID: firstProfileID, ProfileVersion: 3,
	}, reparseCapture()) {
		t.Fatal("enqueue family-linked observation")
	}
	deadline := time.Now().Add(time.Second)
	for r.Stats().Processed == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	response := requestRecorder(Server{Recorder: r, Profiles: store}.Handler(), "/api/v1/fingerprint-families")
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	var result struct {
		ProfileFamilies []managedProfileFamily `json:"profile_families"`
		Items           []fingerprintFamily    `json:"items"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if len(result.ProfileFamilies) != 1 || result.ProfileFamilies[0].FamilyID != "mobile.chrome" || len(result.ProfileFamilies[0].Profiles) != 2 {
		t.Fatalf("explicit family response = %+v", result.ProfileFamilies)
	}
	if len(result.Items) != 1 || len(result.Items[0].Variants) != 1 || result.Items[0].Variants[0].ProfileFamilyID != "mobile.chrome" {
		t.Fatalf("observation was not linked to its explicit profile family: %+v", result.Items)
	}
}

func TestRandomizedTLSProfileCanBeSavedAndActivated(t *testing.T) {
	store, err := tlsprofile.Open(filepath.Join(t.TempDir(), "profiles.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	handler := Server{Profiles: store}.Handler()
	profile := map[string]any{
		"name": "Randomized lab", "enabled": true, "profile_type": "RANDOMIZED",
		"randomized_alpn": "REQUIRED", "base_preset": map[string]any{},
		"fields": map[string]any{}, "policy": map[string]any{}, "host_patterns": []string{"random.example.com"},
	}
	response := profileRequest(handler, http.MethodPost, "/api/v1/tls/profiles/preview", profile)
	if response.Code != http.StatusOK {
		t.Fatal(response.Body.String())
	}
	var preview tlsprofile.Template
	if err := json.Unmarshal(response.Body.Bytes(), &preview); err != nil {
		t.Fatal(err)
	}
	if preview.Expected != nil || preview.Replayability.Status != "NON_DETERMINISTIC" {
		t.Fatalf("randomized preview has a static fingerprint: %+v", preview)
	}
	response = profileRequest(handler, http.MethodPost, "/api/v1/tls/profiles", map[string]any{"expected_version": 0, "template": preview})
	if response.Code != http.StatusCreated {
		t.Fatal(response.Body.String())
	}
	var result struct {
		Template tlsprofile.Template `json:"template"`
		Library  tlsprofile.Library  `json:"library"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	response = profileRequest(handler, http.MethodPut, "/api/v1/tls/profiles/active", map[string]any{
		"expected_version": result.Library.ConfigVersion, "id": result.Template.ID,
	})
	if response.Code != http.StatusOK {
		t.Fatalf("randomized profile activation failed: %s", response.Body.String())
	}
	resolved, _, ok := store.ResolveWithVersion("random.example.com")
	if !ok || resolved.ProfileType != tlsprofile.ProfileTypeRandomized || resolved.RandomizedALPN != tlsprofile.RandomizedALPNRequired {
		t.Fatalf("unexpected resolved profile: %+v, found=%v", resolved, ok)
	}
}

func TestTLSProfileMultiActivationAPI(t *testing.T) {
	store, err := tlsprofile.Open("")
	if err != nil {
		t.Fatal(err)
	}
	first, err := tlsprofile.TemplateFromPreset("wildcard", "Chrome", "120")
	if err != nil {
		t.Fatal(err)
	}
	first.HostPatterns = []string{"*.example.com"}
	createdFirst, library, err := store.Create(first, 0)
	if err != nil {
		t.Fatal(err)
	}
	second, err := tlsprofile.TemplateFromPreset("exact", "Firefox", "105")
	if err != nil {
		t.Fatal(err)
	}
	second.HostPatterns = []string{"api.example.com"}
	createdSecond, library, err := store.Create(second, library.ConfigVersion)
	if err != nil {
		t.Fatal(err)
	}
	response := profileRequest(Server{Profiles: store}.Handler(), http.MethodPut, "/api/v1/tls/profiles/active", map[string]any{
		"expected_version": library.ConfigVersion,
		"ids":              []string{createdFirst.ID, createdSecond.ID},
	})
	if response.Code != http.StatusOK {
		t.Fatal(response.Body.String())
	}
	var activated tlsprofile.Library
	if err := json.Unmarshal(response.Body.Bytes(), &activated); err != nil {
		t.Fatal(err)
	}
	if len(activated.ActiveIDs) != 2 || activated.ActiveID != "" {
		t.Fatalf("multi-activation response = %+v", activated)
	}
	if resolved, ok := store.Resolve("api.example.com"); !ok || resolved.ID != createdSecond.ID {
		t.Fatalf("exact profile selection = %+v, ok=%v", resolved, ok)
	}
}

func TestTLSProfilePreviewFromObservation(t *testing.T) {
	template, err := tlsprofile.TemplateFromPreset("observed", "Chrome", "120")
	if err != nil {
		t.Fatal(err)
	}
	materialized, err := tlsprofile.Materialize(template, "example.com")
	if err != nil {
		t.Fatal(err)
	}
	recording, err := recorder.New(recorder.Options{})
	if err != nil {
		t.Fatal(err)
	}
	recording.TryCapture(recorder.Meta{ConnectionID: recorder.NewID()}, tlshello.Capture{Status: "complete", Raw: materialized.Raw})
	if err := recording.Close(); err != nil {
		t.Fatal(err)
	}
	observations := recording.Snapshot()
	if len(observations) != 1 {
		t.Fatalf("observations = %d", len(observations))
	}
	store, err := tlsprofile.Open("")
	if err != nil {
		t.Fatal(err)
	}
	handler := Server{Profiles: store, Recorder: recording}.Handler()
	response := profileRequest(handler, http.MethodPost, "/api/v1/tls/profiles/from-observation", map[string]any{
		"save": false, "observation_id": observations[0].ID, "name": "Из наблюдения",
		"base_preset": map[string]string{"client": "Chrome", "version": "120"},
	})
	if response.Code != http.StatusOK {
		t.Fatal(response.Body.String())
	}
	var observed tlsprofile.Template
	if err := json.Unmarshal(response.Body.Bytes(), &observed); err != nil {
		t.Fatal(err)
	}
	if observed.SourceObservationID != observations[0].ID || observed.Expected == nil || observed.Replayability.Status == "UNSUPPORTED" {
		t.Fatalf("unexpected observed template: %+v", observed)
	}
}

func TestTLSProfileHistoryAndRollbackAPI(t *testing.T) {
	store, err := tlsprofile.Open("")
	if err != nil {
		t.Fatal(err)
	}
	template, err := tlsprofile.TemplateFromPreset("v1", "Chrome", "120")
	if err != nil {
		t.Fatal(err)
	}
	created, library, err := store.Create(template, 0)
	if err != nil {
		t.Fatal(err)
	}
	template.Name = "v2"
	updated, library, err := store.Update(created.ID, template, library.ConfigVersion)
	if err != nil || updated.Version != 2 {
		t.Fatal(err)
	}
	handler := Server{Profiles: store}.Handler()
	response := profileRequest(handler, http.MethodGet, "/api/v1/tls/profiles/"+created.ID+"/versions", nil)
	if response.Code != http.StatusOK {
		t.Fatal(response.Body.String())
	}
	var history []tlsprofile.Template
	if err := json.Unmarshal(response.Body.Bytes(), &history); err != nil || len(history) != 2 {
		t.Fatal(response.Body.String())
	}
	response = profileRequest(handler, http.MethodPost, "/api/v1/tls/profiles/"+created.ID+"/rollback", map[string]any{"expected_version": library.ConfigVersion, "target_version": 1})
	if response.Code != http.StatusOK {
		t.Fatal(response.Body.String())
	}
	var result struct {
		Template tlsprofile.Template `json:"template"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil || result.Template.Version != 3 || result.Template.BasedOnVersion != 1 || result.Template.Name != "v1" {
		t.Fatal(response.Body.String())
	}
}
