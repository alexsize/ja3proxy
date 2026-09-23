package webpanel

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

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
		"name": "Chrome lab", "base_preset": map[string]string{"client": "Chrome", "version": "120"}, "host_patterns": []string{"*.example.com"},
	})
	if response.Code != http.StatusOK {
		t.Fatal(response.Body.String())
	}
	var template tlsprofile.Template
	if err := json.Unmarshal(response.Body.Bytes(), &template); err != nil || template.Expected == nil {
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
