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
