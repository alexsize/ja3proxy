package webpanel

import (
	"encoding/binary"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/lylemi/ja3proxy/internal/ja3proxy/capture/tlshello"
	"github.com/lylemi/ja3proxy/internal/ja3proxy/recorder"
	"github.com/lylemi/ja3proxy/internal/ja3proxy/tlsprofile"
)

func TestReplayLabRunsLocalTLSAndComparesWire(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer server.Close()
	hostPort := strings.TrimPrefix(server.URL, "https://")
	host, portText, err := net.SplitHostPort(hostPort)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatal(err)
	}

	store, err := tlsprofile.Open("")
	if err != nil {
		t.Fatal(err)
	}
	profile, err := tlsprofile.TemplateFromPreset("Chrome 120", "Chrome", "120")
	if err != nil {
		t.Fatal(err)
	}
	created, _, err := store.Create(profile, 0)
	if err != nil {
		t.Fatal(err)
	}

	materialized, err := tlsprofile.Materialize(profile, host)
	if err != nil {
		t.Fatal(err)
	}
	records := make([]byte, 5+len(materialized.Raw))
	records[0] = 22
	binary.BigEndian.PutUint16(records[1:3], materialized.Hello.LegacyVersion)
	binary.BigEndian.PutUint16(records[3:5], uint16(len(materialized.Raw)))
	copy(records[5:], materialized.Raw)
	recording, err := recorder.New(recorder.Options{Raw: true})
	if err != nil {
		t.Fatal(err)
	}
	if !recording.TryCapture(recorder.Meta{CapturePoint: "CLIENT_IN", Direction: "inbound"}, tlshello.Capture{
		Status: "complete", Raw: materialized.Raw, Records: records, RecordVersion: materialized.Hello.LegacyVersion, RecordCount: 1,
	}) {
		t.Fatal("enqueue reference observation")
	}
	if err := recording.Close(); err != nil {
		t.Fatal(err)
	}
	reference := recording.Snapshot()[0]

	handler := Server{Profiles: store, Recorder: recording}.Handler()
	response := profileRequest(handler, http.MethodPost, "/api/v1/replay-lab/run", map[string]any{
		"profile_id": created.ID, "observation_id": reference.ID,
		"target_host": host, "target_port": port, "server_name": "localhost", "timeout_ms": 5000,
	})
	if response.Code != http.StatusOK {
		t.Fatalf("Replay Lab returned %d: %s", response.Code, response.Body.String())
	}
	var result replayLabResult
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.Status != "OK" || result.Actual == nil || result.Compiled.Fingerprint == nil || !result.ServerResponse.HandshakeComplete {
		t.Fatalf("incomplete Replay Lab result: %+v", result)
	}
	if result.ServerResponse.ServerHello == nil || result.ServerResponse.Fingerprints == nil {
		t.Fatalf("Replay Lab omitted captured ServerHello response: %+v", result.ServerResponse)
	}
	if _, ok := result.Diff["captured_vs_actual"]; !ok {
		t.Fatalf("captured fingerprint comparison is missing: %+v", result.Diff)
	}
	if _, ok := result.Diff["compiled_vs_actual"]; !ok {
		t.Fatalf("compiled fingerprint comparison is missing: %+v", result.Diff)
	}
	if result.Compatibility == "" {
		t.Fatalf("successful saved-profile replay did not record engine compatibility: %+v", result)
	}
	if result.PolicyVerification == nil || result.PolicyVerification.Status == "" {
		t.Fatalf("successful replay did not return MUST/SHOULD policy verification: %+v", result)
	}
	validated, ok := store.Get(created.ID)
	if !ok || validated.LastValidatedWithUTLS == "" || validated.CompatibilityStatus == tlsprofile.CompatibilityNotValidated {
		t.Fatalf("replay result was not persisted to profile: %+v", validated)
	}
}

func TestReplayLabRejectsMissingOrMultipleProfileSources(t *testing.T) {
	handler := Server{}.Handler()
	for _, body := range []map[string]any{
		{"target_host": "127.0.0.1"},
		{"profile_type": "RANDOMIZED", "profile_id": "conflict", "target_host": "127.0.0.1"},
	} {
		response := profileRequest(handler, http.MethodPost, "/api/v1/replay-lab/run", body)
		if response.Code != http.StatusBadRequest {
			t.Fatalf("source validation status = %d, body=%s", response.Code, response.Body.String())
		}
	}
}

func TestReplayLabRandomizedReturnsActualWireFingerprint(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer server.Close()
	host, portText, err := net.SplitHostPort(strings.TrimPrefix(server.URL, "https://"))
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatal(err)
	}
	handler := Server{}.Handler()
	response := profileRequest(handler, http.MethodPost, "/api/v1/replay-lab/run", map[string]any{
		"profile_type": "RANDOMIZED", "randomized_alpn": "REQUIRED",
		"target_host": host, "target_port": port, "server_name": "localhost", "timeout_ms": 5000,
	})
	if response.Code != http.StatusOK {
		t.Fatalf("Replay Lab returned %d: %s", response.Code, response.Body.String())
	}
	var result replayLabResult
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.Status != "OK" || result.Compiled.Status != "NON_DETERMINISTIC" || result.Compiled.Fingerprint != nil || result.Actual == nil || result.Actual.JA4 == "" {
		t.Fatalf("randomized run did not return the wire fingerprint: %+v", result)
	}
}
