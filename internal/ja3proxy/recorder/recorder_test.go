package recorder

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/lylemi/ja3proxy/internal/ja3proxy/capture/tlshello"
)

func sample() tlshello.Capture {
	raw := []byte{1, 0, 0, 43, 3, 3}
	raw = append(raw, make([]byte, 32)...)
	raw = append(raw, 0, 0, 2, 0x13, 1, 1, 0, 0, 0)
	return tlshello.Capture{Status: "complete", Raw: raw, Records: append([]byte{22, 3, 1, 0, 47}, raw...), RecordVersion: 0x0301, RecordCount: 1}
}

func TestRecorderExportAndPrivacy(t *testing.T) {
	for _, raw := range []bool{false, true} {
		t.Run(map[bool]string{false: "metadata", true: "raw"}[raw], func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "capture.jsonl")
			r, err := New(Options{Raw: raw, JSONLPath: path})
			if err != nil {
				t.Fatal(err)
			}
			id := NewID()
			if !r.TryCapture(Meta{ConnectionID: id, CapturePoint: "CLIENT_IN", Direction: "inbound"}, sample()) {
				t.Fatal("enqueue")
			}
			if err := r.Close(); err != nil {
				t.Fatal(err)
			}
			items := r.Snapshot()
			if len(items) != 1 || items[0].Fingerprints == nil || items[0].Fingerprints.JA4 == "" {
				t.Fatalf("%+v", items)
			}
			if (len(items[0].Raw) > 0) != raw {
				t.Fatal("raw policy")
			}
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			var stored Observation
			if err := json.Unmarshal(bytes.TrimSpace(data), &stored); err != nil {
				t.Fatal(err)
			}
			if stored.ConnectionID != id {
				t.Fatal("wrong file")
			}
			items[0].Fingerprints.JA3 = "mutated"
			if r.Snapshot()[0].Fingerprints.JA3 == "mutated" {
				t.Fatal("snapshot shares mutable data")
			}
			if _, err := New(Options{JSONLPath: path}); err == nil {
				t.Fatal("overwrote evidence")
			}
		})
	}
}

func TestRecorderBoundsAndConcurrentClose(t *testing.T) {
	r, err := New(Options{QueueSize: 8, RecentLimit: 2, MemoryBytes: 8192})
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				r.TryCapture(Meta{ConnectionID: NewID()}, sample())
				r.Snapshot()
			}
		}()
	}
	wg.Add(1)
	go func() { defer wg.Done(); r.Close() }()
	wg.Wait()
	r.Close()
	s := r.Stats()
	if s.Recent > 2 || s.MemoryBytes > 8192 || s.Processed != s.Accepted || s.Dropped == 0 || !s.RecordingDegraded {
		t.Fatalf("%+v", s)
	}
}

func TestQueueOverflowIsNonblocking(t *testing.T) {
	// Deliberately no consumer: the second call must return immediately.
	r := &Recorder{queue: make(chan queued, 1)}
	if !r.TryCapture(Meta{}, sample()) || r.TryCapture(Meta{}, sample()) || r.dropped.Load() != 1 {
		t.Fatal("queue overflow")
	}
}

func TestOutputQuotaAndMalformedCapture(t *testing.T) {
	r, err := New(Options{JSONLPath: filepath.Join(t.TempDir(), "c.jsonl"), MaxFileBytes: 1})
	if err != nil {
		t.Fatal(err)
	}
	r.TryCapture(Meta{}, tlshello.Capture{Status: "complete", Raw: []byte{1, 2, 3}})
	r.TryCapture(Meta{}, tlshello.Capture{Status: "complete", Raw: []byte{1, 2, 3}})
	if err := r.Close(); err == nil {
		t.Fatal("output quota reported success")
	}
	o := r.Snapshot()[0]
	if o.Completeness != "malformed" || o.Fingerprints != nil || r.Stats().WriteErrors != 1 {
		t.Fatalf("%+v", o)
	}
}

func TestULID(t *testing.T) {
	seen := map[string]bool{}
	const alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
	for i := 0; i < 10000; i++ {
		id := NewID()
		if len(id) != 26 || id[0] > '7' || seen[id] {
			t.Fatal("invalid/colliding ULID")
		}
		for _, ch := range id {
			if !strings.ContainsRune(alphabet, ch) {
				t.Fatal("alphabet")
			}
		}
		seen[id] = true
	}
}

func obs(norm string) Observation {
	return Observation{Completeness: "complete", Fingerprints: &tlshello.Fingerprints{Normalized: json.RawMessage(norm), NormalizationVersion: "TLS-NORM-1"}}
}
func TestDiff(t *testing.T) {
	a := obs(`{"ciphers":[1,2,3],"old":1,"nested":{"a/b":1}}`)
	b := obs(`{"ciphers":[3,1,2],"new":2,"nested":{"a/b":2}}`)
	diff := Compare(a, b)
	if diff.Status != "MISMATCH" {
		t.Fatal(diff)
	}
	got, _ := json.Marshal(diff.Changes)
	want := `[{"op":"move","path":"/ciphers/0","from":"/ciphers/2"},{"op":"replace","path":"/nested/a~1b","before":1,"after":2},{"op":"add","path":"/new","after":2},{"op":"remove","path":"/old","before":1}]`
	if string(got) != want {
		t.Fatal(string(got))
	}
	if Compare(a, a).Status != "MATCH" {
		t.Fatal("equal mismatch")
	}
	b.Fingerprints.NormalizationVersion = "TLS-NORM-2"
	if Compare(a, b).Status != "UNKNOWN" {
		t.Fatal("version mismatch not unknown")
	}
	if Compare(a, Observation{}).Status != "UNKNOWN" {
		t.Fatal("missing capture not unknown")
	}
}

func TestExpectedProfileVerificationStatuses(t *testing.T) {
	normalized := json.RawMessage(`{"ciphers":[1,2],"extensions":[{"id":0}],"legacy_version":771,"session_id_length":32}`)
	expected := FingerprintExpected{
		ProfileSchemaVersion: SupportedProfileSchemaVersion,
		JA4:                  "expected-ja4",
		Normalized:           normalized,
		NormalizationVersion: "TLS-NORM-1",
		MaterializerVersion:  SupportedMaterializerVersion,
		MustMatch:            []string{"/ciphers", "/extensions"},
		ShouldMatch:          []string{"/session_id_length"},
	}
	actual := Observation{Completeness: "complete", Fingerprints: &tlshello.Fingerprints{JA4: "actual-ja4", NormalizationVersion: "TLS-NORM-1", Normalized: normalized}}
	if got := VerifyExpected(expected, actual); got.Status != "MATCH" {
		t.Fatalf("MATCH verification = %+v", got)
	}
	actual.Fingerprints.Normalized = json.RawMessage(`{"ciphers":[1,2],"extensions":[{"id":0}],"legacy_version":771,"session_id_length":0}`)
	if got := VerifyExpected(expected, actual); got.Status != "PARTIAL_MATCH" {
		t.Fatalf("PARTIAL_MATCH verification = %+v", got)
	}
	actual.Fingerprints.Normalized = json.RawMessage(`{"ciphers":[2,1],"extensions":[{"id":0}],"legacy_version":771,"session_id_length":32}`)
	if got := VerifyExpected(expected, actual); got.Status != "MISMATCH" {
		t.Fatalf("MISMATCH verification = %+v", got)
	}
	actual.Completeness = "timeout"
	if got := VerifyExpected(expected, actual); got.Status != "UNKNOWN" {
		t.Fatalf("UNKNOWN verification = %+v", got)
	}
	actual.Completeness = "complete"
	expected.MaterializerVersion = "utls-template-materializer/2"
	if got := VerifyExpected(expected, actual); got.Status != "UNKNOWN" || got.Reason != "incompatible_materializer_version" {
		t.Fatalf("materializer version verification = %+v", got)
	}
	expected.MaterializerVersion = SupportedMaterializerVersion
	expected.MustMatch = []string{"/missing"}
	if got := VerifyExpected(expected, actual); got.Status != "MISMATCH" {
		t.Fatalf("missing MUST path verification = %+v", got)
	}
	expected.MustMatch = []string{"/ciphers"}
	expected.Constraints = []FingerprintConstraint{{Path: "/legacy_version", Operator: "one_of", Values: []json.RawMessage{json.RawMessage(`772`)}}}
	if got := VerifyExpected(expected, actual); got.Status != "MISMATCH" || got.Reason != "constraint_violation" {
		t.Fatalf("constraint verification = %+v", got)
	}
}

func TestForwardingVerification(t *testing.T) {
	inbound := tlshello.Capture{Status: "complete", Raw: []byte("hello"), Records: []byte("record")}
	expected := ForwardingFromCapture(inbound)
	if got := VerifyForwarding(*expected, inbound); got.Status != "FORWARDED_UNCHANGED" {
		t.Fatalf("unchanged forwarding = %+v", got)
	}
	changed := inbound
	changed.Raw = []byte("changed")
	if got := VerifyForwarding(*expected, changed); got.Status != "MISMATCH" {
		t.Fatalf("changed forwarding = %+v", got)
	}
	incomplete := inbound
	incomplete.Status = "truncated"
	if got := VerifyForwarding(*expected, incomplete); got.Status != "UNVERIFIED" {
		t.Fatalf("incomplete forwarding = %+v", got)
	}
}
