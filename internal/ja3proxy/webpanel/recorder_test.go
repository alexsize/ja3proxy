package webpanel

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/lylemi/ja3proxy/internal/ja3proxy/capture/tlshello"
	"github.com/lylemi/ja3proxy/internal/ja3proxy/recorder"
)

func requestRecorder(h http.Handler, path string) *httptest.ResponseRecorder {
	return requestRecorderMethod(h, "GET", path)
}

func requestRecorderMethod(h http.Handler, method, path string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, "http://127.0.0.1"+path, nil)
	r.RemoteAddr = "127.0.0.1:10000"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func reparseCapture() tlshello.Capture {
	raw := []byte{1, 0, 0, 43, 3, 3}
	raw = append(raw, make([]byte, 32)...)
	raw = append(raw, 0, 0, 2, 0x13, 1, 1, 0, 0, 0)
	return tlshello.Capture{Status: "complete", Raw: raw, Records: append([]byte{22, 3, 1, 0, 47}, raw...), RecordVersion: 0x0301, RecordCount: 1}
}

func TestRecorderAPI(t *testing.T) {
	r, err := recorder.New(recorder.Options{})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		r.TryCapture(recorder.Meta{Destination: "test.example", ConnectionID: recorder.NewID()}, tlshello.Capture{Status: "timeout", ErrorCode: "capture_timeout"})
	}
	r.Close()
	h := Server{Recorder: r}.Handler()
	w := requestRecorder(h, "/api/v1/observations?limit=2")
	if w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	var page struct {
		Items []recorder.Observation `json:"items"`
		Next  string                 `json:"next_cursor"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &page); err != nil || len(page.Items) != 2 || page.Next == "" {
		t.Fatal(w.Body.String())
	}
	if page.Items[0].SchemaVersion != recorder.ObservationSchemaVersion ||
		page.Items[0].ParserVersion != tlshello.ParserVersion || page.Items[0].TLSEngine == "" {
		t.Fatalf("API omitted observation version envelope: %+v", page.Items[0])
	}
	w = requestRecorder(h, "/api/v1/observations?limit=2&cursor="+page.Next)
	if w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	json.Unmarshal(w.Body.Bytes(), &page)
	if len(page.Items) != 1 {
		t.Fatal("pagination")
	}
	for _, path := range []string{"/api/v1/status", "/api/v1/tls/presets", "/api/v1/observations/" + page.Items[0].ID, "/api/v1/export/observations", "/recorder.html", "/recorder.js", "/profiles.html", "/profiles.js", "/profiles.css"} {
		if w := requestRecorder(h, path); w.Code != 200 {
			t.Fatalf("%s: %d", path, w.Code)
		}
	}
	for _, path := range []string{"/api/v1/observations?limit=0", "/api/v1/observations?limit=101"} {
		if requestRecorder(h, path).Code != 400 {
			t.Fatal(path)
		}
	}
	if requestRecorder(h, "/api/v1/observations?cursor=expired").Code != 409 {
		t.Fatal("stale cursor")
	}
	if requestRecorder(h, "/api/v1/observations/missing").Code != 404 {
		t.Fatal("missing observation")
	}
	w = requestRecorder(h, "/api/v1/fingerprints/diff?a="+page.Items[0].ID+"&b="+page.Items[0].ID)
	if !strings.Contains(w.Body.String(), "UNKNOWN") {
		t.Fatal("timeout considered match")
	}
}

func TestRecorderReparseAPI(t *testing.T) {
	r, err := recorder.New(recorder.Options{Raw: true})
	if err != nil {
		t.Fatal(err)
	}
	if !r.TryCapture(recorder.Meta{ConnectionID: "reparse", CapturePoint: "CLIENT_IN", Direction: "inbound"}, reparseCapture()) {
		t.Fatal("enqueue")
	}
	var source recorder.Observation
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		items := r.Snapshot()
		if len(items) == 1 {
			source = items[0]
			break
		}
		time.Sleep(time.Millisecond)
	}
	if source.ID == "" {
		t.Fatal("source observation was not processed")
	}
	w := requestRecorderMethod(recorderServer(r), "POST", "/api/v1/observations/"+source.ID+"/reparse")
	if w.Code != http.StatusCreated {
		t.Fatal(w.Body.String())
	}
	var derived recorder.Observation
	if err := json.Unmarshal(w.Body.Bytes(), &derived); err != nil {
		t.Fatal(err)
	}
	if derived.AnalysisParentID != source.ID || derived.AnalysisRevision != 2 {
		t.Fatalf("invalid revision: %+v", derived)
	}
	if len(r.Snapshot()) != 2 {
		t.Fatal("source and derived observations were not both retained")
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}

	withoutRaw, err := recorder.New(recorder.Options{})
	if err != nil {
		t.Fatal(err)
	}
	withoutRaw.TryCapture(recorder.Meta{ConnectionID: "no-raw"}, reparseCapture())
	deadline = time.Now().Add(time.Second)
	var noRawID string
	for time.Now().Before(deadline) {
		items := withoutRaw.Snapshot()
		if len(items) == 1 {
			noRawID = items[0].ID
			break
		}
		time.Sleep(time.Millisecond)
	}
	w = requestRecorderMethod(recorderServer(withoutRaw), "POST", "/api/v1/observations/"+noRawID+"/reparse")
	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}
	if err := withoutRaw.Close(); err != nil {
		t.Fatal(err)
	}
}

func recorderServer(r *recorder.Recorder) http.Handler {
	return Server{Recorder: r}.Handler()
}

func TestRecorderRejectsRemoteAndRebinding(t *testing.T) {
	h := Server{}.Handler()
	for _, tt := range []struct{ host, peer, origin string }{{"evil.example", "127.0.0.1:20", ""}, {"127.0.0.1", "192.0.2.1:20", ""}, {"127.0.0.1", "127.0.0.1:20", "https://evil.example"}} {
		r := httptest.NewRequest("GET", "http://"+tt.host+"/api/v1/observations", nil)
		r.RemoteAddr = tt.peer
		r.Header.Set("Origin", tt.origin)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != 403 {
			t.Fatalf("%+v accepted", tt)
		}
	}
}
