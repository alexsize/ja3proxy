package webpanel

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/lylemi/ja3proxy/internal/ja3proxy/capture/tlshello"
	"github.com/lylemi/ja3proxy/internal/ja3proxy/recorder"
)

func requestRecorder(h http.Handler, path string) *httptest.ResponseRecorder {
	r := httptest.NewRequest("GET", "http://127.0.0.1"+path, nil)
	r.RemoteAddr = "127.0.0.1:10000"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
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
	w = requestRecorder(h, "/api/v1/observations?limit=2&cursor="+page.Next)
	if w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	json.Unmarshal(w.Body.Bytes(), &page)
	if len(page.Items) != 1 {
		t.Fatal("pagination")
	}
	for _, path := range []string{"/api/v1/status", "/api/v1/tls/presets", "/api/v1/observations/" + page.Items[0].ID, "/api/v1/export/observations", "/recorder.html", "/recorder.js"} {
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
