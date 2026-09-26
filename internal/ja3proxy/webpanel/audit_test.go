package webpanel

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/lylemi/ja3proxy/internal/ja3proxy/audit"
)

func TestAuditAPIRecordsMutationWithoutRequestSecrets(t *testing.T) {
	store, err := audit.Open("")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	h := Server{
		Audit: store,
		Update: func(ConfigUpdate) (RuntimeStatus, error) {
			return RuntimeStatus{ConfigVersion: 1}, nil
		},
	}.Handler()
	request := httptest.NewRequest(http.MethodPut, "/api/config", bytes.NewBufferString(`{"expected_version":0,"proxyPassword":"should-never-be-logged"}`))
	request.RemoteAddr = "127.0.0.1:54321"
	request.Host = "127.0.0.1:9090"
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Operator", "alice")
	response := httptest.NewRecorder()
	h.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("mutation status = %d, body = %s", response.Code, response.Body.String())
	}

	request = httptest.NewRequest(http.MethodGet, "/api/v1/audit?limit=10", nil)
	request.RemoteAddr = "127.0.0.1:54321"
	request.Host = "127.0.0.1:9090"
	response = httptest.NewRecorder()
	h.ServeHTTP(response, request)
	if response.Code != http.StatusOK || strings.Contains(response.Body.String(), "should-never-be-logged") {
		t.Fatalf("audit response = %d %s", response.Code, response.Body.String())
	}
	var page audit.Page
	if err := json.Unmarshal(response.Body.Bytes(), &page); err != nil || len(page.Items) != 2 {
		t.Fatalf("audit page = %s", response.Body.String())
	}
	event := page.Items[0]
	if event.Actor != "alice" || event.Action != "put" || event.Object != "/api/config" || event.Result != "success" || event.SourceIP != "127.0.0.1" {
		t.Fatalf("audit event = %+v", event)
	}
	if page.Items[1].Result != "requested" {
		t.Fatalf("request audit event = %+v", page.Items[1])
	}
}

func TestAuditFailureRejectsMutationBeforeHandler(t *testing.T) {
	store, err := audit.Open("")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	called := false
	h := Server{
		Audit: store,
		Update: func(ConfigUpdate) (RuntimeStatus, error) {
			called = true
			return RuntimeStatus{ConfigVersion: 1}, nil
		},
	}.Handler()
	request := httptest.NewRequest(http.MethodPut, "/api/config", bytes.NewBufferString(`{"expected_version":0,"proxyPort":8081}`))
	request.RemoteAddr = "127.0.0.1:54321"
	request.Host = "127.0.0.1:9090"
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	h.ServeHTTP(response, request)

	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("mutation status = %d, want %d", response.Code, http.StatusServiceUnavailable)
	}
	if called {
		t.Fatal("mutation handler was called despite unavailable audit store")
	}
}
