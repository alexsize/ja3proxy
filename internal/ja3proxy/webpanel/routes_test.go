package webpanel

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/lylemi/ja3proxy/internal/ja3proxy/routing"
)

func TestRouteTestAPIResolvesConfiguredRule(t *testing.T) {
	store := &routing.Store{}
	if err := store.SetValidated(routing.Config{Rules: []routing.Rule{{
		ID: "mobile-api", Priority: 2, Enabled: true, Phase: routing.PhasePreTLS,
		Match:  routing.Match{Host: "api.example.com", Port: 443, DeviceTag: "mobile"},
		Action: routing.Action{Mode: "MITM_REISSUE", TLSProfile: "mobile"},
	}}}); err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/api/v1/routes/test", bytes.NewBufferString(`{"host":"api.example.com","port":443,"device_tags":["mobile"]}`))
	request.RemoteAddr = "127.0.0.1:12000"
	request.Host = "127.0.0.1:9090"
	response := httptest.NewRecorder()

	Server{Routes: store}.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	var decision routing.Decision
	if err := json.NewDecoder(response.Body).Decode(&decision); err != nil {
		t.Fatal(err)
	}
	if decision.MatchedRuleID != "mobile-api" || decision.MatchedRulePriority != 2 || decision.Action.TLSProfile != "mobile" {
		t.Fatalf("decision = %+v", decision)
	}
}

func TestRouteTestAPIRejectsInvalidInput(t *testing.T) {
	store := &routing.Store{}
	request := httptest.NewRequest(http.MethodPost, "/api/v1/routes/test", bytes.NewBufferString(`{"phase":"UNKNOWN"}`))
	request.RemoteAddr = "127.0.0.1:12000"
	request.Host = "127.0.0.1:9090"
	response := httptest.NewRecorder()

	Server{Routes: store}.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
}
