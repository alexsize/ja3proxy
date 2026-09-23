package webpanel

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/lylemi/ja3proxy/internal/ja3proxy/traffic"
)

func TestHandlerServesPanel(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	response := httptest.NewRecorder()

	Server{}.Handler().ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusOK)
	}
	if !strings.Contains(response.Body.String(), "JA3Proxy / Панель трафика") {
		t.Fatal("response does not contain panel title")
	}
	if !strings.Contains(response.Body.String(), `id="proxy-port"`) || !strings.Contains(response.Body.String(), `id="proxy-protocol-choice"`) || !strings.Contains(response.Body.String(), `id="tls-fingerprint"`) || !strings.Contains(response.Body.String(), `id="upstream-choice"`) || !strings.Contains(response.Body.String(), `id="proxy-auth-choice"`) || !strings.Contains(response.Body.String(), `id="proxy-password"`) {
		t.Fatal("response does not contain runtime configuration selects")
	}
	if got := response.Header().Get("Content-Security-Policy"); !strings.Contains(got, "default-src 'self'") {
		t.Fatalf("Content-Security-Policy = %q, want self-only policy", got)
	}
}

func TestConfigAPIUpdatesRuntimeConfiguration(t *testing.T) {
	var received ConfigUpdate
	panel := Server{Update: func(update ConfigUpdate) (RuntimeStatus, error) {
		received = update
		return RuntimeStatus{TLSClient: "Chrome", TLSVersion: "120", UpstreamEnabled: true}, nil
	}}
	request := httptest.NewRequest(http.MethodPut, "/api/config", bytes.NewBufferString(`{"proxyPort":8181,"proxyProtocol":"socks5","tlsFingerprint":"chrome@120","upstream":"socks5://127.0.0.1:1080","proxyAuthEnabled":true,"proxyUsername":"client","proxyPassword":"secret"}`))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	panel.Handler().ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	if received.TLSFingerprint == nil || *received.TLSFingerprint != "chrome@120" {
		t.Fatalf("TLS fingerprint update = %#v", received.TLSFingerprint)
	}
	if received.Upstream == nil || *received.Upstream != "socks5://127.0.0.1:1080" {
		t.Fatalf("upstream update = %#v", received.Upstream)
	}
	if received.ProxyPort == nil || *received.ProxyPort != 8181 {
		t.Fatalf("proxy port update = %#v", received.ProxyPort)
	}
	if received.ProxyProtocol == nil || *received.ProxyProtocol != "socks5" {
		t.Fatalf("proxy protocol update = %#v", received.ProxyProtocol)
	}
	if received.ProxyAuthEnabled == nil || !*received.ProxyAuthEnabled {
		t.Fatalf("proxy auth enabled update = %#v", received.ProxyAuthEnabled)
	}
	if received.ProxyUsername == nil || *received.ProxyUsername != "client" {
		t.Fatalf("proxy username update = %#v", received.ProxyUsername)
	}
	if received.ProxyPassword == nil || *received.ProxyPassword != "secret" {
		t.Fatalf("proxy password update = %#v", received.ProxyPassword)
	}
	if strings.Contains(response.Body.String(), "secret") {
		t.Fatalf("configuration response exposed proxy password: %s", response.Body.String())
	}
}

func TestConfigAPIRejectsUnknownFields(t *testing.T) {
	panel := Server{Update: func(ConfigUpdate) (RuntimeStatus, error) {
		t.Fatal("updater must not be called")
		return RuntimeStatus{}, nil
	}}
	request := httptest.NewRequest(http.MethodPut, "/api/config", strings.NewReader(`{"listen":":9090"}`))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	panel.Handler().ServeHTTP(response, request)

	if response.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusBadRequest)
	}
}

func TestStateAPIReportsRuntimeAndTraffic(t *testing.T) {
	monitor := traffic.NewTrafficMonitor()
	session := monitor.StartSession(traffic.TrafficSessionInfo{
		Protocol:   "HTTP",
		Target:     "example.com:443",
		ClientAddr: "127.0.0.1:51000",
	})
	session.AddUpload(125)
	session.AddDownload(500)

	panel := Server{
		Monitor: monitor,
		Runtime: func() RuntimeStatus {
			return RuntimeStatus{
				ProxyListen:     "127.0.0.1:8080",
				TLSClient:       "Chrome",
				TLSVersion:      "120",
				TLSFingerprints: []string{"Chrome@120", "Firefox@120"},
			}
		},
	}
	request := httptest.NewRequest(http.MethodGet, "/api/state", nil)
	response := httptest.NewRecorder()

	panel.Handler().ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusOK)
	}
	if got := response.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("Cache-Control = %q, want no-store", got)
	}
	var state stateResponse
	if err := json.NewDecoder(response.Body).Decode(&state); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if state.Runtime.TLSClient != "Chrome" || state.Runtime.TLSVersion != "120" {
		t.Fatalf("runtime = %+v, want Chrome@120", state.Runtime)
	}
	if len(state.Runtime.TLSFingerprints) != 2 {
		t.Fatalf("fingerprint options = %v, want two options", state.Runtime.TLSFingerprints)
	}
	if state.Traffic.ActiveSessions != 1 || state.Traffic.TotalUploadBytes != 125 || state.Traffic.TotalDownloadBytes != 500 {
		t.Fatalf("traffic = %+v, want one active 125/500-byte session", state.Traffic)
	}
}

func TestStateAPIAllowsNilMonitor(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "/api/state", nil)
	response := httptest.NewRecorder()

	Server{}.Handler().ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusOK)
	}
}

func TestCompactPanelSnapshotBoundsEachVisibleSessionFilter(t *testing.T) {
	snapshot := traffic.TrafficSnapshot{}
	for id := uint64(1); id <= 150; id++ {
		state := traffic.StateClosed
		switch {
		case id <= 50:
			state = traffic.StateActive
		case id > 100:
			state = traffic.StateFailed
		}
		snapshot.Sessions = append(snapshot.Sessions, traffic.TrafficSessionSnapshot{ID: id, State: state})
	}
	for id := uint64(1); id <= 25; id++ {
		snapshot.Events = append(snapshot.Events, traffic.TrafficEventSnapshot{SessionID: id})
	}

	compactPanelSnapshot(&snapshot)

	if len(snapshot.Sessions) != 80 {
		t.Fatalf("sessions = %d, want 80 (40 active + 40 failed)", len(snapshot.Sessions))
	}
	active := 0
	failed := 0
	for _, session := range snapshot.Sessions {
		if session.State == traffic.StateActive {
			active++
		}
		if session.State == traffic.StateFailed {
			failed++
		}
	}
	if active != panelSessionLimit || failed != panelSessionLimit {
		t.Fatalf("active/failed = %d/%d, want %d/%d", active, failed, panelSessionLimit, panelSessionLimit)
	}
	if len(snapshot.Events) != panelEventLimit || snapshot.Events[0].SessionID != 16 || snapshot.Events[9].SessionID != 25 {
		t.Fatalf("events = %+v, want the latest %d", snapshot.Events, panelEventLimit)
	}
}
