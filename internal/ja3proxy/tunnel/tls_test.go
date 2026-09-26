package tunnel

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"net"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/lylemi/ja3proxy/internal/ja3proxy/capture/tlshello"
	"github.com/lylemi/ja3proxy/internal/ja3proxy/certstore"
	"github.com/lylemi/ja3proxy/internal/ja3proxy/device"
	"github.com/lylemi/ja3proxy/internal/ja3proxy/fingerprint"
	"github.com/lylemi/ja3proxy/internal/ja3proxy/flowid"
	"github.com/lylemi/ja3proxy/internal/ja3proxy/recorder"
	"github.com/lylemi/ja3proxy/internal/ja3proxy/routing"
	"github.com/lylemi/ja3proxy/internal/ja3proxy/tlsprofile"
	"github.com/lylemi/ja3proxy/internal/ja3proxy/upstreamtls"
	utls "github.com/refraction-networking/utls"
)

func TestApplyIdentityEvidenceUsesUsernameThenSourceIP(t *testing.T) {
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()

	meta := applyIdentityEvidence(recorder.Meta{Source: "192.0.2.10:53122"}, flowid.WithProxyUsername(left, "iphone017"))
	if meta.IdentitySource != "proxy_username" || meta.IdentityValue != "iphone017" || meta.Confidence != "exact" {
		t.Fatalf("username identity = %+v", meta)
	}

	meta = applyIdentityEvidence(recorder.Meta{Source: "192.0.2.10:53122"}, left)
	if meta.IdentitySource != "source_ip" || meta.IdentityValue != "192.0.2.10" || meta.Confidence != "inferred" {
		t.Fatalf("source IP identity = %+v", meta)
	}

	meta = applyIdentityEvidence(recorder.Meta{Source: "not-an-ip:1234"}, left)
	if meta.IdentitySource != "" || meta.IdentityValue != "" || meta.Confidence != "" {
		t.Fatalf("invalid source produced identity = %+v", meta)
	}
}

func TestApplyIdentityEvidenceIncludesActiveApplicationAssignment(t *testing.T) {
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()

	store, err := device.Open("")
	if err != nil {
		t.Fatal(err)
	}
	created, registry, err := store.Create(device.Device{ID: "phone-017", Name: "Phone 017", ProxyUsername: "iphone017", Enabled: true}, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = store.CreateAssignment(device.ApplicationAssignment{
		ID: "phone-017-app", DeviceID: created.ID, Application: "Example", Version: "1.2.0",
		ValidFrom: time.Now().UTC().Add(-time.Hour).Format(time.RFC3339),
	}, registry.ConfigVersion)
	if err != nil {
		t.Fatal(err)
	}
	meta := applyIdentityEvidenceWithRegistry(recorder.Meta{Source: "192.0.2.10:53122"}, flowid.WithProxyUsername(left, "iphone017"), store)
	if meta.ResolvedDeviceID != created.ID || meta.Application != "Example" || meta.ApplicationVersion != "1.2.0" || meta.ApplicationAssignmentID != "phone-017-app" {
		t.Fatalf("application assignment identity = %+v", meta)
	}
}

func TestMatchingProtocols(t *testing.T) {
	tests := []struct {
		name      string
		supported []string
		allowed   []string
		want      []string
	}{
		{
			name:      "keeps supported order",
			supported: []string{"h2", "http/1.1", "h3"},
			allowed:   []string{"http/1.1", "h2"},
			want:      []string{"h2", "http/1.1"},
		},
		{
			name:      "no overlap",
			supported: []string{"h3"},
			allowed:   []string{"h2", "http/1.1"},
			want:      []string{},
		},
		{
			name:      "empty allowed",
			supported: []string{"h2"},
			allowed:   nil,
			want:      []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := matchingProtocols(tt.supported, tt.allowed); !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("matchingProtocols() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestUpstreamALPN(t *testing.T) {
	if got := upstreamALPN(nil); !reflect.DeepEqual(got, []string{"http/1.1"}) {
		t.Fatalf("upstreamALPN(nil) = %v, want [http/1.1]", got)
	}

	input := []string{"h2", "http/1.1"}
	if got := upstreamALPN(input); !reflect.DeepEqual(got, input) {
		t.Fatalf("upstreamALPN(%v) = %v, want %v", input, got, input)
	}
}

func TestClientALPN(t *testing.T) {
	if got := clientALPN(""); !reflect.DeepEqual(got, []string{"http/1.1"}) {
		t.Fatalf("clientALPN(\"\") = %v, want [http/1.1]", got)
	}

	if got := clientALPN("h2"); !reflect.DeepEqual(got, []string{"h2"}) {
		t.Fatalf("clientALPN(\"h2\") = %v, want [h2]", got)
	}
}

func TestGenerateCertificateNilGuardReturnsErrors(t *testing.T) {
	tests := []struct {
		name    string
		handler *TunnelHandler
		want    string
	}{
		{
			name:    "nil handler",
			handler: nil,
			want:    "CA certificate has not been loaded",
		},
		{
			name:    "nil CA",
			handler: &TunnelHandler{},
			want:    "CA certificate has not been loaded",
		},
		{
			name:    "nil session key",
			handler: &TunnelHandler{CA: &certstore.CertificateAuthority{}},
			want:    "session key has not been generated",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := tt.handler.generateCertificate("example.com:443"); err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("TunnelHandler.generateCertificate() error = %v, want %q", err, tt.want)
			}
		})
	}
}

func TestConfiguredTLSFingerprintUsesInstanceStore(t *testing.T) {
	var store fingerprint.TLSFingerprintStore
	store.Set(fingerprint.TLSFingerprint{Client: "Firefox", Version: "105"})
	handler := &TunnelHandler{
		TLSFingerprints:   &store,
		DefaultTLSClient:  "Golang",
		DefaultTLSVersion: "0",
	}

	got := handler.configuredTLSFingerprint()
	if got.Client != "Firefox" || got.Version != "105" {
		t.Fatalf("handler.configuredTLSFingerprint() = %+v, want Firefox 105", got)
	}
}

func TestConfiguredTLSFingerprintFallsBackToInstanceDefaults(t *testing.T) {
	var store fingerprint.TLSFingerprintStore
	handler := &TunnelHandler{
		TLSFingerprints:   &store,
		DefaultTLSClient:  "Golang",
		DefaultTLSVersion: "0",
	}

	got := handler.configuredTLSFingerprint()
	if got.Client != "Golang" || got.Version != "0" {
		t.Fatalf("handler.configuredTLSFingerprint() = %+v, want Golang 0", got)
	}
}

func TestConfiguredUpstreamTLSProfileFallsBackToCurrentFingerprint(t *testing.T) {
	store := &fingerprint.TLSFingerprintStore{}
	store.Set(fingerprint.TLSFingerprint{Client: "Firefox", Version: "105"})
	handler := &TunnelHandler{
		TLSFingerprints:   store,
		DefaultTLSClient:  "Chrome",
		DefaultTLSVersion: "120",
	}

	got := handler.configuredUpstreamTLSProfile("example.com")
	if got.Protocol != upstreamtls.ProtocolUTLS || got.Client != "Firefox" || got.Version != "105" {
		t.Fatalf("configuredUpstreamTLSProfile() = %+v, want Firefox 105", got)
	}
}

func TestConfiguredUpstreamTLSProfileUsesRouteStore(t *testing.T) {
	profiles := &upstreamtls.UpstreamTLSProfileStore{}
	profiles.Set(upstreamtls.UpstreamTLSConfig{
		Default: upstreamtls.UpstreamTLSProfile{Protocol: "utls", Client: "Chrome", Version: "120"},
		Routes: []upstreamtls.UpstreamTLSRoute{
			{
				Host:               "*.example.com",
				UpstreamTLSProfile: upstreamtls.UpstreamTLSProfile{Protocol: "utls", Client: "Firefox", Version: "105"},
			},
		},
	})
	handler := &TunnelHandler{
		UpstreamTLSProfiles: profiles,
		DefaultTLSClient:    "Golang",
		DefaultTLSVersion:   "0",
	}

	got := handler.configuredUpstreamTLSProfile("api.example.com")
	if got.Protocol != upstreamtls.ProtocolUTLS || got.Client != "Firefox" || got.Version != "105" {
		t.Fatalf("configuredUpstreamTLSProfile() = %+v, want Firefox 105 route", got)
	}
}

func TestConfiguredUpstreamTLSProfileReturnsSnapshotVersion(t *testing.T) {
	profiles := &upstreamtls.UpstreamTLSProfileStore{}
	profiles.Set(upstreamtls.UpstreamTLSConfig{
		Default: upstreamtls.UpstreamTLSProfile{Protocol: "utls", Client: "Chrome", Version: "120"},
	})
	handler := &TunnelHandler{UpstreamTLSProfiles: profiles}

	profile, version, fromStore := handler.configuredUpstreamTLSProfileWithVersion("example.com")
	if !fromStore || version != 1 || profile.Client != "Chrome" {
		t.Fatalf("profile=%+v, version=%d, fromStore=%v; want Chrome, version 1, true", profile, version, fromStore)
	}
}

func TestConfiguredUpstreamTLSResolutionReturnsRouteEvidence(t *testing.T) {
	profiles := &upstreamtls.UpstreamTLSProfileStore{}
	profiles.Set(upstreamtls.UpstreamTLSConfig{
		Routes: []upstreamtls.UpstreamTLSRoute{{
			ID:                 "api-route",
			Host:               "api.example.com",
			Priority:           7,
			UpstreamTLSProfile: upstreamtls.UpstreamTLSProfile{Protocol: "utls", Client: "Firefox", Version: "105"},
		}},
	})
	handler := &TunnelHandler{UpstreamTLSProfiles: profiles}

	resolution := handler.configuredUpstreamTLSResolution("api.example.com")
	if resolution.RouteID != "api-route" || resolution.Priority != 7 || resolution.MatchReason != "exact" || resolution.ConfigVersion != 1 {
		t.Fatalf("resolution = %+v", resolution)
	}
}

func TestConnectWithRequestAppliesRouteBlock(t *testing.T) {
	profiles := &routing.Store{}
	if err := profiles.SetValidated(routing.Config{Rules: []routing.Rule{{
		ID: "blocked", Priority: 1, Enabled: true, Phase: routing.PhasePreTLS,
		Match: routing.Match{Host: "blocked.example.com"}, Action: routing.Action{Mode: "BLOCK"},
	}}}); err != nil {
		t.Fatal(err)
	}
	handler := &TunnelHandler{Routes: profiles}
	destServer, destPeer := net.Pipe()
	clientPeer, clientServer := net.Pipe()
	defer destPeer.Close()
	defer clientPeer.Close()

	done := make(chan struct{})
	go func() {
		handler.ConnectWithRequest(ConnectRequest{Host: "blocked.example.com", Port: 443}, destServer, clientServer)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("blocked route did not return")
	}
	if _, err := clientPeer.Write([]byte("blocked")); err == nil {
		t.Fatal("blocked route left client connection writable")
	}
}

func TestResolvePostTLSRouteUsesClientSNI(t *testing.T) {
	profiles := &routing.Store{}
	if err := profiles.SetValidated(routing.Config{Rules: []routing.Rule{{
		ID: "blocked-sni", Priority: 1, Enabled: true, Phase: routing.PhasePostClientHello,
		Match: routing.Match{Host: "secure.example.com"}, Action: routing.Action{Mode: "BLOCK"},
	}}}); err != nil {
		t.Fatal(err)
	}
	handler := &TunnelHandler{Routes: profiles}
	decision := handler.resolvePostTLSRoute(ConnectRequest{Host: "connect.example.com", Port: 443}, "secure.example.com", nil)
	if decision.MatchedRuleID != "blocked-sni" || decision.Action.Mode != "BLOCK" {
		t.Fatalf("POST_CLIENTHELLO decision = %+v", decision)
	}
}

func TestResolvePreTLSRouteUsesResolvedDeviceTags(t *testing.T) {
	devices, err := device.Open("")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := devices.Create(device.Device{ID: "phone-017", Name: "Phone 017", ProxyUsername: "iphone017", Tags: []string{"mobile"}, Enabled: true}, 0); err != nil {
		t.Fatal(err)
	}
	routes := &routing.Store{}
	if err := routes.SetValidated(routing.Config{Rules: []routing.Rule{{
		ID: "mobile-route", Priority: 1, Enabled: true, Phase: routing.PhasePreTLS,
		Match: routing.Match{DeviceTag: "mobile"}, Action: routing.Action{Mode: "PASSTHROUGH"},
	}}}); err != nil {
		t.Fatal(err)
	}
	client, peer := net.Pipe()
	defer client.Close()
	defer peer.Close()
	handler := &TunnelHandler{Routes: routes, Devices: devices}
	decision := handler.resolvePreTLSRoute(ConnectRequest{Host: "example.com", Port: 443, Username: "iphone017", ClientAddr: "192.0.2.10:54321"}, client)
	if decision.MatchedRuleID != "mobile-route" {
		t.Fatalf("device-tag route decision = %+v", decision)
	}
}

func TestAuthorityPolicyAndMismatch(t *testing.T) {
	if !authoritiesMismatch("connect.example.com:443", "secure.example.com") {
		t.Fatal("different CONNECT host and SNI were not marked as mismatch")
	}
	if authoritiesMismatch("CONNECT.EXAMPLE.COM", "connect.example.com") {
		t.Fatal("case-insensitive equal authorities were marked as mismatch")
	}
	if got := applyAuthorityPolicy("MITM_REISSUE", "block", true); got != "BLOCK" {
		t.Fatalf("block authority policy = %q", got)
	}
	if got := applyAuthorityPolicy("MITM_REISSUE", "passthrough", true); got != "PASSTHROUGH" {
		t.Fatalf("passthrough authority policy = %q", got)
	}
}

func TestObserveOnlyRouteCannotBeEscalatedByPostRoute(t *testing.T) {
	if got := applyPostRouteMode("OBSERVE_ONLY", "MITM_REISSUE", true); got != "OBSERVE_ONLY" {
		t.Fatalf("OBSERVE_ONLY was changed to %q", got)
	}
	if got := applyPostRouteMode("MITM_REISSUE", "OBSERVE_ONLY", false); got != "OBSERVE_ONLY" {
		t.Fatalf("POST_CLIENTHELLO OBSERVE_ONLY = %q", got)
	}
}

func TestCaptureFailurePolicy(t *testing.T) {
	tests := []struct {
		name       string
		mode       string
		policy     string
		wantMode   string
		wantRecord bool
		wantBlock  bool
	}{
		{name: "default", mode: "MITM_REISSUE", wantMode: "PASSTHROUGH", wantRecord: true},
		{name: "continue passthrough", mode: "MITM_REISSUE", policy: routing.CaptureFailureContinuePassthrough, wantMode: "PASSTHROUGH", wantRecord: true},
		{name: "without recording", mode: "MITM_REISSUE", policy: routing.CaptureFailureContinueWithoutRecording, wantMode: "PASSTHROUGH", wantRecord: false},
		{name: "block", mode: "MITM_REISSUE", policy: routing.CaptureFailureBlock, wantMode: "BLOCK", wantRecord: true, wantBlock: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			mode, record, blocked := applyCaptureFailurePolicy(test.mode, test.policy)
			if mode != test.wantMode || record != test.wantRecord || blocked != test.wantBlock {
				t.Fatalf("applyCaptureFailurePolicy(%q, %q) = mode %q, record %v, blocked %v", test.mode, test.policy, mode, record, blocked)
			}
		})
	}
}

func TestCaptureFailureBlockStopsDeferredDial(t *testing.T) {
	routes := &routing.Store{}
	if err := routes.SetValidated(routing.Config{Rules: []routing.Rule{{
		ID: "block-capture-failure", Priority: 1, Enabled: true, Phase: routing.PhasePreTLS,
		Match: routing.Match{Host: "example.com"}, Action: routing.Action{Mode: "MITM_REISSUE", CaptureFailurePolicy: routing.CaptureFailureBlock},
	}, {
		ID: "post-inspection", Priority: 1, Enabled: true, Phase: routing.PhasePostClientHello,
		Match: routing.Match{Host: "example.com"}, Action: routing.Action{Mode: "MITM_REISSUE"},
	}}}); err != nil {
		t.Fatal(err)
	}
	clientPeer, clientConn := net.Pipe()
	defer clientPeer.Close()
	defer clientConn.Close()
	dialed := make(chan struct{}, 1)
	handler := &TunnelHandler{Routes: routes, CaptureTimeout: 20 * time.Millisecond, DialDefault: func(ConnectRequest) (net.Conn, error) {
		dialed <- struct{}{}
		return nil, nil
	}}
	done := make(chan struct{})
	go func() {
		handler.ConnectWithRequest(ConnectRequest{Host: "example.com", Port: 443}, nil, clientConn)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("capture failure block did not return")
	}
	select {
	case <-dialed:
		t.Fatal("deferred dial ran despite capture_failure_policy=block")
	default:
	}
}

func TestConnectWithRequestAppliesPostClientHelloPassthrough(t *testing.T) {
	routes := &routing.Store{}
	if err := routes.SetValidated(routing.Config{Rules: []routing.Rule{{
		ID: "passthrough-sni", Priority: 1, Enabled: true, Phase: routing.PhasePostClientHello,
		Match: routing.Match{Host: "secure.example.com"}, Action: routing.Action{Mode: "PASSTHROUGH", Upstream: "socks5://route.example:1080"},
	}}}); err != nil {
		t.Fatal(err)
	}
	handler := &TunnelHandler{Routes: routes, CaptureTimeout: time.Second}
	destConn, destPeer := net.Pipe()
	selectedConn, selectedPeer := net.Pipe()
	clientPeer, clientConn := net.Pipe()
	defer destPeer.Close()
	defer selectedPeer.Close()
	defer clientPeer.Close()
	selectedUpstream := make(chan string, 1)
	handler.DialUpstream = func(_ ConnectRequest, upstream string) (net.Conn, error) {
		selectedUpstream <- upstream
		return selectedConn, nil
	}

	done := make(chan struct{})
	go func() {
		handler.ConnectWithRequest(ConnectRequest{Host: "connect.example.com", Port: 443}, destConn, clientConn)
		close(done)
	}()

	client := tls.Client(clientPeer, &tls.Config{ServerName: "secure.example.com", InsecureSkipVerify: true})
	handshakeDone := make(chan error, 1)
	go func() { handshakeDone <- client.Handshake() }()

	select {
	case upstream := <-selectedUpstream:
		if upstream != "socks5://route.example:1080" {
			t.Fatalf("selected upstream = %q", upstream)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for POST_CLIENTHELLO upstream selection")
	}
	header := make([]byte, 5)
	if _, err := io.ReadFull(selectedPeer, header); err != nil {
		t.Fatalf("read forwarded ClientHello: %v", err)
	}
	if header[0] != 22 {
		t.Fatalf("forwarded record type = %d, want handshake", header[0])
	}
	_ = clientPeer.Close()
	_ = selectedPeer.Close()
	_ = destPeer.Close()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("post-ClientHello passthrough did not finish")
	}
	select {
	case <-handshakeDone:
	case <-time.After(2 * time.Second):
		t.Fatal("TLS client did not observe closed passthrough")
	}
}

func TestRoutingSnapshotKeepsTwoPhaseEvidenceWithoutActionSecrets(t *testing.T) {
	pre := routing.Decision{
		ConfigVersion: 4, Phase: routing.PhasePreTLS, MatchedRuleID: "pre-route",
		MatchedRulePriority: 3, MatchReason: "exact", CandidateRuleIDs: []string{"pre-route", "fallback"},
		Action: routing.Action{Mode: "OBSERVE_ONLY", MatchPolicy: "passthrough"},
	}
	snapshot := routingSnapshot(pre)
	if snapshot == nil || snapshot.PreTLS == nil || snapshot.PreTLS.ConfigVersion != 4 || snapshot.PreTLS.EvaluatedConfigVersion != 4 || snapshot.PreTLS.MatchedRuleID != "pre-route" || len(snapshot.PreTLS.CandidateRuleIDs) != 2 || snapshot.PreTLS.ActionMode != "OBSERVE_ONLY" || snapshot.PreTLS.MatchPolicy != "passthrough" {
		t.Fatalf("pre-TLS routing snapshot = %+v", snapshot)
	}
	post := routeDecisionEvidence(routing.Decision{
		ConfigVersion: 4, Phase: routing.PhasePostClientHello, MatchedRuleID: "post-route",
		MatchedRulePriority: 8, MatchReason: "wildcard",
	})
	snapshot.PostClientHello = post
	encoded, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatalf("marshal routing snapshot: %v", err)
	}
	if strings.Contains(string(encoded), "proxy-password") || !strings.Contains(string(encoded), "post-route") {
		t.Fatalf("routing snapshot JSON = %s", encoded)
	}
}

func TestLimitSpecALPN(t *testing.T) {
	spec := &utls.ClientHelloSpec{
		Extensions: []utls.TLSExtension{
			&utls.SNIExtension{},
			&utls.ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1", "h3"}},
			&utls.ApplicationSettingsExtension{SupportedProtocols: []string{"h2", "h3"}},
		},
	}

	mutations := limitSpecALPN(spec, []string{"http/1.1"})
	if len(mutations) != 2 {
		t.Fatalf("runtime mutations = %d, want 2", len(mutations))
	}
	if mutations[0].Type != "PROFILE_RUNTIME_MUTATION" || mutations[0].Field != "ALPN" || !reflect.DeepEqual(mutations[0].Before, []string{"h2", "http/1.1", "h3"}) || !reflect.DeepEqual(mutations[0].After, []string{"http/1.1"}) {
		t.Fatalf("ALPN mutation = %+v", mutations[0])
	}
	if mutations[1].Field != "ALPS" || !reflect.DeepEqual(mutations[1].Before, []string{"h2", "h3"}) || len(mutations[1].After) != 0 {
		t.Fatalf("ALPS mutation = %+v", mutations[1])
	}

	if len(spec.Extensions) != 2 {
		t.Fatalf("extension count after filtering = %d, want 2", len(spec.Extensions))
	}

	alpn, ok := spec.Extensions[1].(*utls.ALPNExtension)
	if !ok {
		t.Fatalf("extension[1] = %T, want *utls.ALPNExtension", spec.Extensions[1])
	}
	if !reflect.DeepEqual(alpn.AlpnProtocols, []string{"http/1.1"}) {
		t.Fatalf("ALPN protocols = %v, want [http/1.1]", alpn.AlpnProtocols)
	}
}

func TestCustomTLSWrapHandshakeNegotiatesALPNAndSNI(t *testing.T) {
	const serverName = "upstream.test"
	nextProtos := []string{"h2", "http/1.1"}
	listener, serverResults := newLocalTLSServer(t, []string{"h2", "http/1.1"})
	handler := &TunnelHandler{
		DefaultTLSClient:  utls.HelloGolang.Client,
		DefaultTLSVersion: utls.HelloGolang.Version,
	}

	conn, err := net.DialTimeout("tcp", listener.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatalf("dial local TLS server: %v", err)
	}
	if err := conn.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("set client deadline: %v", err)
	}

	tlsConn, err := handler.customTLSWrap(conn, serverName, nextProtos)
	if err != nil {
		conn.Close()
		t.Fatalf("TunnelHandler.customTLSWrap() error = %v", err)
	}
	defer tlsConn.Close()

	state := tlsConn.ConnectionState()
	if state.NegotiatedProtocol != "h2" {
		t.Fatalf("client negotiated protocol = %q, want h2", state.NegotiatedProtocol)
	}

	result := receiveTLSServerResult(t, serverResults)
	if result.err != nil {
		t.Fatalf("server handshake error = %v", result.err)
	}
	if result.serverName != serverName {
		t.Fatalf("server saw SNI = %q, want %q", result.serverName, serverName)
	}
	if result.negotiatedProtocol != "h2" {
		t.Fatalf("server negotiated protocol = %q, want h2", result.negotiatedProtocol)
	}
	if !reflect.DeepEqual(result.supportedProtos, nextProtos) {
		t.Fatalf("server saw client ALPN = %v, want %v", result.supportedProtos, nextProtos)
	}
}

func TestCustomTLSWrapWithUTLSPresetLimitsALPN(t *testing.T) {
	const serverName = "upstream.test"
	nextProtos := []string{"http/1.1"}
	listener, serverResults := newLocalTLSServer(t, []string{"h2", "http/1.1"})
	handler := &TunnelHandler{
		DefaultTLSClient:  utls.HelloFirefox_Auto.Client,
		DefaultTLSVersion: utls.HelloFirefox_Auto.Version,
	}

	conn, err := net.DialTimeout("tcp", listener.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatalf("dial local TLS server: %v", err)
	}
	if err := conn.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("set client deadline: %v", err)
	}

	tlsConn, err := handler.customTLSWrap(conn, serverName, nextProtos)
	if err != nil {
		conn.Close()
		t.Fatalf("TunnelHandler.customTLSWrap() error = %v", err)
	}
	defer tlsConn.Close()

	state := tlsConn.ConnectionState()
	if state.NegotiatedProtocol != "http/1.1" {
		t.Fatalf("client negotiated protocol = %q, want http/1.1", state.NegotiatedProtocol)
	}

	result := receiveTLSServerResult(t, serverResults)
	if result.err != nil {
		t.Fatalf("server handshake error = %v", result.err)
	}
	if result.serverName != serverName {
		t.Fatalf("server saw SNI = %q, want %q", result.serverName, serverName)
	}
	if result.negotiatedProtocol != "http/1.1" {
		t.Fatalf("server negotiated protocol = %q, want http/1.1", result.negotiatedProtocol)
	}
	if !reflect.DeepEqual(result.supportedProtos, nextProtos) {
		t.Fatalf("server saw client ALPN = %v, want %v", result.supportedProtos, nextProtos)
	}
}

func TestUTLSWrapAuditedRecordsRuntimeMutations(t *testing.T) {
	const serverName = "upstream.test"
	listener, serverResults := newLocalTLSServer(t, []string{"h2", "http/1.1"})
	handler := &TunnelHandler{}
	conn, err := net.DialTimeout("tcp", listener.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatalf("dial local TLS server: %v", err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	wrapped, err := handler.wrapUpstreamTLSSelection(conn, serverName, []string{"http/1.1"}, upstreamtls.UpstreamTLSProfile{
		Protocol: upstreamtls.ProtocolUTLS,
		Client:   utls.HelloFirefox_Auto.Client,
		Version:  utls.HelloFirefox_Auto.Version,
	}, nil)
	if err != nil {
		t.Fatalf("wrap upstream TLS: %v", err)
	}
	defer wrapped.Close()
	if len(wrapped.runtimeMutations) == 0 {
		t.Fatal("expected runtime mutation audit")
	}
	if wrapped.runtimeMutations[0].Field != "ALPN" || wrapped.runtimeMutations[0].Reason != "downstream protocol compatibility" {
		t.Fatalf("runtime mutations = %+v", wrapped.runtimeMutations)
	}
	result := receiveTLSServerResult(t, serverResults)
	if result.err != nil || result.negotiatedProtocol != "http/1.1" {
		t.Fatalf("server result = %+v", result)
	}
}

func TestCustomTLSWrapReturnsHandshakeError(t *testing.T) {
	listener := newBadUpstreamServer(t, func(conn net.Conn) {
		buf := make([]byte, 1)
		_, _ = conn.Read(buf)
		_, _ = conn.Write([]byte("HTTP/1.1 200 OK\r\n\r\n"))
	})
	handler := &TunnelHandler{
		DefaultTLSClient:  utls.HelloGolang.Client,
		DefaultTLSVersion: utls.HelloGolang.Version,
	}

	conn, err := net.DialTimeout("tcp", listener.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatalf("dial bad upstream: %v", err)
	}
	if err := conn.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("set client deadline: %v", err)
	}

	tlsConn, err := handler.customTLSWrap(conn, "upstream.test", []string{"http/1.1"})
	if err == nil {
		tlsConn.Close()
		t.Fatal("TunnelHandler.customTLSWrap() error = nil, want handshake error")
	}
	conn.Close()
}

func TestConnectMITMHandshakeAndRoundTrip(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "ca.pem")
	keyPath := filepath.Join(dir, "ca-key.pem")

	ca := certstore.CertificateAuthority{}
	if err := ca.Generate(certPath, keyPath); err != nil {
		t.Fatalf("certstore.CertificateAuthority.Generate() error = %v", err)
	}
	session := certstore.SessionKeyHelper{}
	if err := session.Generate(); err != nil {
		t.Fatalf("certstore.SessionKeyHelper.Generate() error = %v", err)
	}
	recorderInstance, err := recorder.New(recorder.Options{})
	if err != nil {
		t.Fatalf("recorder.New() error = %v", err)
	}
	handler := &TunnelHandler{
		CA:                &ca,
		SessionKey:        &session,
		Recorder:          recorderInstance,
		DefaultTLSClient:  utls.HelloGolang.Client,
		DefaultTLSVersion: utls.HelloGolang.Version,
	}

	const serverName = "target.test"
	deadline := time.Now().Add(5 * time.Second)
	destConn, upstreamPeer := net.Pipe()
	clientConn, clientPeer := net.Pipe()
	for _, conn := range []net.Conn{destConn, upstreamPeer, clientConn, clientPeer} {
		defer conn.Close()
		if err := conn.SetDeadline(deadline); err != nil {
			t.Fatalf("set deadline: %v", err)
		}
	}

	upstreamResult := make(chan connectUpstreamResult, 1)
	upstreamCert := localTLSCertificate(t)
	go serveConnectUpstream(upstreamPeer, upstreamCert, upstreamResult)

	connectDone := make(chan struct{})
	go func() {
		handler.Connect(serverName, destConn, clientConn)
		close(connectDone)
	}()

	roots := x509.NewCertPool()
	roots.AddCert(ca.X509Certificate())
	clientTLSConn := tls.Client(clientPeer, &tls.Config{
		ServerName: serverName,
		RootCAs:    roots,
		NextProtos: []string{"h2", "http/1.1"},
	})
	defer clientTLSConn.Close()
	if err := clientTLSConn.SetDeadline(deadline); err != nil {
		t.Fatalf("set client TLS deadline: %v", err)
	}

	if err := clientTLSConn.Handshake(); err != nil {
		t.Fatalf("client TLS handshake error = %v", err)
	}
	clientState := clientTLSConn.ConnectionState()
	if clientState.NegotiatedProtocol != "h2" {
		t.Fatalf("client negotiated protocol = %q, want h2", clientState.NegotiatedProtocol)
	}
	if len(clientState.PeerCertificates) == 0 {
		t.Fatal("client saw no peer certificate")
	}
	leaf := clientState.PeerCertificates[0]
	if leaf.Subject.CommonName != serverName {
		t.Fatalf("MITM certificate CN = %q, want %q", leaf.Subject.CommonName, serverName)
	}
	if err := leaf.CheckSignatureFrom(ca.X509Certificate()); err != nil {
		t.Fatalf("MITM certificate was not signed by test CA: %v", err)
	}

	request := []byte("ping through tunnel")
	if _, err := clientTLSConn.Write(request); err != nil {
		t.Fatalf("client write through tunnel: %v", err)
	}

	response := []byte("pong from upstream")
	got := make([]byte, len(response))
	if _, err := io.ReadFull(clientTLSConn, got); err != nil {
		t.Fatalf("client read upstream response: %v", err)
	}
	if string(got) != string(response) {
		t.Fatalf("client got response = %q, want %q", got, response)
	}

	result := receiveConnectUpstreamResult(t, upstreamResult)
	if result.err != nil {
		t.Fatalf("upstream TLS server error = %v", result.err)
	}
	if result.serverName != serverName {
		t.Fatalf("upstream saw SNI = %q, want %q", result.serverName, serverName)
	}
	if !reflect.DeepEqual(result.supportedProtos, []string{"h2", "http/1.1"}) {
		t.Fatalf("upstream saw client ALPN = %v, want [h2 http/1.1]", result.supportedProtos)
	}
	if result.negotiatedProtocol != "h2" {
		t.Fatalf("upstream negotiated protocol = %q, want h2", result.negotiatedProtocol)
	}
	if string(result.request) != string(request) {
		t.Fatalf("upstream got request = %q, want %q", result.request, request)
	}

	clientTLSConn.Close()
	select {
	case <-connectDone:
	case <-time.After(2 * time.Second):
		t.Fatal("connect did not return after client close")
	}
	if err := recorderInstance.Close(); err != nil {
		t.Fatalf("recorder.Close() error = %v", err)
	}
	var serverObservation *recorder.Observation
	for _, observation := range recorderInstance.Snapshot() {
		if observation.CapturePoint == "SERVER_IN" && observation.HandshakeEvent == "SERVER_HELLO" {
			copyObservation := observation
			serverObservation = &copyObservation
			break
		}
	}
	if serverObservation == nil || serverObservation.ServerFingerprints == nil || serverObservation.ServerFingerprints.JA3S == "" || serverObservation.HandshakeEvent != "SERVER_HELLO" || serverObservation.HandshakeSequence != 1 {
		t.Fatalf("missing upstream ServerHello observation: %+v", recorderInstance.Snapshot())
	}
	var negotiatedObservation *recorder.Observation
	for _, observation := range recorderInstance.Snapshot() {
		if observation.HandshakeEvent == "NEGOTIATED_STATE" {
			copyObservation := observation
			negotiatedObservation = &copyObservation
			break
		}
	}
	if negotiatedObservation == nil || negotiatedObservation.NegotiatedState == nil || negotiatedObservation.NegotiatedState.NegotiatedProtocol != "h2" || negotiatedObservation.NegotiatedState.ProtocolVersion != tls.VersionTLS13 || negotiatedObservation.NegotiatedState.HandshakeType != tlshello.HandshakeTypeFull {
		t.Fatalf("missing negotiated upstream TLS state: %+v", recorderInstance.Snapshot())
	}
}

func TestConnectMITMHandshakeRecordsTLS13HelloRetryRequest(t *testing.T) {
	store, err := tlsprofile.Open("")
	if err != nil {
		t.Fatalf("tlsprofile.Open() error = %v", err)
	}
	template, err := tlsprofile.TemplateFromPreset("Chrome HRR test", "Chrome", "70")
	if err != nil {
		t.Fatalf("tlsprofile.TemplateFromPreset() error = %v", err)
	}
	// The client advertises both groups but initially sends an X25519 key share.
	// The upstream server prefers P-256, which requires TLS 1.3 HelloRetryRequest.
	template.Fields.SupportedGroups = []uint16{uint16(tls.X25519), uint16(tls.CurveP256)}
	created, library, err := store.Create(template, 0)
	if err != nil {
		t.Fatalf("tlsprofile.Store.Create() error = %v", err)
	}
	if _, err := store.Activate(created.ID, library.ConfigVersion); err != nil {
		t.Fatalf("tlsprofile.Store.Activate() error = %v", err)
	}

	dir := t.TempDir()
	certPath := filepath.Join(dir, "ca.pem")
	keyPath := filepath.Join(dir, "ca-key.pem")
	ca := certstore.CertificateAuthority{}
	if err := ca.Generate(certPath, keyPath); err != nil {
		t.Fatalf("certstore.CertificateAuthority.Generate() error = %v", err)
	}
	session := certstore.SessionKeyHelper{}
	if err := session.Generate(); err != nil {
		t.Fatalf("certstore.SessionKeyHelper.Generate() error = %v", err)
	}
	recorderInstance, err := recorder.New(recorder.Options{})
	if err != nil {
		t.Fatalf("recorder.New() error = %v", err)
	}
	handler := &TunnelHandler{
		CA:                &ca,
		SessionKey:        &session,
		Recorder:          recorderInstance,
		TLSProfiles:       store,
		DefaultTLSClient:  utls.HelloGolang.Client,
		DefaultTLSVersion: utls.HelloGolang.Version,
	}

	const serverName = "target.test"
	deadline := time.Now().Add(5 * time.Second)
	upstreamListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen upstream: %v", err)
	}
	defer upstreamListener.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		conn, acceptErr := upstreamListener.Accept()
		if acceptErr != nil {
			accepted <- nil
			return
		}
		accepted <- conn
	}()
	destConn, err := net.Dial("tcp", upstreamListener.Addr().String())
	if err != nil {
		t.Fatalf("dial upstream: %v", err)
	}
	upstreamPeer := <-accepted
	if upstreamPeer == nil {
		t.Fatal("accept upstream connection failed")
	}
	clientConn, clientPeer := net.Pipe()
	for _, conn := range []net.Conn{destConn, upstreamPeer, clientConn, clientPeer} {
		defer conn.Close()
		if err := conn.SetDeadline(deadline); err != nil {
			t.Fatalf("set deadline: %v", err)
		}
	}

	upstreamResult := make(chan connectUpstreamResult, 1)
	upstreamCert := localTLSCertificate(t)
	go serveConnectUpstreamWithCurves(upstreamPeer, upstreamCert, []tls.CurveID{tls.CurveP256}, upstreamResult)

	connectDone := make(chan struct{})
	go func() {
		handler.Connect(serverName, destConn, clientConn)
		close(connectDone)
	}()

	roots := x509.NewCertPool()
	roots.AddCert(ca.X509Certificate())
	clientTLSConn := tls.Client(clientPeer, &tls.Config{
		ServerName: serverName,
		RootCAs:    roots,
		NextProtos: []string{"h2", "http/1.1"},
		MinVersion: tls.VersionTLS13,
		MaxVersion: tls.VersionTLS13,
	})
	defer clientTLSConn.Close()
	if err := clientTLSConn.SetDeadline(deadline); err != nil {
		t.Fatalf("set client TLS deadline: %v", err)
	}
	if err := clientTLSConn.Handshake(); err != nil {
		t.Fatalf("client TLS handshake error = %v", err)
	}
	if _, err := clientTLSConn.Write([]byte("ping through tunnel")); err != nil {
		t.Fatalf("client write through tunnel: %v", err)
	}
	response := make([]byte, len("pong from upstream"))
	if _, err := io.ReadFull(clientTLSConn, response); err != nil {
		t.Fatalf("client read upstream response: %v", err)
	}
	if string(response) != "pong from upstream" {
		t.Fatalf("client got response = %q, want pong from upstream", response)
	}

	result := receiveConnectUpstreamResult(t, upstreamResult)
	if result.err != nil {
		t.Fatalf("upstream TLS server error = %v", result.err)
	}
	if string(result.request) != "ping through tunnel" {
		t.Fatalf("upstream got request = %q, want ping through tunnel", result.request)
	}

	clientTLSConn.Close()
	select {
	case <-connectDone:
	case <-time.After(2 * time.Second):
		t.Fatal("connect did not return after client close")
	}
	if err := recorderInstance.Close(); err != nil {
		t.Fatalf("recorder.Close() error = %v", err)
	}

	var retry, final *recorder.Observation
	for _, observation := range recorderInstance.Snapshot() {
		if observation.CapturePoint != "SERVER_IN" {
			continue
		}
		copyObservation := observation
		switch observation.HandshakeEvent {
		case tlshello.HelloRetryRequestType:
			retry = &copyObservation
		case "SERVER_HELLO":
			final = &copyObservation
		}
	}
	if retry == nil || retry.HandshakeSequence != 1 || retry.ServerFingerprints == nil || retry.ServerFingerprints.JA3S == "" {
		t.Fatalf("missing TLS 1.3 HelloRetryRequest observation: %+v", recorderInstance.Snapshot())
	}
	if final == nil || final.HandshakeSequence != 2 || final.ServerFingerprints == nil || final.ServerFingerprints.JA3S == "" {
		t.Fatalf("missing final TLS 1.3 ServerHello observation: %+v", recorderInstance.Snapshot())
	}
}

func TestMITMClientHelloAfterHelloRetryRequestIsRecorded(t *testing.T) {
	recorderInstance, err := recorder.New(recorder.Options{})
	if err != nil {
		t.Fatalf("recorder.New() error = %v", err)
	}
	defer recorderInstance.Close()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	serverResultConn := make(chan net.Conn, 1)
	go func() {
		accepted, acceptErr := listener.Accept()
		if acceptErr != nil {
			serverResultConn <- nil
			return
		}
		serverResultConn <- accepted
	}()
	clientConn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	serverConn := <-serverResultConn
	if serverConn == nil {
		t.Fatal("accept test connection failed")
	}
	defer serverConn.Close()
	defer clientConn.Close()
	deadline := time.Now().Add(3 * time.Second)
	if err := serverConn.SetDeadline(deadline); err != nil {
		t.Fatal(err)
	}
	if err := clientConn.SetDeadline(deadline); err != nil {
		t.Fatal(err)
	}
	meta := recorder.Meta{
		ConnectionID: "hrr-client-capture", CapturePoint: "CLIENT_IN", Direction: "inbound",
		ByteSource: "client_socket_read", Mode: "MITM_REISSUE",
	}
	var serverHellos []tlshello.Capture
	serverObserved := tlshello.WrapServerHello(serverConn, false, tlshello.DefaultLimits(), func(capture tlshello.Capture) {
		serverHellos = append(serverHellos, capture)
	})
	observedConn := wrapClientHelloRetryCapture(serverObserved, meta, &TunnelHandler{Recorder: recorderInstance})
	serverTLS := tls.Server(observedConn, &tls.Config{
		Certificates:     []tls.Certificate{localTLSCertificate(t)},
		MinVersion:       tls.VersionTLS13,
		MaxVersion:       tls.VersionTLS13,
		CurvePreferences: []tls.CurveID{tls.CurveP256},
	})
	serverResult := make(chan error, 1)
	go func() { serverResult <- serverTLS.Handshake() }()

	clientTLS := tls.Client(clientConn, &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS13,
		MaxVersion:         tls.VersionTLS13,
		CurvePreferences:   []tls.CurveID{tls.X25519, tls.CurveP256},
	})
	if err := clientTLS.Handshake(); err != nil {
		t.Fatalf("TLS 1.3 handshake with HRR failed: %v", err)
	}
	if err := <-serverResult; err != nil {
		t.Fatalf("TLS server handshake with HRR failed: %v", err)
	}
	if len(serverHellos) < 2 {
		t.Fatalf("TLS handshake did not produce HRR and final ServerHello: %+v", serverHellos)
	}
	firstServerHello, err := tlshello.ParseServerHello(serverHellos[0].Raw)
	if err != nil || !firstServerHello.Fields.HelloRetryRequest.Value {
		t.Fatalf("first ServerHello is not HRR: %+v, %v", serverHellos[0], err)
	}
	if err := recorderInstance.Close(); err != nil {
		t.Fatalf("recorder.Close() error = %v", err)
	}

	var second *recorder.Observation
	for _, observation := range recorderInstance.Snapshot() {
		if observation.HandshakeEvent == "CLIENT_HELLO_AFTER_HRR" {
			copyObservation := observation
			second = &copyObservation
		}
	}
	if second == nil || second.CapturePoint != "CLIENT_IN" || second.HandshakeSequence != 2 || second.Fingerprints == nil || second.Fingerprints.JA3 == "" {
		t.Fatalf("missing post-HRR ClientHello observation: %+v; server hellos: %+v", recorderInstance.Snapshot(), serverHellos)
	}
}

func TestUpstreamSessionCacheIsolatedByEffectiveProfile(t *testing.T) {
	handler := &TunnelHandler{}
	profile := fingerprint.TLSFingerprint{Client: utls.HelloGolang.Client, Version: utls.HelloGolang.Version}
	first := handler.getUpstreamSessionCache(profile, []string{"http/1.1"})
	session := &utls.ClientSessionState{}
	first.Put("example.test", session)
	if got, ok := handler.getUpstreamSessionCache(profile, []string{"http/1.1"}).Get("example.test"); !ok || got != session {
		t.Fatal("same profile and ALPN did not reuse the cached session")
	}
	if _, ok := handler.getUpstreamSessionCache(profile, []string{"h2"}).Get("example.test"); ok {
		t.Fatal("different ALPN reused a cached session")
	}
	otherProfile := profile
	otherProfile.Version = "different-version"
	if _, ok := handler.getUpstreamSessionCache(otherProfile, []string{"http/1.1"}).Get("example.test"); ok {
		t.Fatal("different TLS profile reused a cached session")
	}
	if _, ok := first.Get("other.test"); ok {
		t.Fatal("different server reused a cached session")
	}
	first.Put("example.test", nil)
	if _, ok := first.Get("example.test"); ok {
		t.Fatal("cached session was not removed within its own scope")
	}
}

func TestUpstreamTLS13SessionCacheRecordsResumptionClientHello(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	serverResumeResults := make(chan bool, 2)
	serverErrors := make(chan error, 2)
	serverConfig := &tls.Config{
		Certificates:     []tls.Certificate{localTLSCertificate(t)},
		MinVersion:       tls.VersionTLS13,
		MaxVersion:       tls.VersionTLS13,
		CurvePreferences: []tls.CurveID{tls.X25519, tls.CurveP256},
	}
	go func() {
		for range 2 {
			rawConn, acceptErr := listener.Accept()
			if acceptErr != nil {
				serverErrors <- acceptErr
				return
			}
			serverConn := tls.Server(rawConn, serverConfig)
			if handshakeErr := serverConn.Handshake(); handshakeErr != nil {
				serverErrors <- handshakeErr
				return
			}
			serverResumeResults <- serverConn.ConnectionState().DidResume
			if _, writeErr := serverConn.Write([]byte("r")); writeErr != nil {
				serverErrors <- writeErr
				return
			}
			request := make([]byte, 1)
			if _, readErr := io.ReadFull(serverConn, request); readErr != nil {
				serverErrors <- readErr
				return
			}
			_ = serverConn.Close()
		}
	}()

	handler := &TunnelHandler{}
	profile := upstreamtls.UpstreamTLSProfile{Protocol: upstreamtls.ProtocolUTLS, Client: utls.HelloGolang.Client, Version: utls.HelloGolang.Version}
	for attempt := 0; attempt < 2; attempt++ {
		rawConn, dialErr := net.DialTimeout("tcp", listener.Addr().String(), time.Second)
		if dialErr != nil {
			t.Fatal(dialErr)
		}
		_ = rawConn.SetDeadline(time.Now().Add(3 * time.Second))
		var captures []tlshello.Capture
		observedConn := tlshello.Wrap(rawConn, false, tlshello.DefaultLimits(), func(capture tlshello.Capture) {
			captures = append(captures, capture)
		})
		clientTLS, wrapErr := handler.wrapUpstreamTLSProfile(observedConn, "upstream.test", []string{"http/1.1"}, profile)
		if wrapErr != nil {
			t.Fatalf("upstream TLS handshake %d: %v", attempt+1, wrapErr)
		}
		if resumed := clientTLS.ConnectionState().DidResume; resumed != (attempt == 1) {
			t.Fatalf("upstream client handshake %d resumed=%v", attempt+1, resumed)
		}
		response := make([]byte, 1)
		if _, readErr := io.ReadFull(clientTLS, response); readErr != nil || string(response) != "r" {
			t.Fatalf("read session ticket/application data: %q, %v", response, readErr)
		}
		if _, writeErr := clientTLS.Write([]byte("q")); writeErr != nil {
			t.Fatalf("write application data: %v", writeErr)
		}
		if len(captures) != 1 || captures[0].Status != "complete" {
			t.Fatalf("outbound ClientHello capture = %+v", captures)
		}
		hello, parseErr := tlshello.Parse(captures[0].Raw)
		if parseErr != nil {
			t.Fatal(parseErr)
		}
		fingerprints, fingerprintErr := tlshello.Calculate(hello, captures[0].Raw, captures[0].Records)
		if fingerprintErr != nil || fingerprints.JA4 == "" {
			t.Fatalf("calculate ClientHello fingerprint for attempt %d: %+v, %v", attempt+1, fingerprints, fingerprintErr)
		}
		if attempt == 0 && hello.PSKPresent {
			t.Fatal("first ClientHello unexpectedly offered PSK")
		}
		if attempt == 1 && (!hello.PSKPresent || hello.HandshakeType != tlshello.HandshakeTypePSK) {
			t.Fatalf("second ClientHello did not offer PSK resumption: %+v", hello)
		}
		_ = clientTLS.Close()
	}
	if <-serverResumeResults {
		t.Fatal("first upstream TLS handshake unexpectedly resumed")
	}
	if !<-serverResumeResults {
		t.Fatal("second upstream TLS handshake did not resume")
	}
	select {
	case err := <-serverErrors:
		t.Fatal(err)
	default:
	}
}
