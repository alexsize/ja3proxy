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

	"github.com/lylemi/ja3proxy/internal/ja3proxy/certstore"
	"github.com/lylemi/ja3proxy/internal/ja3proxy/device"
	"github.com/lylemi/ja3proxy/internal/ja3proxy/fingerprint"
	"github.com/lylemi/ja3proxy/internal/ja3proxy/flowid"
	"github.com/lylemi/ja3proxy/internal/ja3proxy/recorder"
	"github.com/lylemi/ja3proxy/internal/ja3proxy/routing"
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

func TestRoutingSnapshotKeepsTwoPhaseEvidenceWithoutActionSecrets(t *testing.T) {
	pre := routing.Decision{
		ConfigVersion: 4, Phase: routing.PhasePreTLS, MatchedRuleID: "pre-route",
		MatchedRulePriority: 3, MatchReason: "exact",
	}
	snapshot := routingSnapshot(pre)
	if snapshot == nil || snapshot.PreTLS == nil || snapshot.PreTLS.ConfigVersion != 4 || snapshot.PreTLS.MatchedRuleID != "pre-route" {
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
	handler := &TunnelHandler{
		CA:                &ca,
		SessionKey:        &session,
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
}
