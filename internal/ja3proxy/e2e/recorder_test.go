package e2e

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lylemi/ja3proxy/internal/ja3proxy/capture/tlshello"
	"github.com/lylemi/ja3proxy/internal/ja3proxy/dialer"
	httpproxy "github.com/lylemi/ja3proxy/internal/ja3proxy/proxy"
	"github.com/lylemi/ja3proxy/internal/ja3proxy/recorder"
	"github.com/lylemi/ja3proxy/internal/ja3proxy/tlsprofile"
	"github.com/lylemi/ja3proxy/internal/ja3proxy/upstreamtls"
	utls "github.com/refraction-networking/utls"
)

type utlsWireBaseline struct {
	SchemaVersion    string `json:"schema_version"`
	UTLSVersion      string `json:"utls_version"`
	JA3              string `json:"ja3"`
	JA3Hash          string `json:"ja3_hash"`
	JA4              string `json:"ja4"`
	NormalizedSHA256 string `json:"normalized_sha256"`
}

func serveMixedRecorderProxy(t *testing.T, p *httpproxy.Proxy) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	mixed := httpproxy.NewMixedProxyListener(l, p)
	s := &http.Server{Handler: p}
	done := make(chan struct{})
	go func() { defer close(done); _ = s.Serve(mixed) }()
	t.Cleanup(func() { s.Close(); mixed.Close(); <-done })
	return l.Addr().String()
}

func recordedPair(t *testing.T, r *recorder.Recorder) (recorder.Observation, recorder.Observation) {
	t.Helper()
	deadline := time.NewTimer(3 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for {
		items := r.Snapshot()
		var in, out *recorder.Observation
		for _, o := range items {
			v := o
			if o.Direction == "inbound" {
				in = &v
			} else if o.Direction == "outbound" {
				out = &v
			}
		}
		if in != nil && out != nil {
			return *in, *out
		}
		select {
		case <-deadline.C:
			t.Fatalf("missing observations: %+v", items)
		case <-ticker.C:
		}
	}
}

func TestRecorderOutboundWireThroughProxyMatrix(t *testing.T) {
	for _, downstream := range []string{"http", "socks5"} {
		for _, upstream := range []string{"direct", "http", "socks5"} {
			for _, mode := range []string{"MITM_REISSUE", "PASSTHROUGH", "OBSERVE_ONLY"} {
				t.Run(downstream+"/"+upstream+"/"+mode, func(t *testing.T) {
					r, err := recorder.New(recorder.Options{Raw: true})
					if err != nil {
						t.Fatal(err)
					}
					defer r.Close()
					handler := newTestTunnelHandler(t, utls.HelloFirefox_63)
					handler.Recorder = r
					handler.Mode = mode
					serverAddr, results := newJA3CaptureTLSServer(t)
					upstreamURL := ""
					if upstream != "direct" {
						addr := serveMixedRecorderProxy(t, httpproxy.NewProxy(nil, nil, nil))
						upstreamURL = upstream + "://" + addr
					}
					up, err := dialer.NewUpstreamDialer(upstreamURL, 3*time.Second)
					if err != nil {
						t.Fatal(err)
					}
					proxyAddr := serveMixedRecorderProxy(t, httpproxy.NewProxy(up.Dial, handler.Connect, up.Transport).WithTLSInspection(true))
					client := newProxyHTTPClient(t, downstream+"://"+proxyAddr, &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"http/1.1"}})
					response, err := client.Get("https://" + serverAddr + "/wire")
					if err != nil {
						t.Fatal(err)
					}
					body, err := io.ReadAll(response.Body)
					response.Body.Close()
					if err != nil || string(body) != "ok" {
						t.Fatalf("body=%q err=%v", body, err)
					}
					wire := receiveJA3CaptureResult(t, results)
					if wire.err != nil {
						t.Fatal(wire.err)
					}
					in, out := recordedPair(t, r)
					if in.Completeness != "complete" || out.Completeness != "complete" {
						t.Fatalf("capture: %+v %+v", in, out)
					}
					if in.ConnectionID != out.ConnectionID || in.ConnectionID == "" {
						t.Fatal("unrelated captures")
					}
					if !bytes.Equal(out.Records, wire.rawClientHello) {
						t.Fatal("recorder differs from independent server wire capture")
					}
					if out.Fingerprints.JA3 != wire.ja3 || out.Fingerprints.JA3Hash != wire.ja3Fingerprint {
						t.Fatalf("JA3 differs: recorder %q (%s), server %q (%s)", out.Fingerprints.JA3, out.Fingerprints.JA3Hash, wire.ja3, wire.ja3Fingerprint)
					}
					if downstream == "http" && upstream == "direct" && mode == "MITM_REISSUE" {
						assertUTLSWireBaseline(t, out.Fingerprints)
					}
					reparsedHello, err := tlshello.Parse(out.Raw)
					if err != nil {
						t.Fatalf("reparse captured outbound ClientHello: %v", err)
					}
					reparsedFingerprints, err := tlshello.Calculate(reparsedHello, out.Raw, out.Records)
					if err != nil {
						t.Fatalf("recalculate captured outbound fingerprints: %v", err)
					}
					if out.Fingerprints.JA4 != reparsedFingerprints.JA4 || out.Fingerprints.NormalizedSHA256 != reparsedFingerprints.NormalizedSHA256 || !bytes.Equal(out.Fingerprints.Normalized, reparsedFingerprints.Normalized) {
						t.Fatalf("fingerprint does not match captured wire bytes: stored=%+v reparsed=%+v", out.Fingerprints, reparsedFingerprints)
					}
					if mode != "MITM_REISSUE" {
						if out.Profile != "" || !bytes.Equal(in.Raw, out.Raw) || !bytes.Equal(in.Records, out.Records) {
							t.Fatal("passthrough changed or incorrectly labelled")
						}
						if out.Forwarding == nil || out.Forwarding.Status != "FORWARDED_UNCHANGED" {
							t.Fatalf("passthrough forwarding verification = %+v", out.Forwarding)
						}
						if recorder.Compare(in, out).Status != "MATCH" {
							t.Fatal("passthrough diff")
						}
					} else if out.Profile == "" || bytes.Equal(in.Raw, out.Raw) {
						t.Fatal("MITM capture or profile missing")
					}
				})
			}
		}
	}
}

func assertUTLSWireBaseline(t *testing.T, actual *tlshello.Fingerprints) {
	t.Helper()
	if actual == nil {
		t.Fatal("outbound wire fingerprints are missing")
	}
	baselinePath := filepath.Join("testdata", "utls-wire-baseline.json")
	baselineBytes, err := os.ReadFile(baselinePath)
	if err != nil {
		t.Fatalf("read uTLS wire baseline %s: %v", baselinePath, err)
	}
	var expected utlsWireBaseline
	if err := json.Unmarshal(baselineBytes, &expected); err != nil {
		t.Fatalf("decode uTLS wire baseline: %v", err)
	}
	actualBaseline := utlsWireBaseline{
		SchemaVersion:    "ja3proxy-utls-wire-baseline/1",
		UTLSVersion:      linkedUTLSVersion(t),
		JA3:              actual.JA3,
		JA3Hash:          actual.JA3Hash,
		JA4:              actual.JA4,
		NormalizedSHA256: actual.NormalizedSHA256,
	}
	if expected != actualBaseline {
		wantJSON, _ := json.MarshalIndent(expected, "    ", "  ")
		gotJSON, _ := json.MarshalIndent(actualBaseline, "    ", "  ")
		t.Errorf("uTLS outbound wire baseline drift:\n  want:\n    %s\n   got:\n    %s", wantJSON, gotJSON)
	}
}

func linkedUTLSVersion(t *testing.T) string {
	t.Helper()
	goMod, err := os.ReadFile(filepath.Join("..", "..", "..", "go.mod"))
	if err != nil {
		t.Fatalf("read go.mod to verify uTLS pin: %v", err)
	}
	for _, line := range strings.Split(string(goMod), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[0] == "github.com/refraction-networking/utls" {
			return fields[1]
		}
	}
	t.Fatal("uTLS dependency missing from go.mod")
	return ""
}

func TestRecorderKeepsHelloWhenClientRejectsCA(t *testing.T) {
	r, err := recorder.New(recorder.Options{Raw: true})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	handler := newTestTunnelHandler(t, utls.HelloGolang)
	handler.Recorder = r
	target := newLocalHTTPSTarget(t)
	up, err := dialer.NewUpstreamDialer("", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	addr := serveMixedRecorderProxy(t, httpproxy.NewProxy(up.Dial, handler.Connect, up.Transport).WithTLSInspection(true))
	client := newProxyHTTPClient(t, "http://"+addr, &tls.Config{})
	response, err := client.Get(target)
	if response != nil {
		response.Body.Close()
	}
	if err == nil {
		t.Fatal("untrusted CA accepted")
	}
	in, out := recordedPair(t, r)
	if in.Completeness != "complete" || out.Completeness != "complete" || len(in.Raw) == 0 {
		t.Fatal("lost ClientHello after TLS failure")
	}
}

func newLocalHTTPSTarget(t *testing.T) string {
	t.Helper()
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "ok") }))
	t.Cleanup(s.Close)
	return s.URL
}

func TestRecorderNonTLSFallbackPreservesBytes(t *testing.T) {
	r, _ := recorder.New(recorder.Options{Raw: true})
	defer r.Close()
	h := newTestTunnelHandler(t, utls.HelloGolang)
	h.Recorder = r
	client, proxyIn := net.Pipe()
	proxyOut, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	client.SetDeadline(time.Now().Add(2 * time.Second))
	server.SetDeadline(time.Now().Add(2 * time.Second))
	done := make(chan struct{})
	go func() { defer close(done); h.Connect("non-tls.test", proxyOut, proxyIn) }()
	request := []byte("PLAIN TCP CANARY\r\n")
	received := make(chan []byte, 1)
	go func() {
		p := make([]byte, len(request))
		_, _ = io.ReadFull(server, p)
		received <- p
		server.Write([]byte("ok"))
		server.Close()
	}()
	if _, err := client.Write(request); err != nil {
		t.Fatal(err)
	}
	reply, _ := io.ReadAll(client)
	if string(reply) != "ok" || !bytes.Equal(<-received, request) {
		t.Fatal("fallback did not replay bytes")
	}
	client.Close()
	<-done
	in, out := recordedPair(t, r)
	if in.Mode != "PASSTHROUGH" || out.Profile != "" || in.Completeness != "not_tls" {
		t.Fatal("fallback incorrectly labelled")
	}
}

func TestRecorderTLS12And13(t *testing.T) {
	for _, version := range []uint16{tls.VersionTLS12, tls.VersionTLS13} {
		t.Run(tls.VersionName(version), func(t *testing.T) {
			r, _ := recorder.New(recorder.Options{})
			defer r.Close()
			h := newTestTunnelHandler(t, utls.HelloGolang)
			h.Recorder = r
			target := newLocalHTTPSTarget(t)
			up, _ := dialer.NewUpstreamDialer("", time.Second)
			addr := serveMixedRecorderProxy(t, httpproxy.NewProxy(up.Dial, h.Connect, up.Transport).WithTLSInspection(true))
			client := newProxyHTTPClient(t, "http://"+addr, &tls.Config{InsecureSkipVerify: true, MinVersion: version, MaxVersion: version})
			response, err := client.Get(target)
			if err != nil {
				t.Fatal(err)
			}
			io.Copy(io.Discard, response.Body)
			response.Body.Close()
			in, _ := recordedPair(t, r)
			want := "t12"
			if version == tls.VersionTLS13 {
				want = "t13"
			}
			if in.Fingerprints == nil || !strings.HasPrefix(in.Fingerprints.JA4, want) {
				t.Fatalf("wrong advertised TLS version: %+v", in)
			}
		})
	}
}

func TestCustomTLSProfileProducesExpectedJA4AndVerification(t *testing.T) {
	store, err := tlsprofile.Open("")
	if err != nil {
		t.Fatal(err)
	}
	template, err := tlsprofile.TemplateFromPreset("Редактируемый Chrome", "Chrome", "120")
	if err != nil {
		t.Fatal(err)
	}
	template.ProfileMode = tlsprofile.ProfileModeAdaptive
	template.Fields.ALPN = []string{"h2", "http/1.1"}
	created, library, err := store.Create(template, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Activate(created.ID, library.ConfigVersion); err != nil {
		t.Fatal(err)
	}

	r, err := recorder.New(recorder.Options{Raw: true})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	handler := newTestTunnelHandler(t, utls.HelloFirefox_63)
	handler.Recorder = r
	handler.TLSProfiles = store
	upstreamProfiles := &upstreamtls.UpstreamTLSProfileStore{}
	upstreamProfiles.Set(upstreamtls.UpstreamTLSConfig{
		Routes: []upstreamtls.UpstreamTLSRoute{{
			ID:       "localhost-route",
			Host:     "localhost",
			Priority: 3,
			UpstreamTLSProfile: upstreamtls.UpstreamTLSProfile{
				Protocol: upstreamtls.ProtocolUTLS,
				Client:   utls.HelloGolang.Client,
				Version:  utls.HelloGolang.Version,
			},
		}},
	})
	handler.UpstreamTLSProfiles = upstreamProfiles
	serverAddr, results := newJA3CaptureTLSServer(t)
	_, port, err := net.SplitHostPort(serverAddr)
	if err != nil {
		t.Fatal(err)
	}
	up, err := dialer.NewUpstreamDialer("", 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	proxyAddr := serveMixedRecorderProxy(t, httpproxy.NewProxy(up.Dial, handler.Connect, up.Transport).WithTLSInspection(true))
	client := newProxyHTTPClient(t, "http://"+proxyAddr, &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"http/1.1"}})
	response, err := client.Get("https://localhost:" + port + "/profile")
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	wire := receiveJA3CaptureResult(t, results)
	if wire.err != nil {
		t.Fatal(wire.err)
	}
	_, outbound := recordedPair(t, r)
	if outbound.ProfileID != created.ID || outbound.ProfileVersion != 1 {
		t.Fatalf("profile snapshot missing: %+v", outbound.Meta)
	}
	if outbound.ConfigVersion != library.ConfigVersion+1 || outbound.ByteSource != "upstream_socket_successful_write" {
		t.Fatalf("config/byte source snapshot missing: %+v", outbound.Meta)
	}
	if outbound.UpstreamConfigVersion != 1 {
		t.Fatalf("upstream config snapshot missing: %+v", outbound.Meta)
	}
	if outbound.MatchedRouteID != "localhost-route" || outbound.MatchedRoutePriority == nil || *outbound.MatchedRoutePriority != 3 || outbound.RouteMatchReason != "exact" {
		t.Fatalf("upstream route evidence missing: %+v", outbound.Meta)
	}
	if outbound.Verification == nil || outbound.Verification.Status != "MATCH" {
		t.Fatalf("verification = %+v", outbound.Verification)
	}
	if outbound.Verification.Expected.JA4 != outbound.Fingerprints.JA4 || outbound.Fingerprints.JA3Hash != wire.ja3Fingerprint {
		t.Fatalf("expected/actual mismatch: %+v", outbound.Verification)
	}
	mutationFound := false
	for _, mutation := range outbound.RuntimeMutations {
		if mutation.Field == "ALPN" && mutation.Reason != "" && mutation.Before != nil && mutation.After != nil {
			mutationFound = true
		}
	}
	if !mutationFound {
		t.Fatalf("adaptive ALPN mutation missing from outbound observation: %+v", outbound.RuntimeMutations)
	}
}

func TestStrictProfileProtocolConflictIsReported(t *testing.T) {
	store, err := tlsprofile.Open("")
	if err != nil {
		t.Fatal(err)
	}
	template, err := tlsprofile.TemplateFromPreset("Strict h2", "Chrome", "120")
	if err != nil {
		t.Fatal(err)
	}
	template.ProfileMode = tlsprofile.ProfileModeStrict
	template.Fields.ALPN = []string{"h2"}
	template.Fields.ALPNPolicy = tlsprofile.ALPNPolicyProfile
	created, library, err := store.Create(template, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Activate(created.ID, library.ConfigVersion); err != nil {
		t.Fatal(err)
	}
	r, err := recorder.New(recorder.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	handler := newTestTunnelHandler(t, utls.HelloFirefox_63)
	handler.Recorder = r
	handler.TLSProfiles = store
	upstream, err := dialer.NewUpstreamDialer("", 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	proxyAddr := serveMixedRecorderProxy(t, httpproxy.NewProxy(upstream.Dial, handler.Connect, upstream.Transport).WithTLSInspection(true))
	client := newProxyHTTPClient(t, "http://"+proxyAddr, &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"http/1.1"}})
	target := newLocalHTTPSTarget(t)
	response, requestErr := client.Get(target)
	if response != nil {
		response.Body.Close()
	}
	if requestErr == nil {
		t.Fatal("STRICT profile unexpectedly adapted incompatible h2 ALPN")
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	for _, observation := range r.Snapshot() {
		if observation.ErrorCode == "PROFILE_PROTOCOL_CONFLICT" {
			if observation.Completeness != "policy_conflict" || observation.ErrorStage != "policy" || observation.ProfileID != created.ID {
				t.Fatalf("incorrect conflict observation: %+v", observation)
			}
			return
		}
	}
	t.Fatalf("PROFILE_PROTOCOL_CONFLICT was not reported: %+v", r.Snapshot())
}
