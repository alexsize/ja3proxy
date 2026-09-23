package e2e

import (
	"bytes"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/lylemi/ja3proxy/internal/ja3proxy/dialer"
	httpproxy "github.com/lylemi/ja3proxy/internal/ja3proxy/proxy"
	"github.com/lylemi/ja3proxy/internal/ja3proxy/recorder"
	"github.com/lylemi/ja3proxy/internal/ja3proxy/tlsprofile"
	utls "github.com/refraction-networking/utls"
)

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
	template.Fields.ALPN = []string{"http/1.1"}
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
	if outbound.Verification == nil || outbound.Verification.Status != "MATCH" {
		t.Fatalf("verification = %+v", outbound.Verification)
	}
	if outbound.Verification.Expected.JA4 != outbound.Fingerprints.JA4 || outbound.Fingerprints.JA3Hash != wire.ja3Fingerprint {
		t.Fatalf("expected/actual mismatch: %+v", outbound.Verification)
	}
}
