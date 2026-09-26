package dialer

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lylemi/ja3proxy/internal/ja3proxy/secrets"
)

func TestResolveProxyCredentialsFromSecretFiles(t *testing.T) {
	dir := t.TempDir()
	usernamePath := filepath.Join(dir, "upstream-user")
	passwordPath := filepath.Join(dir, "upstream-password")
	if err := os.WriteFile(usernamePath, []byte("proxy-user"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(passwordPath, []byte("proxy-password"), 0600); err != nil {
		t.Fatal(err)
	}
	configured := (&url.URL{
		Scheme: "http", Host: "127.0.0.1:8080",
		User: url.UserPassword("file:"+usernamePath, "file:"+passwordPath),
	}).String()
	parsed, err := parseProxyURL(configured)
	if err != nil {
		t.Fatal(err)
	}
	if err := resolveProxyCredentials(parsed, secrets.FileProvider{}); err != nil {
		t.Fatal(err)
	}
	username := parsed.User.Username()
	password, ok := parsed.User.Password()
	if !ok || username != "proxy-user" || password != "proxy-password" {
		t.Fatalf("resolved upstream credentials = %q/%q, want file contents", username, password)
	}
	upstream, err := NewUpstreamDialerWithProvider(configured, time.Second, secrets.FileProvider{})
	if err != nil {
		t.Fatalf("NewUpstreamDialerWithProvider() error = %v", err)
	}
	connectDialer, ok := upstream.dialer.(*httpConnectDialer)
	if !ok {
		t.Fatalf("upstream.dialer = %T, want HTTP CONNECT dialer", upstream.dialer)
	}
	resolvedPassword, _ := connectDialer.proxyURL.User.Password()
	if connectDialer.proxyURL.User.Username() != "proxy-user" || resolvedPassword != "proxy-password" {
		t.Fatal("HTTP CONNECT dialer did not receive resolved credentials")
	}
}

func TestResolveProxyCredentialsRejectsMissingSecretFile(t *testing.T) {
	parsed, err := parseProxyURL("http://user:file%3AC%3A%5Cmissing%5Csecret@127.0.0.1:8080")
	if err != nil {
		t.Fatal(err)
	}
	if err := resolveProxyCredentials(parsed, secrets.FileProvider{}); err == nil {
		t.Fatal("missing password reference was accepted")
	}
}

func TestNewUpstreamDialerDirect(t *testing.T) {
	timeout := 3 * time.Second

	upstream, err := NewUpstreamDialer("", timeout)
	if err != nil {
		t.Fatalf("NewUpstreamDialer() error = %v", err)
	}
	if upstream == nil {
		t.Fatal("expected upstream dialer")
	}

	netDialer, ok := upstream.dialer.(*net.Dialer)
	if !ok {
		t.Fatalf("upstream.dialer = %T, want *net.Dialer", upstream.dialer)
	}
	if netDialer.Timeout != timeout {
		t.Fatalf("net.Dialer timeout = %v, want %v", netDialer.Timeout, timeout)
	}
	transport, ok := upstream.Transport.(*http.Transport)
	if !ok || transport == http.DefaultTransport {
		t.Fatalf("upstream.Transport = %T, want dedicated *http.Transport", upstream.Transport)
	}
	if transport.Proxy != nil {
		t.Fatal("direct transport unexpectedly uses an environment proxy")
	}
}

func TestUpstreamDialerDialLocalTCP(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()

	serverErr := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			serverErr <- err
			return
		}
		defer conn.Close()
		if err := conn.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
			serverErr <- err
			return
		}

		buf := make([]byte, len("ping"))
		if _, err := io.ReadFull(conn, buf); err != nil {
			serverErr <- err
			return
		}
		if string(buf) != "ping" {
			serverErr <- fmt.Errorf("payload = %q, want %q", buf, "ping")
			return
		}
		_, err = conn.Write([]byte("pong"))
		serverErr <- err
	}()

	upstream, err := NewUpstreamDialer("", time.Second)
	if err != nil {
		t.Fatalf("NewUpstreamDialer() error = %v", err)
	}

	conn, err := upstream.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatalf("Dial() error = %v", err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}

	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatalf("write to server: %v", err)
	}
	got := make([]byte, len("pong"))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read from server: %v", err)
	}
	if string(got) != "pong" {
		t.Fatalf("response = %q, want pong", got)
	}

	select {
	case err := <-serverErr:
		if err != nil {
			t.Fatalf("server error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("server timed out")
	}
}

func TestNewUpstreamDialerSocksURLValidation(t *testing.T) {
	tests := []struct {
		name      string
		socksAddr string
		wantErr   bool
	}{
		{name: "readme host port", socksAddr: "127.0.0.1:1080"},
		{name: "socks5 url", socksAddr: "socks5://127.0.0.1:1080"},
		{name: "invalid url", socksAddr: "%", wantErr: true},
		{name: "missing host", socksAddr: "socks5://", wantErr: true},
		{name: "http url", socksAddr: "http://127.0.0.1:3128"},
		{name: "unsupported scheme", socksAddr: "https://127.0.0.1:1080", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			upstream, err := NewUpstreamDialer(tt.socksAddr, time.Second)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("NewUpstreamDialer() error = %v", err)
			}
			if upstream == nil || upstream.dialer == nil {
				t.Fatal("expected upstream dialer")
			}
		})
	}
}

func TestHTTPUpstreamCONNECTWithAuthentication(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()

	serverErr := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			serverErr <- err
			return
		}
		defer conn.Close()
		request, err := http.ReadRequest(bufio.NewReader(conn))
		if err != nil {
			serverErr <- err
			return
		}
		if request.Method != http.MethodConnect || request.Host != "example.com:443" {
			serverErr <- fmt.Errorf("request = %s %s", request.Method, request.Host)
			return
		}
		wantAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte("user:pass"))
		if got := request.Header.Get("Proxy-Authorization"); got != wantAuth {
			serverErr <- fmt.Errorf("Proxy-Authorization = %q, want %q", got, wantAuth)
			return
		}
		if _, err := conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\nprefetched")); err != nil {
			serverErr <- err
			return
		}
		payload := make([]byte, len("ping"))
		if _, err := io.ReadFull(conn, payload); err != nil {
			serverErr <- err
			return
		}
		if string(payload) != "ping" {
			serverErr <- fmt.Errorf("payload = %q", payload)
			return
		}
		_, err = conn.Write([]byte("pong"))
		serverErr <- err
	}()

	upstream, err := NewUpstreamDialer("http://user:pass@"+listener.Addr().String(), time.Second)
	if err != nil {
		t.Fatalf("NewUpstreamDialer() error = %v", err)
	}
	conn, err := upstream.Dial("tcp", "example.com:443")
	if err != nil {
		t.Fatalf("Dial() error = %v", err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}

	prefetched := make([]byte, len("prefetched"))
	if _, err := io.ReadFull(conn, prefetched); err != nil || string(prefetched) != "prefetched" {
		t.Fatalf("prefetched data = %q, err = %v", prefetched, err)
	}
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatalf("write tunnel: %v", err)
	}
	response := make([]byte, len("pong"))
	if _, err := io.ReadFull(conn, response); err != nil || string(response) != "pong" {
		t.Fatalf("tunnel response = %q, err = %v", response, err)
	}
	if err := <-serverErr; err != nil {
		t.Fatalf("HTTP proxy: %v", err)
	}
}

func TestHTTPUpstreamCONNECTErrorDoesNotExposeResponseBodyCanary(t *testing.T) {
	const canary = "CANARY_UPSTREAM_SECRET_4f69a3"
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.WriteHeader(http.StatusProxyAuthRequired)
		_, _ = io.WriteString(response, canary)
	}))
	defer server.Close()

	upstream, err := NewUpstreamDialer(server.URL, time.Second)
	if err != nil {
		t.Fatalf("NewUpstreamDialer: %v", err)
	}
	_, err = upstream.Dial("tcp", "example.com:443")
	if err == nil {
		t.Fatal("Dial error = nil")
	}
	if strings.Contains(err.Error(), canary) {
		t.Fatalf("upstream response body leaked through error: %q", err)
	}
}

func TestHTTPUpstreamForwardsPlainHTTPRequest(t *testing.T) {
	requests := make(chan *http.Request, 1)
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		requests <- request.Clone(request.Context())
		response.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	proxyURL := "http://user:pass@" + server.Listener.Addr().String()
	upstream, err := NewUpstreamDialer(proxyURL, time.Second)
	if err != nil {
		t.Fatalf("NewUpstreamDialer() error = %v", err)
	}
	request, err := http.NewRequest(http.MethodGet, "http://example.com/resource", nil)
	if err != nil {
		t.Fatalf("NewRequest() error = %v", err)
	}
	response, err := upstream.Transport.RoundTrip(request)
	if err != nil {
		t.Fatalf("RoundTrip() error = %v", err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", response.StatusCode, http.StatusNoContent)
	}

	forwarded := <-requests
	if forwarded.URL.String() != "http://example.com/resource" {
		t.Fatalf("forwarded URL = %q", forwarded.URL.String())
	}
	wantAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte("user:pass"))
	if got := forwarded.Header.Get("Proxy-Authorization"); got != wantAuth {
		t.Fatalf("Proxy-Authorization = %q, want %q", got, wantAuth)
	}
}

func TestNewUpstreamDialerReadmeSocksAddressSetsTransportProxy(t *testing.T) {
	oldDefaultTransport := http.DefaultTransport

	upstream, err := NewUpstreamDialer("127.0.0.1:1080", time.Second)
	if err != nil {
		t.Fatalf("NewUpstreamDialer() error = %v", err)
	}

	if http.DefaultTransport != oldDefaultTransport {
		t.Fatal("http.DefaultTransport was modified")
	}

	transport, ok := upstream.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("upstream.Transport = %T, want *http.Transport", upstream.Transport)
	}
	proxyURL, err := transport.Proxy(&http.Request{})
	if err != nil {
		t.Fatalf("transport.Proxy() error = %v", err)
	}
	if proxyURL == nil {
		t.Fatal("expected proxy URL")
	}
	if proxyURL.Scheme != "socks5" {
		t.Fatalf("proxy URL scheme = %q, want socks5", proxyURL.Scheme)
	}
	if proxyURL.Host != "127.0.0.1:1080" {
		t.Fatalf("proxy URL host = %q, want 127.0.0.1:1080", proxyURL.Host)
	}
}

func TestParseSocksURLPreservesAuthAndDefaultsScheme(t *testing.T) {
	parsedURL, err := parseSocksURL("user:pass@127.0.0.1:1080")
	if err != nil {
		t.Fatalf("parseSocksURL() error = %v", err)
	}
	if parsedURL.Scheme != "socks5" {
		t.Fatalf("scheme = %q, want socks5", parsedURL.Scheme)
	}
	if parsedURL.Host != "127.0.0.1:1080" {
		t.Fatalf("host = %q, want 127.0.0.1:1080", parsedURL.Host)
	}
	if got := parsedURL.User.Username(); got != "user" {
		t.Fatalf("username = %q, want user", got)
	}
	password, ok := parsedURL.User.Password()
	if !ok {
		t.Fatal("password missing")
	}
	if password != "pass" {
		t.Fatalf("password = %q, want pass", password)
	}
}

func TestDynamicUpstreamDialerReconfiguresNewRequests(t *testing.T) {
	dynamic, err := NewDynamicUpstreamDialer("", time.Second)
	if err != nil {
		t.Fatalf("NewDynamicUpstreamDialer() error = %v", err)
	}
	if err := dynamic.Configure("socks5://127.0.0.1:1080"); err != nil {
		t.Fatalf("Configure() error = %v", err)
	}
	if got := dynamic.Upstream(); got != "socks5://127.0.0.1:1080" {
		t.Fatalf("Upstream() = %q", got)
	}
	if err := dynamic.Configure(""); err != nil {
		t.Fatalf("Configure(direct) error = %v", err)
	}
	if got := dynamic.Upstream(); got != "" {
		t.Fatalf("Upstream() = %q, want direct", got)
	}
}

func TestNewDynamicUpstreamDialerNormalizesInitialUpstream(t *testing.T) {
	dynamic, err := NewDynamicUpstreamDialer("  socks5://127.0.0.1:1080  ", time.Second)
	if err != nil {
		t.Fatalf("NewDynamicUpstreamDialer() error = %v", err)
	}
	if got := dynamic.Upstream(); got != "socks5://127.0.0.1:1080" {
		t.Fatalf("Upstream() = %q, want normalized address", got)
	}
}

func TestDynamicUpstreamDialerKeepsConfigurationAfterInvalidUpdate(t *testing.T) {
	dynamic, err := NewDynamicUpstreamDialer("socks5://127.0.0.1:1080", time.Second)
	if err != nil {
		t.Fatalf("NewDynamicUpstreamDialer() error = %v", err)
	}
	if err := dynamic.Configure("https://127.0.0.1:3128"); err == nil {
		t.Fatal("Configure() error = nil, want unsupported scheme")
	}
	if got := dynamic.Upstream(); got != "socks5://127.0.0.1:1080" {
		t.Fatalf("Upstream() = %q, previous configuration was lost", got)
	}
}
