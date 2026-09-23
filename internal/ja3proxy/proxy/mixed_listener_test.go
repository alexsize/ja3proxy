package proxy

import (
	"bufio"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/lylemi/ja3proxy/internal/ja3proxy/flowid"
)

func TestMixedProxyListenerRoutesHTTPToServer(t *testing.T) {
	baseListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	proxy := NewProxy(nil, nil, roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.String() != "http://example.com/resource" {
			t.Fatalf("upstream URL = %q, want http://example.com/resource", req.URL.String())
		}
		return &http.Response{
			StatusCode: http.StatusAccepted,
			Header:     http.Header{"X-Test": {"ok"}},
			Body:       io.NopCloser(strings.NewReader("mixed http")),
		}, nil
	}))
	server := &http.Server{
		Handler: proxy,
	}
	go func() {
		_ = server.Serve(newMixedProxyListener(baseListener, proxy))
	}()
	t.Cleanup(func() {
		_ = server.Close()
	})

	conn, err := net.DialTimeout("tcp", baseListener.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatalf("dial mixed listener: %v", err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}

	_, err = io.WriteString(conn, "GET http://example.com/resource HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")
	if err != nil {
		t.Fatalf("write HTTP proxy request: %v", err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("read HTTP response: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("status code = %d, want %d", resp.StatusCode, http.StatusAccepted)
	}
	if got := resp.Header.Get("X-Test"); got != "ok" {
		t.Fatalf("X-Test = %q, want ok", got)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if string(body) != "mixed http" {
		t.Fatalf("body = %q, want mixed http", string(body))
	}
}

func TestMixedProxyListenerAssignsConnectionIDBeforeProtocolDetection(t *testing.T) {
	baseListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	listener := newMixedProxyListener(baseListener, NewProxy(nil, nil, nil))
	defer listener.Close()

	client, err := net.DialTimeout("tcp", baseListener.Addr().String(), time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()
	if _, err := client.Write([]byte("G")); err != nil {
		t.Fatalf("write protocol byte: %v", err)
	}
	accepted, err := listener.Accept()
	if err != nil {
		t.Fatalf("Accept: %v", err)
	}
	defer accepted.Close()
	if id := flowid.From(accepted); len(id) != 26 {
		t.Fatalf("accepted connection ID = %q, want ULID before HTTP parsing", id)
	}
}

func TestMixedProxyListenerAddrAndClose(t *testing.T) {
	baseListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	listener := newMixedProxyListener(baseListener, NewProxy(nil, nil, nil))
	if listener.Addr().String() != baseListener.Addr().String() {
		t.Fatalf("Addr() = %q, want %q", listener.Addr().String(), baseListener.Addr().String())
	}
	if err := listener.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if err := listener.Close(); err != nil {
		t.Fatalf("second Close() error = %v", err)
	}
	if _, err := listener.Accept(); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Accept() error = %v, want %v", err, net.ErrClosed)
	}
}

func TestMixedProxyListenerProtocolModesRejectOtherHandshake(t *testing.T) {
	tests := []struct {
		name     string
		protocol string
		first    byte
	}{
		{name: "HTTP rejects SOCKS5", protocol: ProtocolHTTP, first: socks5Version},
		{name: "SOCKS5 rejects HTTP", protocol: ProtocolSOCKS5, first: 'G'},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			listener := &MixedProxyListener{
				proxy:     NewProxy(nil, nil, nil),
				httpConns: make(chan net.Conn, 1),
				done:      make(chan struct{}),
			}
			if err := listener.SetProtocol(tt.protocol); err != nil {
				t.Fatalf("SetProtocol() error = %v", err)
			}
			serverConn, clientConn := net.Pipe()
			defer clientConn.Close()
			go listener.route(serverConn)
			if _, err := clientConn.Write([]byte{tt.first}); err != nil {
				t.Fatalf("write handshake: %v", err)
			}
			if err := clientConn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
				if errors.Is(err, io.ErrClosedPipe) {
					return
				}
				t.Fatalf("set read deadline: %v", err)
			}
			if _, err := clientConn.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
				t.Fatalf("rejected handshake read error = %v, want EOF", err)
			}
		})
	}
}

func TestMixedProxyListenerRejectsUnknownProtocol(t *testing.T) {
	listener := &MixedProxyListener{}
	if err := listener.SetProtocol("ftp"); err == nil {
		t.Fatal("SetProtocol() error = nil, want unsupported protocol error")
	}
}
