package proxy

import (
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestBlockedHTTPTunnelRejectsBeforeDial(t *testing.T) {
	dialed := false
	proxy := NewProxy(func(network, addr string) (net.Conn, error) {
		dialed = true
		return nil, nil
	}, nil, nil).WithBlockedTunnels(true)

	request := httptest.NewRequest(http.MethodConnect, "http://example.com:443", nil)
	request.Host = "example.com:443"
	response := httptest.NewRecorder()
	proxy.ServeHTTP(response, request)

	if response.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusForbidden)
	}
	if dialed {
		t.Fatal("blocked CONNECT dialed the destination")
	}
}

func TestProxyDefaultDependencies(t *testing.T) {
	proxy := NewProxy(nil, nil, nil)

	if proxy.transport() != http.DefaultTransport {
		t.Fatalf("default transport = %T, want http.DefaultTransport", proxy.transport())
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen on local TCP address: %v", err)
	}
	defer listener.Close()

	accepted := make(chan net.Conn, 1)
	acceptErr := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			acceptErr <- err
			return
		}
		accepted <- conn
	}()

	conn, err := proxy.dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatalf("default tunnel dial error = %v", err)
	}
	defer conn.Close()

	select {
	case acceptedConn := <-accepted:
		acceptedConn.Close()
	case err := <-acceptErr:
		t.Fatalf("accept default tunnel dial: %v", err)
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for default tunnel dial")
	}

	destConn, upstreamPeer := net.Pipe()
	clientConn, clientPeer := net.Pipe()
	for _, conn := range []net.Conn{destConn, upstreamPeer, clientConn, clientPeer} {
		defer conn.Close()
		if err := conn.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
			t.Fatalf("set deadline: %v", err)
		}
	}

	connectDone := make(chan struct{})
	go func() {
		proxy.connect("", destConn, clientConn)
		close(connectDone)
	}()

	payload := []byte("default connect")
	writeErr := make(chan error, 1)
	go func() {
		_, err := clientPeer.Write(payload)
		writeErr <- err
	}()
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(upstreamPeer, got); err != nil {
		t.Fatalf("read through default tunnel connect: %v", err)
	}
	if string(got) != string(payload) {
		t.Fatalf("default tunnel connect payload = %q, want %q", got, payload)
	}
	select {
	case err := <-writeErr:
		if err != nil {
			t.Fatalf("write through default tunnel connect: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("write through default tunnel connect timed out")
	}

	clientPeer.Close()
	upstreamPeer.Close()
	select {
	case <-connectDone:
	case <-time.After(2 * time.Second):
		t.Fatal("default tunnel connect did not return after peers closed")
	}
}

func TestNilProxyUsesDefaultTransport(t *testing.T) {
	var proxy *Proxy
	if proxy.transport() != http.DefaultTransport {
		t.Fatalf("nil proxy transport = %T, want http.DefaultTransport", proxy.transport())
	}
}
