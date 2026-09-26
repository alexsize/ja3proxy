package proxy

import (
	"bufio"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/lylemi/ja3proxy/internal/ja3proxy/traffic"
)

func TestHandleTunnelingDialErrorReturnsServiceUnavailable(t *testing.T) {
	proxy := NewProxy(func(network, addr string) (net.Conn, error) {
		if network != "tcp" {
			t.Fatalf("network = %q, want tcp", network)
		}
		if addr != "example.com:443" {
			t.Fatalf("addr = %q, want example.com:443", addr)
		}
		return nil, errors.New("dial failed")
	}, nil, nil)

	clientConn, clientPeer := net.Pipe()
	defer clientConn.Close()
	defer clientPeer.Close()

	rec := &hijackResponseRecorder{
		ResponseRecorder: httptest.NewRecorder(),
		conn:             clientConn,
	}
	req := httptest.NewRequest(http.MethodConnect, "http://example.com:443", nil)
	req.Host = "example.com:443"

	proxy.ServeHTTP(rec, req)

	resp := rec.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status code = %d, want %d", resp.StatusCode, http.StatusServiceUnavailable)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read response body: %v", err)
	}
	if !strings.Contains(string(body), "dial failed") {
		t.Fatalf("body = %q, want dial error", string(body))
	}
	if rec.hijacked {
		t.Fatal("Hijack was called after dial failure")
	}
}

func TestHandleTunnelingWithoutHijackerReturnsInternalServerError(t *testing.T) {
	proxy := NewProxy(func(network, addr string) (net.Conn, error) {
		t.Fatal("dial should not be called without Hijacker support")
		return nil, nil
	}, nil, nil)

	req := httptest.NewRequest(http.MethodConnect, "http://example.com:443", nil)
	req.Host = "example.com:443"
	rec := httptest.NewRecorder()

	proxy.ServeHTTP(rec, req)

	resp := rec.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("status code = %d, want %d", resp.StatusCode, http.StatusInternalServerError)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read response body: %v", err)
	}
	if !strings.Contains(string(body), "Hijacking not supported") {
		t.Fatalf("body = %q, want hijacking error", string(body))
	}
}

func TestHandleTunnelingSuccessDialsHijacksAndConnects(t *testing.T) {
	destConn, destPeer := net.Pipe()
	clientConn, clientPeer := net.Pipe()
	defer destConn.Close()
	defer destPeer.Close()
	defer clientConn.Close()
	defer clientPeer.Close()

	var dialNetwork, dialAddr string
	dial := func(network, addr string) (net.Conn, error) {
		dialNetwork = network
		dialAddr = addr
		return destConn, nil
	}

	connectCalls := make(chan connectInvocation, 1)
	connect := func(sni string, destConn net.Conn, clientConn net.Conn) {
		connectCalls <- connectInvocation{
			sni:        sni,
			destConn:   destConn,
			clientConn: clientConn,
		}
	}
	proxy := NewProxy(dial, connect, nil)

	rec := &hijackResponseRecorder{
		ResponseRecorder: httptest.NewRecorder(),
		conn:             clientConn,
	}
	req := httptest.NewRequest(http.MethodConnect, "http://example.com:443", nil)
	req.Host = "example.com:443"

	serveDone := make(chan struct{})
	go func() {
		proxy.ServeHTTP(rec, req)
		close(serveDone)
	}()

	response := make([]byte, len(connectEstablishedResponse))
	if _, err := io.ReadFull(clientPeer, response); err != nil {
		t.Fatalf("read CONNECT response: %v", err)
	}
	if string(response) != connectEstablishedResponse {
		t.Fatalf("CONNECT response = %q, want %q", response, connectEstablishedResponse)
	}

	select {
	case <-serveDone:
	case <-time.After(2 * time.Second):
		t.Fatal("ServeHTTP did not return after CONNECT response was read")
	}

	if dialNetwork != "tcp" {
		t.Fatalf("dial network = %q, want tcp", dialNetwork)
	}
	if dialAddr != "example.com:443" {
		t.Fatalf("dial addr = %q, want example.com:443", dialAddr)
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("status code = %d, want %d", rec.Code, http.StatusOK)
	}
	if !reflect.DeepEqual(rec.events, []string{"hijack"}) {
		t.Fatalf("events = %v, want [hijack]", rec.events)
	}

	var call connectInvocation
	select {
	case call = <-connectCalls:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for connect")
	}

	if call.sni != "example.com" {
		t.Fatalf("connect sni = %q, want example.com", call.sni)
	}
	if call.destConn != destConn {
		t.Fatalf("connect destConn = %p, want %p", call.destConn, destConn)
	}
	if call.clientConn != clientConn {
		t.Fatalf("connect clientConn = %p, want %p", call.clientConn, clientConn)
	}
}

func TestHandleTunnelingSessionHandlerDefersDial(t *testing.T) {
	clientConn, clientPeer := net.Pipe()
	defer clientConn.Close()
	defer clientPeer.Close()

	dialCalled := make(chan struct{}, 1)
	connectCalled := make(chan net.Conn, 1)
	proxy := NewProxy(func(network, addr string) (net.Conn, error) {
		dialCalled <- struct{}{}
		return nil, errors.New("dial must be deferred")
	}, nil, nil).WithTunnelConnectRequestAndSession(func(_ TunnelRequest, destConn net.Conn, clientConn net.Conn, _ *traffic.TrafficSessionHandle) {
		connectCalled <- destConn
		_ = clientConn.Close()
	})

	rec := &hijackResponseRecorder{ResponseRecorder: httptest.NewRecorder(), conn: clientConn}
	req := httptest.NewRequest(http.MethodConnect, "http://example.com:443", nil)
	req.Host = "example.com:443"
	go proxy.ServeHTTP(rec, req)

	response := make([]byte, len(connectEstablishedResponse))
	if _, err := io.ReadFull(clientPeer, response); err != nil {
		t.Fatalf("read CONNECT response: %v", err)
	}
	select {
	case destConn := <-connectCalled:
		if destConn != nil {
			t.Fatal("session handler received a pre-opened destination")
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for deferred connect handler")
	}
	select {
	case <-dialCalled:
		t.Fatal("destination was dialed before session handler")
	default:
	}
}

func TestHandleTunnelingRouteBlockRejectsBeforeDial(t *testing.T) {
	dialCalled := false
	proxy := NewProxy(func(network, addr string) (net.Conn, error) {
		dialCalled = true
		return nil, errors.New("dial must not run")
	}, nil, nil).WithTunnelBlockRequest(func(TunnelRequest) bool { return true })
	req := httptest.NewRequest(http.MethodConnect, "http://blocked.example.com:443", nil)
	req.Host = "blocked.example.com:443"
	rec := httptest.NewRecorder()

	proxy.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("route block status = %d, want %d", rec.Code, http.StatusForbidden)
	}
	if dialCalled {
		t.Fatal("route block dialed destination")
	}
}

func TestHandleTunnelingWritesPlainConnectResponse(t *testing.T) {
	destConn, destPeer := net.Pipe()
	defer destConn.Close()
	defer destPeer.Close()

	connectStarted := make(chan struct{})
	releaseConnect := make(chan struct{})
	proxy := NewProxy(func(network, addr string) (net.Conn, error) {
		if network != "tcp" {
			t.Fatalf("network = %q, want tcp", network)
		}
		if addr != "example.com:443" {
			t.Fatalf("addr = %q, want example.com:443", addr)
		}
		return destConn, nil
	}, func(sni string, destConn net.Conn, clientConn net.Conn) {
		close(connectStarted)
		<-releaseConnect
		destConn.Close()
		clientConn.Close()
	}, nil)

	server := httptest.NewServer(proxy)
	defer server.Close()

	serverURL := strings.TrimPrefix(server.URL, "http://")
	conn, err := net.DialTimeout("tcp", serverURL, 2*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("set proxy connection deadline: %v", err)
	}

	if _, err := io.WriteString(conn, "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n"); err != nil {
		t.Fatalf("write CONNECT request: %v", err)
	}

	reader := bufio.NewReader(conn)
	statusLine, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("read CONNECT status line: %v", err)
	}
	if statusLine != "HTTP/1.1 200 Connection Established\r\n" {
		t.Fatalf("CONNECT status line = %q, want Connection Established", statusLine)
	}

	headers := http.Header{}
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("read CONNECT header: %v", err)
		}
		if line == "\r\n" {
			break
		}
		parts := strings.SplitN(strings.TrimRight(line, "\r\n"), ":", 2)
		if len(parts) != 2 {
			t.Fatalf("malformed CONNECT header line %q", line)
		}
		headers.Add(parts[0], strings.TrimSpace(parts[1]))
	}

	if got := headers.Get("Transfer-Encoding"); got != "" {
		t.Fatalf("Transfer-Encoding = %q, want empty", got)
	}
	if got := headers.Get("Content-Length"); got != "" {
		t.Fatalf("Content-Length = %q, want empty", got)
	}

	select {
	case <-connectStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("CONNECT handler did not start tunnel")
	}
	close(releaseConnect)
}

func TestHandleTunnelingConnectResponseWriteErrorClosesConnections(t *testing.T) {
	destConn := &closeTrackingConn{}
	clientConn := &writeErrorConn{err: errors.New("write failed")}
	proxy := NewProxy(func(network, addr string) (net.Conn, error) {
		return destConn, nil
	}, func(sni string, destConn net.Conn, clientConn net.Conn) {
		t.Fatal("connect should not be called after CONNECT response write failure")
	}, nil)

	rec := &connectResponseErrorRecorder{
		ResponseRecorder: httptest.NewRecorder(),
		conn:             clientConn,
		writerSize:       1,
	}
	req := httptest.NewRequest(http.MethodConnect, "http://example.com:443", nil)
	req.Host = "example.com:443"

	proxy.ServeHTTP(rec, req)

	if !destConn.closed {
		t.Fatal("destination connection was not closed after CONNECT response write failure")
	}
	if !clientConn.closed {
		t.Fatal("client connection was not closed after CONNECT response write failure")
	}
}

func TestHandleTunnelingConnectResponseFlushErrorClosesConnections(t *testing.T) {
	destConn := &closeTrackingConn{}
	clientConn := &writeErrorConn{err: errors.New("flush failed")}
	proxy := NewProxy(func(network, addr string) (net.Conn, error) {
		return destConn, nil
	}, func(sni string, destConn net.Conn, clientConn net.Conn) {
		t.Fatal("connect should not be called after CONNECT response flush failure")
	}, nil)

	rec := &connectResponseErrorRecorder{
		ResponseRecorder: httptest.NewRecorder(),
		conn:             clientConn,
		writerSize:       len(connectEstablishedResponse) + 1,
	}
	req := httptest.NewRequest(http.MethodConnect, "http://example.com:443", nil)
	req.Host = "example.com:443"

	proxy.ServeHTTP(rec, req)

	if !destConn.closed {
		t.Fatal("destination connection was not closed after CONNECT response flush failure")
	}
	if !clientConn.closed {
		t.Fatal("client connection was not closed after CONNECT response flush failure")
	}
}

func TestHandleTunnelingHijackErrorClosesDestination(t *testing.T) {
	destConn := &closeTrackingConn{}
	proxy := NewProxy(func(network, addr string) (net.Conn, error) {
		return destConn, nil
	}, func(sni string, destConn net.Conn, clientConn net.Conn) {
		t.Fatal("connect should not be called after hijack failure")
	}, nil)

	rec := &failingHijackResponseRecorder{ResponseRecorder: httptest.NewRecorder()}
	req := httptest.NewRequest(http.MethodConnect, "http://example.com:443", nil)
	req.Host = "example.com:443"

	proxy.ServeHTTP(rec, req)

	if !destConn.closed {
		t.Fatal("destination connection was not closed after hijack failure")
	}
}

type connectInvocation struct {
	sni        string
	destConn   net.Conn
	clientConn net.Conn
}

type hijackResponseRecorder struct {
	*httptest.ResponseRecorder
	conn     net.Conn
	hijacked bool
	events   []string
}

func (r *hijackResponseRecorder) WriteHeader(code int) {
	r.events = append(r.events, "writeHeader")
	r.ResponseRecorder.WriteHeader(code)
}

func (r *hijackResponseRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	r.hijacked = true
	r.events = append(r.events, "hijack")
	rw := bufio.NewReadWriter(bufio.NewReader(r.conn), bufio.NewWriter(r.conn))
	return r.conn, rw, nil
}

type failingHijackResponseRecorder struct {
	*httptest.ResponseRecorder
}

func (r *failingHijackResponseRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return nil, nil, errors.New("hijack failed")
}

type connectResponseErrorRecorder struct {
	*httptest.ResponseRecorder
	conn       *writeErrorConn
	writerSize int
}

func (r *connectResponseErrorRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	rw := bufio.NewReadWriter(
		bufio.NewReader(r.conn),
		bufio.NewWriterSize(r.conn, r.writerSize),
	)
	return r.conn, rw, nil
}

type closeTrackingConn struct {
	net.Conn
	closed bool
}

func (conn *closeTrackingConn) Close() error {
	conn.closed = true
	return nil
}

type writeErrorConn struct {
	net.Conn
	closed bool
	err    error
}

func (conn *writeErrorConn) Write(_ []byte) (int, error) {
	return 0, conn.err
}

func (conn *writeErrorConn) Close() error {
	conn.closed = true
	return nil
}
