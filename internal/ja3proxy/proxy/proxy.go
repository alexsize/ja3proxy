package proxy

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/lylemi/ja3proxy/internal/ja3proxy/flowid"
	"github.com/lylemi/ja3proxy/internal/ja3proxy/logutil"
	"github.com/lylemi/ja3proxy/internal/ja3proxy/netutil"
	"github.com/lylemi/ja3proxy/internal/ja3proxy/pipe"
	"github.com/lylemi/ja3proxy/internal/ja3proxy/traffic"
)

const connectEstablishedResponse = "HTTP/1.1 200 Connection Established\r\n\r\n"

type bufferedReadConn struct {
	net.Conn
	reader *bufio.Reader
}

func (conn *bufferedReadConn) UnwrapConn() net.Conn { return conn.Conn }

func (conn *bufferedReadConn) Read(p []byte) (int, error) {
	if conn.reader.Buffered() > 0 {
		return conn.reader.Read(p)
	}
	return conn.Conn.Read(p)
}

type Proxy struct {
	inspectTLS           bool
	blockTunnels         bool
	tunnelDial           func(network, addr string) (net.Conn, error)
	tunnelConnect        func(sni string, destConn net.Conn, clientConn net.Conn)
	tunnelConnectRequest func(TunnelRequest, net.Conn, net.Conn)
	httpTransport        http.RoundTripper
	traffic              *traffic.TrafficMonitor
	credentialsMu        sync.RWMutex
	credentials          proxyCredentials
}

type TunnelRequest struct {
	Host     string
	Port     int
	Username string
}

// WithTLSInspection delegates protocol detection to the bounded tunnel recorder.
// It is opt-in to preserve the legacy proxy behavior when recording is disabled.
func (p *Proxy) WithTLSInspection(enabled bool) *Proxy { p.inspectTLS = enabled; return p }

func (p *Proxy) WithBlockedTunnels(block bool) *Proxy { p.blockTunnels = block; return p }

func NewProxy(
	dial func(network, addr string) (net.Conn, error),
	connect func(sni string, destConn net.Conn, clientConn net.Conn),
	transport http.RoundTripper,
) *Proxy {
	if dial == nil {
		dial = defaultTunnelDial
	}
	if connect == nil {
		connect = defaultTunnelConnect
	}
	if transport == nil {
		transport = http.DefaultTransport
	}
	return &Proxy{
		tunnelDial:    dial,
		tunnelConnect: connect,
		httpTransport: transport,
	}
}

// WithTunnelConnectRequest adds destination context without breaking the
// legacy tunnel callback API.
func (p *Proxy) WithTunnelConnectRequest(connect func(TunnelRequest, net.Conn, net.Conn)) *Proxy {
	if p != nil {
		p.tunnelConnectRequest = connect
	}
	return p
}

func (p *Proxy) WithTrafficMonitor(monitor *traffic.TrafficMonitor) *Proxy {
	if p != nil {
		p.traffic = monitor
	}
	return p
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	proxyUsername, ok := p.authenticateHTTPIdentity(w, r)
	if !ok {
		return
	}
	if r.Method == http.MethodConnect {
		p.handleTunneling(w, r, proxyUsername)
		return
	}
	p.handleHTTP(w, r)
}

func (p *Proxy) dial(network, addr string) (net.Conn, error) {
	if p != nil && p.tunnelDial != nil {
		return p.tunnelDial(network, addr)
	}
	return defaultTunnelDial(network, addr)
}

func (p *Proxy) connect(sni string, destConn net.Conn, clientConn net.Conn) {
	if p != nil && p.tunnelConnect != nil {
		p.tunnelConnect(sni, destConn, clientConn)
		return
	}
	defaultTunnelConnect(sni, destConn, clientConn)
}

func (p *Proxy) connectRequest(request TunnelRequest, destConn net.Conn, clientConn net.Conn) {
	if p != nil && p.tunnelConnectRequest != nil {
		p.tunnelConnectRequest(request, destConn, clientConn)
		return
	}
	p.connect(request.Host, destConn, clientConn)
}

func (p *Proxy) transport() http.RoundTripper {
	if p != nil && p.httpTransport != nil {
		return p.httpTransport
	}
	return http.DefaultTransport
}

func (p *Proxy) monitor() *traffic.TrafficMonitor {
	if p == nil {
		return nil
	}
	return p.traffic
}

func (p *Proxy) TrafficMonitor() *traffic.TrafficMonitor {
	return p.monitor()
}

func (p *Proxy) handleTunneling(w http.ResponseWriter, r *http.Request, proxyUsername string) {
	if p.blockTunnels {
		http.Error(w, "tunnel blocked by policy", http.StatusForbidden)
		return
	}
	logger := logutil.WithComponent("http_connect", "target", r.Host)
	logger.Info("opening tunnel")
	info := traffic.TrafficSessionInfo{
		Protocol:   "HTTP CONNECT",
		Target:     r.Host,
		ClientAddr: r.RemoteAddr,
		SNI:        netutil.StripPort(r.Host),
	}

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		logger.Error("hijacking not supported")
		p.monitor().RecordEvent("error", "hijacking not supported", info, nil)
		return
	}

	destConn, err := p.dial("tcp", r.Host)

	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		logger.Warn("dial target failed", "err", err)
		p.monitor().RecordEvent("warn", "dial target failed", info, err)
		return
	}

	clientConn, clientRW, err := hijacker.Hijack()
	if err != nil {
		destConn.Close()
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		logger.Error("hijack failed", "err", err)
		p.monitor().RecordEvent("error", "hijack failed", info, err)
		return
	}
	if info.ClientAddr == "" {
		info.ClientAddr = netutil.RemoteAddr(clientConn)
	}

	tunnelClientConn := clientConn
	if clientRW.Reader.Buffered() > 0 {
		tunnelClientConn = &bufferedReadConn{
			Conn:   clientConn,
			reader: clientRW.Reader,
		}
	}
	tunnelClientConn = flowid.WithProxyUsername(tunnelClientConn, proxyUsername)

	if _, err := io.WriteString(clientRW, connectEstablishedResponse); err != nil {
		destConn.Close()
		clientConn.Close()
		logger.Warn("write CONNECT response failed", "err", err)
		p.monitor().RecordEvent("warn", "write CONNECT response failed", info, err)
		return
	}
	if err := clientRW.Flush(); err != nil {
		destConn.Close()
		clientConn.Close()
		logger.Warn("flush CONNECT response failed", "err", err)
		p.monitor().RecordEvent("warn", "flush CONNECT response failed", info, err)
		return
	}

	session := p.monitor().StartSession(info)
	destConn, tunnelClientConn = traffic.WrapTunnel(session, destConn, tunnelClientConn)
	go func() {
		defer session.Finish()
		p.connectRequest(TunnelRequest{Host: netutil.StripPort(r.Host), Port: targetPort(r.Host), Username: proxyUsername}, destConn, tunnelClientConn)
	}()
}

func targetPort(address string) int {
	if _, port, err := net.SplitHostPort(address); err == nil {
		if value, err := strconv.Atoi(port); err == nil {
			return value
		}
	}
	return 443
}

func defaultTunnelDial(network, addr string) (net.Conn, error) {
	return net.DialTimeout(network, addr, 10*time.Second)
}

func defaultTunnelConnect(_ string, destConn net.Conn, clientConn net.Conn) {
	pipe.Junction(destConn, clientConn)
}

func (p *Proxy) handleHTTP(w http.ResponseWriter, req *http.Request) {
	info := traffic.TrafficSessionInfo{
		Protocol:   "HTTP",
		Target:     httpRequestTarget(req),
		ClientAddr: req.RemoteAddr,
	}
	session := p.monitor().StartSession(info)
	defer session.Finish()

	outReq := req.Clone(req.Context())
	outReq.RequestURI = ""
	if outReq.Body != nil {
		outReq.Body = traffic.WrapReadCloser(session, outReq.Body)
	}

	resp, err := p.transport().RoundTrip(outReq)
	if err != nil {
		session.Fail(err)
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		logutil.Warn(
			"http_proxy",
			"HTTP upstream request failed",
			"method", req.Method,
			"target", httpRequestTarget(req),
			"err", err,
		)
		return
	}
	defer resp.Body.Close()
	copyHeader(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	responseWriter := traffic.WrapResponseWriter(session, w)
	if _, err := io.Copy(responseWriter, resp.Body); err != nil {
		session.Fail(err)
		logutil.Warn(
			"http_proxy",
			"HTTP response copy failed",
			"method", req.Method,
			"target", httpRequestTarget(req),
			"err", err,
		)
	}
}

func httpRequestTarget(req *http.Request) string {
	if req.URL != nil && req.URL.Host != "" {
		return req.URL.Host
	}
	return req.Host
}

func copyHeader(dst, src http.Header) {
	for k, vv := range src {
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}
