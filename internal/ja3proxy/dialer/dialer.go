package dialer

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/lylemi/ja3proxy/internal/ja3proxy/secrets"
	"golang.org/x/net/proxy"
)

type UpstreamDialer struct {
	dialer    proxy.Dialer
	Transport http.RoundTripper
}

// DynamicUpstreamDialer lets new connections pick up an upstream proxy change
// without interrupting connections that are already in flight.
type DynamicUpstreamDialer struct {
	mu       sync.RWMutex
	current  *UpstreamDialer
	upstream string
	timeout  time.Duration
	provider secrets.Provider
}

func NewDynamicUpstreamDialer(upstream string, timeout time.Duration) (*DynamicUpstreamDialer, error) {
	return NewDynamicUpstreamDialerWithProvider(upstream, timeout, nil)
}

func NewDynamicUpstreamDialerWithProvider(upstream string, timeout time.Duration, provider secrets.Provider) (*DynamicUpstreamDialer, error) {
	upstream = strings.TrimSpace(upstream)
	current, err := NewUpstreamDialerWithProvider(upstream, timeout, provider)
	if err != nil {
		return nil, err
	}
	return &DynamicUpstreamDialer{current: current, upstream: upstream, timeout: timeout, provider: provider}, nil
}

func (u *DynamicUpstreamDialer) Configure(upstream string) error {
	upstream = strings.TrimSpace(upstream)
	next, err := NewUpstreamDialerWithProvider(upstream, u.timeout, u.provider)
	if err != nil {
		return err
	}

	u.mu.Lock()
	previous := u.current
	u.current = next
	u.upstream = upstream
	u.mu.Unlock()

	if previous != nil {
		if transport, ok := previous.Transport.(*http.Transport); ok {
			transport.CloseIdleConnections()
		}
	}
	return nil
}

func (u *DynamicUpstreamDialer) Upstream() string {
	if u == nil {
		return ""
	}
	u.mu.RLock()
	defer u.mu.RUnlock()
	return u.upstream
}

func (u *DynamicUpstreamDialer) Dial(network, addr string) (net.Conn, error) {
	u.mu.RLock()
	current := u.current
	u.mu.RUnlock()
	return current.Dial(network, addr)
}

func (u *DynamicUpstreamDialer) RoundTrip(request *http.Request) (*http.Response, error) {
	u.mu.RLock()
	current := u.current
	u.mu.RUnlock()
	return current.Transport.RoundTrip(request)
}

func NewUpstreamDialer(upstream string, timeout time.Duration) (*UpstreamDialer, error) {
	return NewUpstreamDialerWithProvider(upstream, timeout, nil)
}

// NewUpstreamDialerWithProvider resolves credentials written as file:<path>
// in URL userinfo. Literal URL credentials remain supported.
func NewUpstreamDialerWithProvider(upstream string, timeout time.Duration, provider secrets.Provider) (*UpstreamDialer, error) {
	var dialer proxy.Dialer
	var transport http.RoundTripper

	if upstream != "" {
		parsedURL, err := parseProxyURL(upstream)
		if err != nil {
			return nil, err
		}
		if err := resolveProxyCredentials(parsedURL, provider); err != nil {
			return nil, err
		}

		switch parsedURL.Scheme {
		case "socks5":
			user := parsedURL.User.Username()
			password, _ := parsedURL.User.Password()
			socksDialer, err := proxy.SOCKS5(
				"tcp", parsedURL.Host,
				&proxy.Auth{User: user, Password: password},
				&net.Dialer{Timeout: timeout},
			)
			if err != nil {
				return nil, err
			}
			dialer = socksDialer
		case "http":
			dialer = &httpConnectDialer{proxyURL: parsedURL, timeout: timeout}
		}

		defaultTransport := http.DefaultTransport.(*http.Transport).Clone()
		defaultTransport.Proxy = http.ProxyURL(parsedURL)
		transport = defaultTransport
	} else {
		directDialer := &net.Dialer{Timeout: timeout}
		dialer = directDialer
		directTransport := http.DefaultTransport.(*http.Transport).Clone()
		directTransport.Proxy = nil
		directTransport.DialContext = directDialer.DialContext
		transport = directTransport
	}

	return &UpstreamDialer{
		dialer:    dialer,
		Transport: transport,
	}, nil
}

func resolveProxyCredentials(parsedURL *url.URL, provider secrets.Provider) error {
	if parsedURL == nil || parsedURL.User == nil {
		return nil
	}
	username := parsedURL.User.Username()
	password, hasPassword := parsedURL.User.Password()
	if strings.HasPrefix(username, "file:") {
		value, err := secrets.Read(provider, strings.TrimPrefix(username, "file:"))
		if err != nil {
			return fmt.Errorf("load upstream proxy username reference: %w", err)
		}
		username = string(value)
		clear(value)
	}
	if hasPassword && strings.HasPrefix(password, "file:") {
		value, err := secrets.Read(provider, strings.TrimPrefix(password, "file:"))
		if err != nil {
			return fmt.Errorf("load upstream proxy password reference: %w", err)
		}
		password = string(value)
		clear(value)
	}
	if hasPassword {
		parsedURL.User = url.UserPassword(username, password)
	} else {
		parsedURL.User = url.User(username)
	}
	return nil
}

func parseProxyURL(upstream string) (*url.URL, error) {
	parsedURL, err := url.Parse(upstream)
	if err != nil || !strings.Contains(upstream, "://") {
		parsedURL, err = url.Parse("socks5://" + upstream)
		if err != nil {
			return nil, err
		}
	}
	if parsedURL.Scheme == "" {
		parsedURL.Scheme = "socks5"
	}
	parsedURL.Scheme = strings.ToLower(parsedURL.Scheme)
	if parsedURL.Scheme != "socks5" && parsedURL.Scheme != "http" {
		return nil, fmt.Errorf("unsupported upstream proxy scheme %q", parsedURL.Scheme)
	}
	if parsedURL.Host == "" {
		return nil, fmt.Errorf("missing upstream proxy host")
	}
	return parsedURL, nil
}

// parseSocksURL is kept for callers that rely on host:port defaulting to SOCKS5.
func parseSocksURL(socksAddr string) (*url.URL, error) {
	return parseProxyURL(socksAddr)
}

type httpConnectDialer struct {
	proxyURL *url.URL
	timeout  time.Duration
}

func (dialer *httpConnectDialer) Dial(network, addr string) (net.Conn, error) {
	if network != "tcp" && network != "tcp4" && network != "tcp6" {
		return nil, fmt.Errorf("HTTP proxy CONNECT does not support network %q", network)
	}

	conn, err := (&net.Dialer{Timeout: dialer.timeout}).Dial("tcp", dialer.proxyURL.Host)
	if err != nil {
		return nil, fmt.Errorf("dial HTTP proxy %s: %w", dialer.proxyURL.Host, err)
	}
	succeeded := false
	defer func() {
		if !succeeded {
			_ = conn.Close()
		}
	}()

	if dialer.timeout > 0 {
		if err := conn.SetDeadline(time.Now().Add(dialer.timeout)); err != nil {
			return nil, err
		}
	}
	request := &http.Request{
		Method: http.MethodConnect,
		URL:    &url.URL{Opaque: addr},
		Host:   addr,
		Header: make(http.Header),
	}
	if dialer.proxyURL.User != nil {
		password, _ := dialer.proxyURL.User.Password()
		token := base64.StdEncoding.EncodeToString([]byte(dialer.proxyURL.User.Username() + ":" + password))
		request.Header.Set("Proxy-Authorization", "Basic "+token)
	}
	if err := request.Write(conn); err != nil {
		return nil, fmt.Errorf("write HTTP proxy CONNECT request: %w", err)
	}

	reader := bufio.NewReader(conn)
	response, err := http.ReadResponse(reader, request)
	if err != nil {
		return nil, fmt.Errorf("read HTTP proxy CONNECT response: %w", err)
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4<<10))
		_ = response.Body.Close()
		return nil, fmt.Errorf("HTTP proxy CONNECT failed: %s", response.Status)
	}
	if err := conn.SetDeadline(time.Time{}); err != nil {
		return nil, err
	}

	succeeded = true
	if reader.Buffered() > 0 {
		return &bufferedConn{Conn: conn, reader: reader}, nil
	}
	return conn, nil
}

type bufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

func (conn *bufferedConn) Read(p []byte) (int, error) {
	if conn.reader.Buffered() > 0 {
		return conn.reader.Read(p)
	}
	return conn.Conn.Read(p)
}

func (u *UpstreamDialer) Dial(network, addr string) (net.Conn, error) {
	return u.dialer.Dial(network, addr)
}
