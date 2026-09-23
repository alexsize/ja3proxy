package proxy

import (
	"bufio"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/lylemi/ja3proxy/internal/ja3proxy/flowid"
)

const defaultHTTPConnBack = 64

const (
	ProtocolMixed  = "mixed"
	ProtocolHTTP   = "http"
	ProtocolSOCKS5 = "socks5"
)

type MixedProxyListener struct {
	base      net.Listener
	proxy     *Proxy
	httpConns chan net.Conn
	done      chan struct{}
	closeOnce sync.Once
	protocol  atomic.Uint32
}

func newMixedProxyListener(base net.Listener, proxy *Proxy) *MixedProxyListener {
	listener := &MixedProxyListener{
		base:      base,
		proxy:     proxy,
		httpConns: make(chan net.Conn, defaultHTTPConnBack),
		done:      make(chan struct{}),
	}
	listener.protocol.Store(protocolCode(ProtocolMixed))
	go listener.acceptLoop()
	return listener
}

func NewMixedProxyListener(base net.Listener, proxy *Proxy) *MixedProxyListener {
	return newMixedProxyListener(base, proxy)
}

func (listener *MixedProxyListener) Accept() (net.Conn, error) {
	select {
	case conn := <-listener.httpConns:
		return conn, nil
	case <-listener.done:
		return nil, net.ErrClosed
	}
}

func (listener *MixedProxyListener) Close() error {
	var err error
	listener.closeOnce.Do(func() {
		close(listener.done)
		err = listener.base.Close()
	})
	return err
}

func (listener *MixedProxyListener) Addr() net.Addr {
	return listener.base.Addr()
}

func (listener *MixedProxyListener) SetProtocol(protocol string) error {
	normalized := strings.ToLower(strings.TrimSpace(protocol))
	code := protocolCode(normalized)
	if code == 0 {
		return fmt.Errorf("unsupported listen protocol %q", protocol)
	}
	listener.protocol.Store(code)
	return nil
}

func (listener *MixedProxyListener) Protocol() string {
	switch listener.protocol.Load() {
	case protocolCode(ProtocolHTTP):
		return ProtocolHTTP
	case protocolCode(ProtocolSOCKS5):
		return ProtocolSOCKS5
	default:
		return ProtocolMixed
	}
}

func protocolCode(protocol string) uint32 {
	switch protocol {
	case ProtocolMixed:
		return 1
	case ProtocolHTTP:
		return 2
	case ProtocolSOCKS5:
		return 3
	default:
		return 0
	}
}

func (listener *MixedProxyListener) acceptLoop() {
	for {
		conn, err := listener.base.Accept()
		if err != nil {
			_ = listener.Close()
			return
		}
		// The transport-flow ID exists before the first byte is inspected and is
		// preserved through HTTP, SOCKS5 and traffic-monitor wrappers.
		conn = flowid.Wrap(conn)
		go listener.route(conn)
	}
}

func (listener *MixedProxyListener) route(conn net.Conn) {
	reader := bufio.NewReader(conn)
	first, err := reader.Peek(1)
	if err != nil {
		conn.Close()
		return
	}

	bufferedConn := &bufferedReadConn{
		Conn:   conn,
		reader: reader,
	}
	isSOCKS5 := first[0] == socks5Version
	protocol := listener.Protocol()
	if isSOCKS5 && protocol != ProtocolHTTP {
		listener.proxy.handleSOCKS5(bufferedConn)
		return
	}
	if isSOCKS5 || protocol == ProtocolSOCKS5 {
		_ = conn.Close()
		return
	}

	select {
	case listener.httpConns <- bufferedConn:
	case <-listener.done:
		conn.Close()
	}
}
