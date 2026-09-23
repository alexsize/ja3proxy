package proxy

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
	"time"

	"github.com/lylemi/ja3proxy/internal/ja3proxy/flowid"
	"github.com/lylemi/ja3proxy/internal/ja3proxy/logutil"
	"github.com/lylemi/ja3proxy/internal/ja3proxy/netutil"
	"github.com/lylemi/ja3proxy/internal/ja3proxy/pipe"
	"github.com/lylemi/ja3proxy/internal/ja3proxy/traffic"
)

const (
	socks5Version      = 0x05
	socks5NoAuth       = 0x00
	socks5UserPassAuth = 0x02
	socks5NoAcceptable = 0xff
	socks5AuthVersion  = 0x01
	socks5AuthSuccess  = 0x00
	socks5AuthFailure  = 0x01
	socks5Connect      = 0x01
	socks5Reserved     = 0x00
	socks5IPv4         = 0x01
	socks5Domain       = 0x03
	socks5IPv6         = 0x04
	socks5Succeeded    = 0x00
	socks5GeneralFail  = 0x01
	socks5CommandFail  = 0x07
	socks5AddressFail  = 0x08
	tlsHandshakeRecord = 0x16
	socks5TLSPeekTime  = 100 * time.Millisecond
)

type socks5Request struct {
	command byte
	host    string
	port    uint16
}

type socks5Tunnel struct {
	request    socks5Request
	username   string
	destConn   net.Conn
	clientConn net.Conn
	reader     *bufio.Reader
	info       traffic.TrafficSessionInfo
}

func (request socks5Request) addr() string {
	return net.JoinHostPort(request.host, strconv.Itoa(int(request.port)))
}

func (tunnel socks5Tunnel) target() string {
	return tunnel.request.addr()
}

func (tunnel socks5Tunnel) bufferedClientConn() net.Conn {
	return &bufferedReadConn{
		Conn:   tunnel.clientConn,
		reader: tunnel.reader,
	}
}

func (p *Proxy) handleSOCKS5(conn net.Conn) {
	defer conn.Close()

	logger := logutil.WithComponent("socks5")
	reader := bufio.NewReader(conn)
	username, err := p.negotiateSOCKS5Identity(conn, reader)
	if err != nil {
		logger.Warn("negotiation failed", "err", err)
		return
	}

	request, err := readSOCKS5Request(reader)
	if err != nil {
		_ = writeSOCKS5Reply(conn, socks5AddressFail)
		logger.Warn("request read failed", "err", err)
		return
	}
	if request.command != socks5Connect {
		_ = writeSOCKS5Reply(conn, socks5CommandFail)
		logger.Warn("unsupported command", "command", request.command)
		return
	}
	if p.blockTunnels {
		_ = writeSOCKS5Reply(conn, 0x02)
		return
	}

	destAddr := request.addr()
	logger = logger.With("target", destAddr)
	logger.Info("opening tunnel")
	info := traffic.TrafficSessionInfo{
		Protocol:   "SOCKS5",
		Target:     destAddr,
		ClientAddr: netutil.RemoteAddr(conn),
		SNI:        request.host,
	}
	destConn, err := p.dial("tcp", destAddr)
	if err != nil {
		_ = writeSOCKS5Reply(conn, socks5GeneralFail)
		logger.Warn("dial target failed", "err", err)
		p.monitor().RecordEvent("warn", "dial target failed", info, err)
		return
	}

	if err := writeSOCKS5Reply(conn, socks5Succeeded); err != nil {
		destConn.Close()
		logger.Warn("reply failed", "err", err)
		p.monitor().RecordEvent("warn", "SOCKS5 reply failed", info, err)
		return
	}

	p.handleSOCKS5Tunnel(socks5Tunnel{
		request:    request,
		username:   username,
		destConn:   destConn,
		clientConn: conn,
		reader:     reader,
		info:       info,
	})
}

func (p *Proxy) negotiateSOCKS5(conn net.Conn, reader *bufio.Reader) error {
	_, err := p.negotiateSOCKS5Identity(conn, reader)
	return err
}

func (p *Proxy) negotiateSOCKS5Identity(conn net.Conn, reader *bufio.Reader) (string, error) {
	header := make([]byte, 2)
	if _, err := io.ReadFull(reader, header); err != nil {
		return "", err
	}
	if header[0] != socks5Version {
		return "", fmt.Errorf("unsupported version %d", header[0])
	}

	methods := make([]byte, int(header[1]))
	if _, err := io.ReadFull(reader, methods); err != nil {
		return "", err
	}
	requiredMethod := byte(socks5NoAuth)
	credentials := p.authentication()
	if credentials.enabled() {
		requiredMethod = socks5UserPassAuth
	}
	for _, method := range methods {
		if method != requiredMethod {
			continue
		}
		if _, err := conn.Write([]byte{socks5Version, requiredMethod}); err != nil {
			return "", err
		}
		if requiredMethod == socks5UserPassAuth {
			return authenticateSOCKS5(conn, reader, credentials)
		}
		return "", nil
	}

	_, _ = conn.Write([]byte{socks5Version, socks5NoAcceptable})
	return "", fmt.Errorf("no supported authentication method")
}

func authenticateSOCKS5(conn net.Conn, reader *bufio.Reader, credentials proxyCredentials) (string, error) {
	header := make([]byte, 2)
	if _, err := io.ReadFull(reader, header); err != nil {
		return "", err
	}
	if header[0] != socks5AuthVersion {
		_, _ = conn.Write([]byte{socks5AuthVersion, socks5AuthFailure})
		return "", fmt.Errorf("unsupported username/password authentication version %d", header[0])
	}

	username := make([]byte, int(header[1]))
	if _, err := io.ReadFull(reader, username); err != nil {
		return "", err
	}
	passwordLength, err := reader.ReadByte()
	if err != nil {
		return "", err
	}
	password := make([]byte, int(passwordLength))
	if _, err := io.ReadFull(reader, password); err != nil {
		return "", err
	}
	if !credentials.matches(string(username), string(password)) {
		_, _ = conn.Write([]byte{socks5AuthVersion, socks5AuthFailure})
		return "", fmt.Errorf("invalid username or password")
	}

	_, err = conn.Write([]byte{socks5AuthVersion, socks5AuthSuccess})
	return string(username), err
}

func readSOCKS5Request(reader *bufio.Reader) (socks5Request, error) {
	header := make([]byte, 4)
	if _, err := io.ReadFull(reader, header); err != nil {
		return socks5Request{}, err
	}
	if header[0] != socks5Version {
		return socks5Request{}, fmt.Errorf("unsupported version %d", header[0])
	}
	if header[2] != socks5Reserved {
		return socks5Request{}, fmt.Errorf("reserved byte = %d", header[2])
	}

	host, err := readSOCKS5Address(reader, header[3])
	if err != nil {
		return socks5Request{}, err
	}

	portBytes := make([]byte, 2)
	if _, err := io.ReadFull(reader, portBytes); err != nil {
		return socks5Request{}, err
	}

	return socks5Request{
		command: header[1],
		host:    host,
		port:    binary.BigEndian.Uint16(portBytes),
	}, nil
}

func readSOCKS5Address(reader *bufio.Reader, atyp byte) (string, error) {
	switch atyp {
	case socks5IPv4:
		addr := make([]byte, net.IPv4len)
		if _, err := io.ReadFull(reader, addr); err != nil {
			return "", err
		}
		return net.IP(addr).String(), nil
	case socks5Domain:
		length, err := reader.ReadByte()
		if err != nil {
			return "", err
		}
		if length == 0 {
			return "", fmt.Errorf("empty domain")
		}
		domain := make([]byte, int(length))
		if _, err := io.ReadFull(reader, domain); err != nil {
			return "", err
		}
		return string(domain), nil
	case socks5IPv6:
		addr := make([]byte, net.IPv6len)
		if _, err := io.ReadFull(reader, addr); err != nil {
			return "", err
		}
		return net.IP(addr).String(), nil
	default:
		return "", fmt.Errorf("unsupported address type %d", atyp)
	}
}

func writeSOCKS5Reply(conn net.Conn, status byte) error {
	_, err := conn.Write([]byte{
		socks5Version,
		status,
		socks5Reserved,
		socks5IPv4,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00,
	})
	return err
}

func (p *Proxy) handleSOCKS5Tunnel(tunnel socks5Tunnel) {
	destConn := tunnel.destConn
	logger := logutil.WithComponent("socks5", "target", tunnel.target())
	session := p.monitor().StartSession(tunnel.info)
	defer session.Finish()

	if p.inspectTLS || tunnel.request.port == 443 {
		tunnelClientConn := flowid.WithProxyUsername(tunnel.bufferedClientConn(), tunnel.username)
		destConn, wrappedClientConn := traffic.WrapTunnel(session, destConn, tunnelClientConn)
		p.connect(tunnel.request.host, destConn, wrappedClientConn)
		return
	}

	if err := tunnel.clientConn.SetReadDeadline(time.Now().Add(socks5TLSPeekTime)); err != nil {
		destConn.Close()
		logger.Error("set read deadline failed", "err", err)
		session.Fail(err)
		return
	}
	first, err := tunnel.reader.Peek(1)
	if deadlineErr := tunnel.clientConn.SetReadDeadline(time.Time{}); deadlineErr != nil {
		destConn.Close()
		logger.Error("clear read deadline failed", "err", deadlineErr)
		session.Fail(deadlineErr)
		return
	}
	if err != nil {
		if netErr, ok := err.(net.Error); !ok || !netErr.Timeout() {
			destConn.Close()
			logger.Warn("client read failed", "err", err)
			session.Fail(err)
			return
		}
	}

	tunnelClientConn := tunnel.bufferedClientConn()
	if len(first) > 0 && first[0] == tlsHandshakeRecord {
		destConn, wrappedClientConn := traffic.WrapTunnel(session, destConn, tunnelClientConn)
		p.connect(tunnel.request.host, destConn, wrappedClientConn)
		return
	}

	defer destConn.Close()
	destConn, tunnelClientConn = traffic.WrapTunnel(session, destConn, tunnelClientConn)
	pipe.Junction(destConn, tunnelClientConn)
}
