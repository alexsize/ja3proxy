package tlshello

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"time"
)

type replayConn struct {
	net.Conn
	prefix *bytes.Reader
}

// UnwrapConn preserves transparent connection metadata (flow ID, proxy
// username and source address) for callers that inspect the connection after
// the bounded replay buffer has been installed.
func (c *replayConn) UnwrapConn() net.Conn { return c.Conn }

func (c *replayConn) Read(p []byte) (int, error) {
	if c.prefix.Len() > 0 {
		return c.prefix.Read(p)
	}
	return c.Conn.Read(p)
}

// Sniff is used only on newly owned proxy connections with no previous read
// deadline. Every byte consumed is replayed, including on timeout/non-TLS.
func Sniff(conn net.Conn, timeout time.Duration, limits Limits) (net.Conn, Capture, error) {
	return sniff(conn, timeout, NewStream(limits))
}

func SniffServerHello(conn net.Conn, timeout time.Duration, limits Limits) (net.Conn, Capture, error) {
	return sniff(conn, timeout, NewServerStream(limits))
}

func sniff(conn net.Conn, timeout time.Duration, stream *Stream) (net.Conn, Capture, error) {
	limits := stream.limits.bounded()
	stream = newStream(limits, stream.handshakeType)
	var consumed []byte
	if err := conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		return conn, Capture{Status: "timeout", ErrorCode: "deadline_failed"}, err
	}
	read := func(n int) error {
		p := make([]byte, n)
		got, err := io.ReadFull(conn, p)
		consumed = append(consumed, p[:got]...)
		stream.Feed(p[:got])
		return err
	}
	var readErr error
	for !stream.Done() {
		// Fail early for non-TLS without waiting for a full record header.
		if readErr = read(1); readErr != nil || stream.Done() {
			break
		}
		if readErr = read(4); readErr != nil || stream.Done() {
			break
		}
		n := int(binary.BigEndian.Uint16(consumed[len(consumed)-2:]))
		if readErr = read(n); readErr != nil {
			break
		}
	}
	reason := "closed"
	if e, ok := readErr.(net.Error); ok && e.Timeout() {
		reason = "timeout"
	}
	capture := stream.Finish(reason)
	resetErr := conn.SetReadDeadline(time.Time{})
	return &replayConn{Conn: conn, prefix: bytes.NewReader(consumed)}, capture, resetErr
}
