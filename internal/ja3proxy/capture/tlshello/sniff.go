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

func (c *replayConn) Read(p []byte) (int, error) {
	if c.prefix.Len() > 0 {
		return c.prefix.Read(p)
	}
	return c.Conn.Read(p)
}

// Sniff is used only on newly owned proxy connections with no previous read
// deadline. Every byte consumed is replayed, including on timeout/non-TLS.
func Sniff(conn net.Conn, timeout time.Duration, limits Limits) (net.Conn, Capture, error) {
	limits = limits.bounded()
	s := NewStream(limits)
	var consumed []byte
	if err := conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		return conn, Capture{Status: "timeout", ErrorCode: "deadline_failed"}, err
	}
	read := func(n int) error {
		p := make([]byte, n)
		got, err := io.ReadFull(conn, p)
		consumed = append(consumed, p[:got]...)
		s.Feed(p[:got])
		return err
	}
	var readErr error
	for !s.Done() {
		// Fail early for non-TLS without waiting for a full record header.
		if readErr = read(1); readErr != nil || s.Done() {
			break
		}
		if readErr = read(4); readErr != nil || s.Done() {
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
	capture := s.Finish(reason)
	resetErr := conn.SetReadDeadline(time.Time{})
	return &replayConn{Conn: conn, prefix: bytes.NewReader(consumed)}, capture, resetErr
}
