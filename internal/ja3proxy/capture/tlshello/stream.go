package tlshello

import (
	"encoding/binary"
	"net"
	"sync"
)

type Limits struct {
	MaxHello   int
	MaxRecord  int
	MaxRecords int
}

func DefaultLimits() Limits { return Limits{MaxHelloSize, 18432, 64} }

func (l Limits) bounded() Limits {
	if l.MaxHello <= 0 || l.MaxHello > MaxHelloSize {
		l.MaxHello = MaxHelloSize
	}
	if l.MaxRecord <= 0 || l.MaxRecord > 18432 {
		l.MaxRecord = 18432
	}
	if l.MaxRecords <= 0 || l.MaxRecords > 64 {
		l.MaxRecords = 64
	}
	return l
}

type Capture struct {
	Status              string `json:"completeness"`
	ErrorStage          string `json:"error_stage,omitempty"`
	ErrorCode           string `json:"error_code,omitempty"`
	RecordVersion       uint16 `json:"record_version"`
	RecordCount         int    `json:"record_count"`
	DeclaredHelloLength int    `json:"declared_hello_length,omitempty"`
	Raw                 []byte `json:"-"`
	Records             []byte `json:"-"`
	HandshakeSequence   int    `json:"-"`
}

// Stream reassembles the first expected plaintext TLS handshake message.
// Memory has hard limits independent of the size of Feed's argument. Returned
// captures own their bytes.
type Stream struct {
	limits                Limits
	handshakeType         byte
	header                [5]byte
	headerN               int
	remaining             int
	skipRecord            bool
	allowCompatibilityCCS bool
	result                Capture
	done                  bool
}

func newStream(l Limits, handshakeType byte) *Stream {
	return &Stream{
		limits:                l.bounded(),
		handshakeType:         handshakeType,
		allowCompatibilityCCS: handshakeType == ServerHelloType,
	}
}

func NewStream(l Limits) *Stream       { return newStream(l, 1) }
func NewServerStream(l Limits) *Stream { return newStream(l, ServerHelloType) }
func (s *Stream) Done() bool           { return s.done }
func (s *Stream) fail(status, code string) {
	s.result.Status = status
	s.result.ErrorStage = "capture"
	s.result.ErrorCode = code
	s.done = true
}

func (s *Stream) Feed(p []byte) {
	_ = s.FeedN(p)
}

// FeedN is Feed with the number of input bytes consumed. A complete TLS
// record is consumed as a unit; this is enough to chain server handshake
// records because HelloRetryRequest and the following ServerHello are sent in
// different server records.
func (s *Stream) FeedN(p []byte) int {
	initial := len(p)
	for len(p) > 0 && !s.done {
		if s.skipRecord {
			if s.remaining == 1 && len(p) > 0 && p[0] != 1 {
				s.fail("malformed", "invalid_change_cipher_spec")
				return initial - len(p)
			}
			n := min(s.remaining, len(p))
			p = p[n:]
			s.remaining -= n
			if s.remaining == 0 {
				s.skipRecord = false
				s.headerN = 0
			}
			continue
		}
		if s.headerN < 5 {
			// A TLS 1.3 peer may send a one-byte compatibility
			// ChangeCipherSpec between HelloRetryRequest and the next Hello.
			compatibilityCCS := s.allowCompatibilityCCS && p[0] == 20
			if s.headerN == 0 && p[0] != 22 && !compatibilityCCS {
				if s.result.RecordCount == 0 {
					s.fail("not_tls", s.notExpectedCode())
				} else {
					s.fail("malformed", "unexpected_record_type")
				}
				return initial - len(p)
			}
			n := copy(s.header[s.headerN:], p)
			s.headerN += n
			p = p[n:]
			if s.headerN < 5 {
				return initial - len(p)
			}
			version := binary.BigEndian.Uint16(s.header[1:3])
			s.remaining = int(binary.BigEndian.Uint16(s.header[3:5]))
			if version < 0x0300 || version > 0x0303 {
				s.fail("malformed", "record_version")
				return initial - len(p)
			}
			if s.remaining > s.limits.MaxRecord {
				s.fail("truncated", "record_limit")
				return initial - len(p)
			}
			if s.remaining == 0 {
				s.fail("malformed", "empty_handshake_record")
				return initial - len(p)
			}
			if s.header[0] == 20 && s.allowCompatibilityCCS {
				if s.remaining != 1 {
					s.fail("malformed", "invalid_change_cipher_spec")
					return initial - len(p)
				}
				s.allowCompatibilityCCS = false
				s.skipRecord = true
				continue
			}
			if s.header[0] != 22 {
				s.fail("malformed", s.notExpectedCode())
				return initial - len(p)
			}
			if s.result.RecordCount >= s.limits.MaxRecords {
				s.fail("truncated", "record_count_limit")
				return initial - len(p)
			}
			if s.result.RecordCount == 0 {
				s.result.RecordVersion = version
			}
			s.result.RecordCount++
			s.result.Records = append(s.result.Records, s.header[:]...)
		}
		n := min(s.remaining, len(p))
		chunk := p[:n]
		p = p[n:]
		s.remaining -= n
		s.result.Records = append(s.result.Records, chunk...)
		for len(chunk) > 0 {
			if len(s.result.Raw) < 4 {
				k := min(4-len(s.result.Raw), len(chunk))
				s.result.Raw = append(s.result.Raw, chunk[:k]...)
				chunk = chunk[k:]
				if len(s.result.Raw) < 4 {
					break
				}
				if s.result.Raw[0] != s.handshakeType {
					s.fail("malformed", s.notExpectedCode())
					return initial - len(p)
				}
				s.result.DeclaredHelloLength = 4 + (int(s.result.Raw[1])<<16 | int(s.result.Raw[2])<<8 | int(s.result.Raw[3]))
				if s.result.DeclaredHelloLength > s.limits.MaxHello {
					s.fail("truncated", "hello_limit")
					return initial - len(p)
				}
			}
			k := min(s.result.DeclaredHelloLength-len(s.result.Raw), len(chunk))
			s.result.Raw = append(s.result.Raw, chunk[:k]...)
			chunk = chunk[k:]
			if len(s.result.Raw) == s.result.DeclaredHelloLength {
				break
			}
		}
		if s.remaining == 0 {
			if s.result.DeclaredHelloLength > 0 && len(s.result.Raw) == s.result.DeclaredHelloLength {
				s.result.Status = "complete"
				s.done = true
				return initial - len(p)
			}
			s.headerN = 0
		}
	}
	return initial - len(p)
}

func (s *Stream) Finish(reason string) Capture {
	if !s.done {
		if reason == "timeout" {
			s.fail("timeout", "capture_timeout")
		} else {
			s.fail("truncated", s.incompleteCode())
		}
	}
	return s.result
}

func (s *Stream) notExpectedCode() string {
	if s.handshakeType == ServerHelloType {
		return "not_server_hello"
	}
	return "not_client_hello"
}

func (s *Stream) incompleteCode() string {
	if s.handshakeType == ServerHelloType {
		return "incomplete_server_hello"
	}
	return "incomplete_client_hello"
}

// Conn observes one side of a connection without prefetching or modifying
// deadlines. publish MUST be nonblocking (the recorder's TryCapture is).
type Conn struct {
	net.Conn
	stream   *Stream
	read     bool
	server   bool
	publish  func(Capture)
	mu       sync.Mutex
	emitted  bool
	sequence int
}

func Wrap(conn net.Conn, read bool, limits Limits, publish func(Capture)) *Conn {
	return wrap(conn, read, NewStream(limits), publish)
}

func WrapServerHello(conn net.Conn, read bool, limits Limits, publish func(Capture)) *Conn {
	return wrap(conn, read, NewServerStream(limits), publish)
}

func wrap(conn net.Conn, read bool, stream *Stream, publish func(Capture)) *Conn {
	return &Conn{Conn: conn, read: read, stream: stream, server: stream.handshakeType == ServerHelloType, publish: publish}
}

func (c *Conn) capture(p []byte, err error) {
	remaining := p
	for {
		if c.emitted && !c.server && startsPotentialClientHelloRecord(remaining) {
			c.stream = NewStream(c.stream.limits)
			c.stream.allowCompatibilityCCS = true
			c.emitted = false
			continue
		}
		if len(remaining) > 0 && !c.stream.Done() {
			consumed := c.stream.FeedN(remaining)
			if consumed > 0 {
				remaining = remaining[consumed:]
			} else {
				break
			}
		}
		if !c.stream.Done() || c.emitted {
			break
		}
		capture := c.stream.Finish("closed")
		c.emitted = true
		if c.ignoreFollowup(capture) {
			// A post-ClientHello CCS or a different handshake message is not
			// another ClientHello observation.
			if startsPotentialClientHelloRecord(remaining) {
				continue
			}
			break
		}
		c.sequence++
		capture.HandshakeSequence = c.sequence
		if c.publish != nil {
			c.publish(capture)
		}
		if c.server && capture.Status == "complete" && isHelloRetryRequest(capture.Raw) {
			c.stream = NewServerStream(c.stream.limits)
			c.emitted = false
			continue
		}
		if !c.server && capture.Status == "complete" && startsPotentialClientHelloRecord(remaining) {
			c.stream = NewStream(c.stream.limits)
			c.stream.allowCompatibilityCCS = true
			c.emitted = false
			continue
		}
		break
	}
	if err != nil && !c.stream.Done() {
		reason := "closed"
		if e, ok := err.(net.Error); ok && e.Timeout() {
			reason = "timeout"
		}
		c.stream.Finish(reason)
	}
	if c.stream.Done() && !c.emitted {
		c.emitted = true
		capture := c.stream.Finish("closed")
		if c.ignoreFollowup(capture) {
			return
		}
		c.sequence++
		capture.HandshakeSequence = c.sequence
		if c.publish != nil {
			c.publish(capture)
		}
	}
}

func (c *Conn) ignoreFollowup(capture Capture) bool {
	return !c.server && c.sequence > 0 && (capture.ErrorCode == "not_client_hello" ||
		(capture.RecordCount == 0 && len(capture.Raw) == 0 && c.stream.headerN == 0))
}

func startsPotentialClientHelloRecord(p []byte) bool {
	return len(p) > 0 && (p[0] == 20 || p[0] == 22)
}

func isHelloRetryRequest(raw []byte) bool {
	hello, err := ParseServerHello(raw)
	return err == nil && hello.Fields.HelloRetryRequest.Available && hello.Fields.HelloRetryRequest.Value
}

func (c *Conn) Read(p []byte) (int, error) {
	if !c.read {
		return c.Conn.Read(p)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	n, err := c.Conn.Read(p)
	c.capture(p[:n], err)
	return n, err
}

func (c *Conn) Write(p []byte) (int, error) {
	if c.read {
		return c.Conn.Write(p)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	n, err := c.Conn.Write(p)
	c.capture(p[:n], err)
	return n, err
}

// Close first closes the underlying socket, unblocking an in-flight Read/Write.
func (c *Conn) Close() error {
	err := c.Conn.Close()
	c.Finish()
	return err
}

func (c *Conn) Finish() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.emitted {
		c.stream.Finish("closed")
		c.capture(nil, nil)
	}
}
