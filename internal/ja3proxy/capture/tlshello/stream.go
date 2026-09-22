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
	ErrorCode           string `json:"error_code,omitempty"`
	RecordVersion       uint16 `json:"record_version"`
	RecordCount         int    `json:"record_count"`
	DeclaredHelloLength int    `json:"declared_hello_length,omitempty"`
	Raw                 []byte `json:"-"`
	Records             []byte `json:"-"`
}

// Stream reassembles the first plaintext ClientHello. Memory has hard limits
// independent of the size of Feed's argument. Returned captures own their bytes.
type Stream struct {
	limits    Limits
	header    [5]byte
	headerN   int
	remaining int
	result    Capture
	done      bool
}

func NewStream(l Limits) *Stream { return &Stream{limits: l.bounded()} }
func (s *Stream) Done() bool     { return s.done }
func (s *Stream) fail(status, code string) {
	s.result.Status = status
	s.result.ErrorCode = code
	s.done = true
}

func (s *Stream) Feed(p []byte) {
	for len(p) > 0 && !s.done {
		if s.headerN < 5 {
			// A non-handshake first byte is sufficient to reject TLS ClientHello,
			// but never sufficient to accept it as TLS.
			if s.headerN == 0 && p[0] != 22 {
				if s.result.RecordCount == 0 {
					s.fail("not_tls", "not_client_hello")
				} else {
					s.fail("malformed", "unexpected_record_type")
				}
				return
			}
			n := copy(s.header[s.headerN:], p)
			s.headerN += n
			p = p[n:]
			if s.headerN < 5 {
				return
			}
			version := binary.BigEndian.Uint16(s.header[1:3])
			s.remaining = int(binary.BigEndian.Uint16(s.header[3:5]))
			if version < 0x0300 || version > 0x0303 {
				s.fail("malformed", "record_version")
				return
			}
			if s.remaining > s.limits.MaxRecord {
				s.fail("truncated", "record_limit")
				return
			}
			if s.remaining == 0 {
				s.fail("malformed", "empty_handshake_record")
				return
			}
			if s.result.RecordCount >= s.limits.MaxRecords {
				s.fail("truncated", "record_count_limit")
				return
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
				if s.result.Raw[0] != 1 {
					s.fail("malformed", "handshake_type")
					return
				}
				s.result.DeclaredHelloLength = 4 + (int(s.result.Raw[1])<<16 | int(s.result.Raw[2])<<8 | int(s.result.Raw[3]))
				if s.result.DeclaredHelloLength > s.limits.MaxHello {
					s.fail("truncated", "hello_limit")
					return
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
				return
			}
			s.headerN = 0
		}
	}
}

func (s *Stream) Finish(reason string) Capture {
	if !s.done {
		if reason == "timeout" {
			s.fail("timeout", "capture_timeout")
		} else {
			s.fail("truncated", "incomplete_client_hello")
		}
	}
	return s.result
}

// Conn observes one side of a connection without prefetching or modifying
// deadlines. publish MUST be nonblocking (the recorder's TryCapture is).
type Conn struct {
	net.Conn
	stream  *Stream
	read    bool
	publish func(Capture)
	mu      sync.Mutex
	emitted bool
}

func Wrap(conn net.Conn, read bool, limits Limits, publish func(Capture)) *Conn {
	return &Conn{Conn: conn, read: read, stream: NewStream(limits), publish: publish}
}

func (c *Conn) capture(p []byte, err error) {
	c.stream.Feed(p)
	if err != nil && !c.stream.Done() {
		reason := "closed"
		if e, ok := err.(net.Error); ok && e.Timeout() {
			reason = "timeout"
		}
		c.stream.Finish(reason)
	}
	if c.stream.Done() && !c.emitted {
		c.emitted = true
		if c.publish != nil {
			c.publish(c.stream.Finish("closed"))
		}
	}
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
