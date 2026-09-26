// Package http1 extracts a bounded, privacy-safe HTTP/1.x fingerprint from
// raw application bytes. It is intentionally independent of net/http so
// header order and original header spelling are preserved.
package http1

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net"
	"strconv"
	"strings"

	"github.com/lylemi/ja3proxy/internal/ja3proxy/capture/appversion"
)

const (
	NormalizationVersion = "HTTP1-NORM-2"
	DefaultMaxHeaderSize = 64 << 10
)

type Header struct {
	Name        string `json:"name"`
	ValueSHA256 string `json:"value_sha256"`
}

type Message struct {
	Direction           string                 `json:"direction"`
	Kind                string                 `json:"kind"`
	Sequence            int                    `json:"sequence"`
	Completeness        string                 `json:"completeness"`
	BodyFraming         string                 `json:"body_framing"`
	BodyCaptured        bool                   `json:"body_captured"`
	TrailerStatus       string                 `json:"trailer_status,omitempty"`
	Method              string                 `json:"method,omitempty"`
	RequestTarget       string                 `json:"request_target,omitempty"`
	HTTPVersion         string                 `json:"http_version"`
	StatusCode          int                    `json:"status_code,omitempty"`
	Reason              string                 `json:"reason,omitempty"`
	HeaderOrder         []string               `json:"header_order"`
	OriginalHeaderNames []string               `json:"original_header_names"`
	Headers             []Header               `json:"headers"`
	VersionEvidence     []appversion.Evidence  `json:"application_version_evidence,omitempty"`
	ContentLength       int64                  `json:"content_length,omitempty"`
	TransferEncoding    []string               `json:"transfer_encoding,omitempty"`
}

type Analyzer struct {
	direction      string
	maxHeader      int
	buffer         []byte
	remaining      int64
	chunked        bool
	chunkRemaining int64
	chunkNeedCRLF  bool
	chunkTrailers  bool
	sequence       int
	disabled       bool
}

func New(direction string, maxHeader int) *Analyzer {
	if maxHeader < 1 {
		maxHeader = DefaultMaxHeaderSize
	}
	return &Analyzer{direction: direction, maxHeader: maxHeader}
}

func (a *Analyzer) Observe(p []byte) []Message {
	if a == nil || a.disabled || len(p) == 0 {
		return nil
	}
	a.buffer = append(a.buffer, p...)
	var messages []Message
	for len(a.buffer) > 0 {
		if a.chunked {
			complete, err := a.consumeChunkedBody()
			if err != nil {
				a.buffer = nil
				a.disabled = true
				break
			}
			if !complete {
				break
			}
			a.chunked = false
			continue
		}
		if a.remaining > 0 {
			skip := int64(len(a.buffer))
			if skip > a.remaining {
				skip = a.remaining
			}
			a.buffer = a.buffer[skip:]
			a.remaining -= skip
			if a.remaining > 0 {
				break
			}
		}
		end := bytes.Index(a.buffer, []byte("\r\n\r\n"))
		if end < 0 {
			if len(a.buffer) > a.maxHeader {
				a.buffer = nil
				a.disabled = true
			}
			break
		}
		if end > a.maxHeader {
			a.buffer = nil
			a.disabled = true
			break
		}
		blockEnd := end + 4
		message, contentLength, chunked, err := parse(a.direction, a.sequence+1, a.buffer[:blockEnd])
		if err != nil {
			a.buffer = nil
			a.disabled = true
			break
		}
		a.sequence++
		messages = append(messages, message)
		a.buffer = a.buffer[blockEnd:]
		if chunked {
			a.chunked = true
			a.chunkRemaining = -1
			a.chunkNeedCRLF = false
			a.chunkTrailers = false
			continue
		}
		if message.BodyFraming == "close_delimited" || message.BodyFraming == "upgrade" || message.BodyFraming == "unsupported_transfer_encoding" {
			a.buffer = nil
			a.disabled = true
			break
		}
		a.remaining = contentLength
	}
	return messages
}

// consumeChunkedBody skips chunk framing and payload without retaining either.
// complete is true only after the terminal chunk and optional trailers.
func (a *Analyzer) consumeChunkedBody() (complete bool, err error) {
	for {
		if a.chunkRemaining > 0 {
			skip := int64(len(a.buffer))
			if skip > a.chunkRemaining {
				skip = a.chunkRemaining
			}
			a.buffer = a.buffer[skip:]
			a.chunkRemaining -= skip
			if a.chunkRemaining > 0 {
				return false, nil
			}
			a.chunkNeedCRLF = true
		}
		if a.chunkNeedCRLF {
			if len(a.buffer) < 2 {
				return false, nil
			}
			if !bytes.Equal(a.buffer[:2], []byte("\r\n")) {
				return false, errors.New("invalid HTTP/1 chunk terminator")
			}
			a.buffer = a.buffer[2:]
			a.chunkNeedCRLF = false
			a.chunkRemaining = -1
		}
		if a.chunkTrailers {
			if len(a.buffer) < 2 {
				return false, nil
			}
			if bytes.Equal(a.buffer[:2], []byte("\r\n")) {
				a.buffer = a.buffer[2:]
				return true, nil
			}
			end := bytes.Index(a.buffer, []byte("\r\n\r\n"))
			if end < 0 {
				if len(a.buffer) > a.maxHeader {
					return false, errors.New("HTTP/1 trailers exceed limit")
				}
				return false, nil
			}
			if end > a.maxHeader {
				return false, errors.New("HTTP/1 trailers exceed limit")
			}
			for _, line := range bytes.Split(a.buffer[:end], []byte("\r\n")) {
				if bytes.IndexByte(line, ':') <= 0 {
					return false, errors.New("invalid HTTP/1 trailer")
				}
			}
			a.buffer = a.buffer[end+4:]
			return true, nil
		}
		if a.chunkRemaining < 0 {
			end := bytes.Index(a.buffer, []byte("\r\n"))
			if end < 0 {
				if len(a.buffer) > a.maxHeader {
					return false, errors.New("HTTP/1 chunk size exceeds limit")
				}
				return false, nil
			}
			if end > a.maxHeader {
				return false, errors.New("HTTP/1 chunk size exceeds limit")
			}
			line := a.buffer[:end]
			if extension := bytes.IndexByte(line, ';'); extension >= 0 {
				line = line[:extension]
			}
			if len(line) == 0 {
				return false, errors.New("empty HTTP/1 chunk size")
			}
			size, parseErr := strconv.ParseUint(string(line), 16, 63)
			if parseErr != nil {
				return false, errors.New("invalid HTTP/1 chunk size")
			}
			a.buffer = a.buffer[end+2:]
			if size == 0 {
				a.chunkTrailers = true
				continue
			}
			a.chunkRemaining = int64(size)
		}
	}
}

func parse(direction string, sequence int, block []byte) (Message, int64, bool, error) {
	lines := bytes.Split(block[:len(block)-4], []byte("\r\n"))
	if len(lines) < 1 {
		return Message{}, 0, false, errors.New("empty HTTP/1 message")
	}
	first := strings.Fields(string(lines[0]))
	message := Message{Direction: direction, Sequence: sequence, Completeness: "complete", BodyFraming: "none"}
	if len(first) >= 2 && strings.HasPrefix(first[0], "HTTP/") {
		if first[0] != "HTTP/1.0" && first[0] != "HTTP/1.1" {
			return Message{}, 0, false, errors.New("unsupported HTTP version")
		}
		message.Kind = "response"
		message.HTTPVersion = first[0]
		code, err := strconv.Atoi(first[1])
		if err != nil || code < 100 || code > 999 {
			return Message{}, 0, false, errors.New("invalid HTTP/1 status")
		}
		message.StatusCode = code
		if len(first) > 2 {
			message.Reason = strings.Join(first[2:], " ")
		}
	} else {
		if len(first) != 3 || (first[2] != "HTTP/1.0" && first[2] != "HTTP/1.1") || first[0] == "" || first[1] == "" {
			return Message{}, 0, false, errors.New("invalid HTTP/1 request line")
		}
		message.Kind = "request"
		message.Method, message.RequestTarget, message.HTTPVersion = first[0], first[1], first[2]
	}
	var contentLength int64
	var hasContentLength bool
	var chunked bool
	for _, raw := range lines[1:] {
		colon := bytes.IndexByte(raw, ':')
		if colon <= 0 {
			return Message{}, 0, false, errors.New("invalid HTTP/1 header")
		}
		name := string(raw[:colon])
		value := strings.TrimSpace(string(raw[colon+1:]))
		message.HeaderOrder = append(message.HeaderOrder, name)
		message.OriginalHeaderNames = append(message.OriginalHeaderNames, name)
		digest := sha256.Sum256([]byte(value))
		message.Headers = append(message.Headers, Header{Name: name, ValueSHA256: hex.EncodeToString(digest[:])})
		if strings.EqualFold(name, "Content-Length") && !hasContentLength {
			n, err := strconv.ParseInt(value, 10, 64)
			if err != nil || n < 0 {
				return Message{}, 0, false, errors.New("invalid Content-Length")
			}
			contentLength, hasContentLength = n, true
			message.ContentLength = n
		}
		if message.Kind == "request" && strings.EqualFold(name, "User-Agent") {
			message.VersionEvidence = appversion.AppendUserAgent(message.VersionEvidence, value)
		}
		if strings.EqualFold(name, "Transfer-Encoding") {
			for _, encoding := range strings.Split(value, ",") {
				encoding = strings.ToLower(strings.TrimSpace(encoding))
				if encoding != "" {
					message.TransferEncoding = append(message.TransferEncoding, encoding)
				}
			}
		}
	}
	for index, encoding := range message.TransferEncoding {
		if encoding == "chunked" {
			if index != len(message.TransferEncoding)-1 {
				return Message{}, 0, false, errors.New("chunked must be the final transfer coding")
			}
			chunked = true
		}
	}
	if len(message.TransferEncoding) > 0 && !chunked {
		message.BodyFraming = "unsupported_transfer_encoding"
		message.Completeness = "partial"
	}
	if chunked {
		message.BodyFraming = "chunked"
		message.Completeness = "partial"
		message.TrailerStatus = "not_fingerprinted"
	} else if hasContentLength {
		message.BodyFraming = "content_length"
		if contentLength > 0 {
			message.Completeness = "partial"
		}
	}
	if message.Kind == "response" {
		switch {
		case message.StatusCode == 101:
			message.BodyFraming = "upgrade"
			message.Completeness = "partial"
		case message.StatusCode >= 100 && message.StatusCode < 200,
			message.StatusCode == 204, message.StatusCode == 205, message.StatusCode == 304:
			// These responses are defined to have no message body.
			contentLength = 0
			chunked = false
			message.BodyFraming = "none"
			message.Completeness = "complete"
			message.TrailerStatus = ""
		default:
			if !chunked && (len(message.TransferEncoding) > 0 || !hasContentLength) {
				// The body ends with the connection. Do not mistake body bytes for
				// another HTTP response when framing cannot be observed safely.
				message.BodyFraming = "close_delimited"
				message.Completeness = "partial"
			}
		}
	}
	return message, contentLength, chunked, nil
}

type Conn struct {
	net.Conn
	analyzer *Analyzer
	on       func(Message)
}

func WrapConn(conn net.Conn, direction string, on func(Message)) net.Conn {
	if conn == nil || on == nil {
		return conn
	}
	return &Conn{Conn: conn, analyzer: New(direction, DefaultMaxHeaderSize), on: on}
}

func (c *Conn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		for _, message := range c.analyzer.Observe(p[:n]) {
			c.on(message)
		}
	}
	return n, err
}
