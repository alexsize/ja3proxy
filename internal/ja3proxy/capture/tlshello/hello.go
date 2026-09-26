// Package tlshello parses wire ClientHello messages without using a TLS stack's
// normalized ClientHelloInfo. It does not establish or decrypt TLS connections.
package tlshello

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
)

const MaxHelloSize = 256 << 10

var ErrMalformed = errors.New("malformed_client_hello")

// Extension preserves duplicate IDs, wire order and unknown extension lengths.
// Data is deliberately not exported: it can contain session tickets/identities.
type Extension struct {
	ID       uint16         `json:"id"`
	Position int            `json:"position"`
	Length   int            `json:"length"`
	Fields   map[string]any `json:"fields"`
	Data     []byte         `json:"-"`
}

// NumericIDName keeps the wire numeric identifier authoritative while adding
// a best-effort name for known groups. Unknown and future values are retained
// with an explicit "unknown" name and never cause parse failure.
type NumericIDName struct {
	NumericID    uint16 `json:"numeric_id"`
	ResolvedName string `json:"resolved_name"`
}

type Hello struct {
	LegacyVersion       uint16          `json:"legacy_version"`
	SessionIDLength     int             `json:"session_id_length"`
	CipherSuites        []uint16        `json:"cipher_suites"`
	CompressionMethods  []int           `json:"compression_methods"`
	Extensions          []Extension     `json:"extensions"`
	ServerName          string          `json:"sni"`
	ALPN                []string        `json:"alpn_hex"`
	ALPS                []string        `json:"alps_hex"`
	SupportedVersions   []uint16        `json:"supported_versions"`
	SupportedGroups     []uint16        `json:"supported_groups"`
	SupportedGroupNames []NumericIDName `json:"supported_group_names"`
	SignatureAlgorithms []uint16        `json:"signature_algorithms"`
	PointFormats        []int           `json:"point_formats"`
	ECH                 bool            `json:"ech_detected"`
	HandshakeType       string          `json:"handshake_type"`
	SessionResumption   bool            `json:"session_resumption"`
	PSKPresent          bool            `json:"psk_present"`
	PSKIdentityCount    int             `json:"psk_identity_count"`
	EarlyData           bool            `json:"early_data"`
	Length              int             `json:"length"`
}

// cursor never reads beyond an untrusted length and carries errors to callers.
type cursor struct {
	b   []byte
	err bool
}

func (c *cursor) take(n int) []byte {
	if c.err || n < 0 || n > len(c.b) {
		c.err = true
		return nil
	}
	p := c.b[:n]
	c.b = c.b[n:]
	return p
}
func (c *cursor) u8() int {
	p := c.take(1)
	if p == nil {
		return 0
	}
	return int(p[0])
}
func (c *cursor) u16() int {
	p := c.take(2)
	if p == nil {
		return 0
	}
	return int(binary.BigEndian.Uint16(p))
}
func (c *cursor) vector8() []byte  { n := c.u8(); return c.take(n) }
func (c *cursor) vector16() []byte { n := c.u16(); return c.take(n) }
func (c *cursor) done() bool       { return !c.err && len(c.b) == 0 }
func ids(p []byte) ([]uint16, bool) {
	if len(p)%2 != 0 {
		return nil, false
	}
	out := make([]uint16, 0, len(p)/2)
	for len(p) > 0 {
		out = append(out, binary.BigEndian.Uint16(p))
		p = p[2:]
	}
	return out, true
}
func byteIDs(p []byte) []int {
	out := make([]int, len(p))
	for i, v := range p {
		out[i] = int(v)
	}
	return out
}

func IsGREASE(v uint16) bool { return v&0x0f0f == 0x0a0a && byte(v) == byte(v>>8) }

// Parse accepts exactly one handshake message, including its four-byte header.
func Parse(raw []byte) (*Hello, error) {
	if len(raw) < 4 || len(raw) > MaxHelloSize || raw[0] != 1 || int(raw[1])<<16|int(raw[2])<<8|int(raw[3]) != len(raw)-4 {
		return nil, ErrMalformed
	}
	c := cursor{b: raw[4:]}
	h := &Hello{LegacyVersion: uint16(c.u16()), Length: len(raw), Extensions: []Extension{}, ALPN: []string{}, ALPS: []string{}, SupportedVersions: []uint16{}, SupportedGroups: []uint16{}, SupportedGroupNames: []NumericIDName{}, SignatureAlgorithms: []uint16{}, PointFormats: []int{}}
	c.take(32)
	h.SessionIDLength = len(c.vector8())
	var ok bool
	h.CipherSuites, ok = ids(c.vector16())
	if !ok || len(h.CipherSuites) == 0 || h.SessionIDLength > 32 {
		return nil, ErrMalformed
	}
	h.CompressionMethods = byteIDs(c.vector8())
	if len(h.CompressionMethods) == 0 {
		return nil, ErrMalformed
	}
	if c.done() {
		refreshHandshakeMetadata(h)
		return h, nil
	} // pre-extension ClientHello
	e := cursor{b: c.vector16()}
	if !c.done() {
		return nil, ErrMalformed
	}
	for len(e.b) > 0 && !e.err {
		id := uint16(e.u16())
		data := e.vector16()
		if e.err {
			break
		}
		ext := Extension{ID: id, Position: len(h.Extensions), Length: len(data), Data: append([]byte(nil), data...), Fields: map[string]any{}}
		if err := decodeExtension(h, &ext); err != nil {
			return nil, fmt.Errorf("%w: extension %d", ErrMalformed, id)
		}
		h.Extensions = append(h.Extensions, ext)
	}
	if !e.done() {
		return nil, ErrMalformed
	}
	refreshHandshakeMetadata(h)
	return h, nil
}

// ClientRandom returns the 32-byte ClientHello random for in-memory
// correlation with a user-provided TLS key log. It must not be persisted.
func ClientRandom(raw []byte) ([]byte, error) {
	if len(raw) < 38 || raw[0] != 1 {
		return nil, ErrMalformed
	}
	length := int(raw[1])<<16 | int(raw[2])<<8 | int(raw[3])
	if length != len(raw)-4 {
		return nil, ErrMalformed
	}
	return append([]byte(nil), raw[6:38]...), nil
}

func decodeExtension(h *Hello, e *Extension) error {
	c := cursor{b: e.Data}
	switch e.ID {
	case 0: // server_name
		names := cursor{b: c.vector16()}
		entries := []any{}
		for len(names.b) > 0 && !names.err {
			typ := names.u8()
			name := names.vector16()
			if len(name) == 0 {
				names.err = true
				break
			}
			entries = append(entries, map[string]any{"type": typ, "name_hex": hex.EncodeToString(name)})
			if typ == 0 && h.ServerName == "" {
				h.ServerName = string(name)
			}
		}
		if !names.done() {
			return ErrMalformed
		}
		e.Fields["names"] = entries
	case 10, 13, 50, 34: // groups, signatures, cert signatures, delegated credentials
		v, ok := ids(c.vector16())
		if !ok {
			return ErrMalformed
		}
		e.Fields["values"] = v
		if e.ID == 10 {
			h.SupportedGroups = append(h.SupportedGroups, v...)
			named := namedNumericIDs(v)
			e.Fields["values_named"] = named
			h.SupportedGroupNames = append(h.SupportedGroupNames, named...)
		}
		if e.ID == 13 {
			h.SignatureAlgorithms = append(h.SignatureAlgorithms, v...)
		}
	case 11, 45: // point formats / PSK exchange modes
		v := byteIDs(c.vector8())
		e.Fields["values"] = v
		if e.ID == 11 {
			h.PointFormats = append(h.PointFormats, v...)
		}
	case 16, 17513, 17613: // ALPN/ALPS carry the same length-prefixed protocol list
		list := cursor{b: c.vector16()}
		protocols := []string{}
		for len(list.b) > 0 && !list.err {
			p := list.vector8()
			if len(p) == 0 {
				list.err = true
				break
			}
			protocols = append(protocols, hex.EncodeToString(p))
		}
		if !list.done() {
			return ErrMalformed
		}
		e.Fields["protocols_hex"] = protocols
		if e.ID == 16 {
			h.ALPN = append(h.ALPN, protocols...)
		} else {
			h.ALPS = append(h.ALPS, protocols...)
		}
	case 43:
		v, ok := ids(c.vector8())
		if !ok {
			return ErrMalformed
		}
		e.Fields["values"] = v
		h.SupportedVersions = append(h.SupportedVersions, v...)
	case 51:
		list := cursor{b: c.vector16()}
		shares := []any{}
		for len(list.b) > 0 && !list.err {
			group := list.u16()
			key := list.vector16()
			shares = append(shares, map[string]any{"group": group, "key_length": len(key)})
		}
		if !list.done() {
			return ErrMalformed
		}
		e.Fields["shares"] = shares
		named := make([]NumericIDName, 0, len(shares))
		for _, share := range shares {
			m := share.(map[string]any)
			named = append(named, NumericIDName{NumericID: uint16(m["group"].(int)), ResolvedName: resolveNumericGroup(uint16(m["group"].(int)))})
		}
		e.Fields["shares_named"] = named
	case 41:
		list := cursor{b: c.vector16()}
		identities := []any{}
		for len(list.b) > 0 && !list.err {
			identity := list.vector16()
			age := list.take(4)
			if len(identity) == 0 {
				list.err = true
			}
			if len(age) == 4 {
				identities = append(identities, map[string]any{"length": len(identity), "obfuscated_ticket_age": binary.BigEndian.Uint32(age)})
			}
		}
		if !list.done() {
			return ErrMalformed
		}
		binders := cursor{b: c.vector16()}
		lengths := []int{}
		for len(binders.b) > 0 && !binders.err {
			b := binders.vector8()
			if len(b) < 32 {
				binders.err = true
			}
			lengths = append(lengths, len(b))
		}
		if !binders.done() || len(identities) == 0 || len(identities) != len(lengths) {
			return ErrMalformed
		}
		e.Fields["identities"] = identities
		e.Fields["binder_lengths"] = lengths
		h.PSKPresent = true
		h.PSKIdentityCount = len(identities)
	case 42:
		h.EarlyData = true
		e.Fields["present"] = true
		c.take(len(c.b))
	case 27:
		v, ok := ids(c.vector8())
		if !ok {
			return ErrMalformed
		}
		e.Fields["values"] = v
	case 28:
		e.Fields["limit"] = c.u16()
	case 21:
		for _, b := range c.b {
			if b != 0 {
				return ErrMalformed
			}
		}
		c.take(len(c.b))
		e.Fields["padding_length"] = e.Length
	case 35: // session ticket bytes deliberately discarded
		c.take(len(c.b))
		e.Fields["ticket_length"] = e.Length
	case 65037: // ECH: only outer structure available
		h.ECH = true
		e.Fields["inner_available"] = false
		c.take(len(c.b))
	case 5, 18, 23, 65281:
		// Retain non-secret wire parameters as hex for these opaque structures.
		e.Fields["data_hex"] = hex.EncodeToString(c.take(len(c.b)))
	default:
		e.Fields["opaque_length"] = e.Length
		c.take(len(c.b))
	}
	if !c.done() {
		return ErrMalformed
	}
	return nil
}
