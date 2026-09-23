// Package flowid assigns an immutable ID to an accepted proxy transport flow.
package flowid

import (
	"crypto/rand"
	"net"
	"time"
)

type carrier interface {
	ConnectionID() string
}

type proxyUsernameCarrier interface {
	ProxyUsername() string
}

type unwrapper interface {
	UnwrapConn() net.Conn
}

type identifiedConn struct {
	net.Conn
	id string
}

type proxyUsernameConn struct {
	net.Conn
	username string
}

func (conn *identifiedConn) ConnectionID() string     { return conn.id }
func (conn *identifiedConn) UnwrapConn() net.Conn     { return conn.Conn }
func (conn *proxyUsernameConn) ProxyUsername() string { return conn.username }
func (conn *proxyUsernameConn) UnwrapConn() net.Conn  { return conn.Conn }

// WithProxyUsername attaches only the authenticated proxy username to a
// connection. Passwords and authorization headers are deliberately excluded.
func WithProxyUsername(conn net.Conn, username string) net.Conn {
	if conn == nil || username == "" {
		return conn
	}
	if ProxyUsernameFrom(conn) != "" {
		return conn
	}
	return &proxyUsernameConn{Conn: conn, username: username}
}

// ProxyUsernameFrom follows transparent connection wrappers and returns the
// authenticated proxy username, if the proxy protocol supplied one.
func ProxyUsernameFrom(conn net.Conn) string {
	for depth := 0; conn != nil && depth < 16; depth++ {
		if value, ok := conn.(proxyUsernameCarrier); ok {
			if username := value.ProxyUsername(); username != "" {
				return username
			}
		}
		value, ok := conn.(unwrapper)
		if !ok {
			return ""
		}
		next := value.UnwrapConn()
		if next == conn {
			return ""
		}
		conn = next
	}
	return ""
}

// New returns a Crockford-base32 ULID with random entropy and a millisecond UTC
// timestamp. IDs need not be strictly monotonic within one millisecond.
func New() string {
	var value [16]byte
	_, _ = rand.Read(value[:])
	milliseconds := uint64(time.Now().UnixMilli())
	for index := 5; index >= 0; index-- {
		value[index] = byte(milliseconds)
		milliseconds >>= 8
	}
	const alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
	var result [26]byte
	for index := range result {
		encoded := 0
		for bitOffset := 0; bitOffset < 5; bitOffset++ {
			bit := index*5 + bitOffset - 2
			encoded <<= 1
			if bit >= 0 {
				encoded |= int((value[bit/8] >> uint(7-bit%8)) & 1)
			}
		}
		result[index] = alphabet[encoded]
	}
	return string(result[:])
}

// Wrap assigns an ID once. It must be called immediately after Accept, before
// protocol detection. Existing identified connections are returned unchanged.
func Wrap(conn net.Conn) net.Conn {
	if conn == nil || From(conn) != "" {
		return conn
	}
	return &identifiedConn{Conn: conn, id: New()}
}

// From follows transparent connection wrappers without relying on concrete
// proxy, traffic-monitor or recorder types.
func From(conn net.Conn) string {
	for depth := 0; conn != nil && depth < 16; depth++ {
		if value, ok := conn.(carrier); ok {
			if id := value.ConnectionID(); id != "" {
				return id
			}
		}
		value, ok := conn.(unwrapper)
		if !ok {
			return ""
		}
		next := value.UnwrapConn()
		if next == conn {
			return ""
		}
		conn = next
	}
	return ""
}
