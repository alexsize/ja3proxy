package flowid

import (
	"net"
	"testing"
	"time"

	"github.com/lylemi/ja3proxy/internal/ja3proxy/capture/tlshello"
)

type testWrapper struct{ net.Conn }

func (conn *testWrapper) UnwrapConn() net.Conn { return conn.Conn }

func TestWrapAssignsOneStableIDThroughWrappers(t *testing.T) {
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()

	identified := Wrap(left)
	id := From(identified)
	if len(id) != 26 || id[0] > '7' {
		t.Fatalf("connection ID = %q, want ULID", id)
	}
	if got := From(&testWrapper{Conn: identified}); got != id {
		t.Fatalf("wrapped connection ID = %q, want %q", got, id)
	}
	if got := Wrap(identified); got != identified {
		t.Fatal("Wrap replaced an already identified connection")
	}
}

func TestProxyUsernameSurvivesTransparentWrappers(t *testing.T) {
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()

	identified := Wrap(left)
	withUsername := WithProxyUsername(identified, "device-user")
	if got := ProxyUsernameFrom(withUsername); got != "device-user" {
		t.Fatalf("proxy username = %q, want device-user", got)
	}
	if got := ProxyUsernameFrom(&testWrapper{Conn: withUsername}); got != "device-user" {
		t.Fatalf("wrapped proxy username = %q, want device-user", got)
	}
	if got := WithProxyUsername(withUsername, "other"); got != withUsername {
		t.Fatal("replaced existing proxy username")
	}
}

func TestIdentitySurvivesTLSHelloReplayWrapper(t *testing.T) {
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()

	identified := WithProxyUsername(Wrap(left), "device-user")
	go func() { _, _ = right.Write([]byte("x")) }()
	replayed, _, err := tlshello.Sniff(identified, time.Second, tlshello.DefaultLimits())
	if err != nil {
		t.Fatalf("Sniff() error = %v", err)
	}
	if got := From(replayed); got != From(identified) {
		t.Fatalf("replayed connection ID = %q, want %q", got, From(identified))
	}
	if got := ProxyUsernameFrom(replayed); got != "device-user" {
		t.Fatalf("replayed proxy username = %q, want device-user", got)
	}
}
