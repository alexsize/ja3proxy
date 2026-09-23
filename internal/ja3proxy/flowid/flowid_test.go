package flowid

import (
	"net"
	"testing"
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
