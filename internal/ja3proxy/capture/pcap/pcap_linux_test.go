//go:build linux

package pcap

import (
	"syscall"
	"testing"
)

func TestLinuxPacketLinkTypeFollowsHardwareHeader(t *testing.T) {
	for _, test := range []struct {
		name   string
		typeID uint16
		want   int
	}{
		{name: "ethernet", typeID: 1, want: 1},
		{name: "loopback", typeID: 772, want: 101},
		{name: "no-link-header", typeID: 65534, want: 101},
	} {
		t.Run(test.name, func(t *testing.T) {
			got := linkTypeForHardware(&syscall.SockaddrLinklayer{Hatype: test.typeID})
			if got != test.want {
				t.Fatalf("linkTypeForHardware(%d) = %d, want %d", test.typeID, got, test.want)
			}
		})
	}
}
