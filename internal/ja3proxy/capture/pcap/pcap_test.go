package pcap

import (
	"errors"
	"testing"
)

func TestIPPayloadEthernetVLANAndRaw(t *testing.T) {
	ipv4 := []byte{0x45, 0, 0, 20}
	ethernet := make([]byte, 14+len(ipv4))
	ethernet[12], ethernet[13] = 0x08, 0x00
	copy(ethernet[14:], ipv4)
	got, err := (Packet{LinkType: 1, Data: ethernet}).IPPayload()
	if err != nil || len(got) != len(ipv4) || got[0]>>4 != 4 {
		t.Fatalf("Ethernet IPv4 = %x, error = %v", got, err)
	}
	vlan := make([]byte, 18+len(ipv4))
	vlan[12], vlan[13] = 0x81, 0x00
	vlan[16], vlan[17] = 0x08, 0x00
	copy(vlan[18:], ipv4)
	got, err = (Packet{LinkType: 1, Data: vlan}).IPPayload()
	if err != nil || len(got) != len(ipv4) {
		t.Fatalf("VLAN IPv4 = %x, error = %v", got, err)
	}
	got, err = (Packet{LinkType: 101, Data: ipv4}).IPPayload()
	if err != nil || len(got) != len(ipv4) {
		t.Fatalf("raw IPv4 = %x, error = %v", got, err)
	}
}

func TestIPPayloadRejectsMalformedAndUnsupportedFrames(t *testing.T) {
	if _, err := (Packet{LinkType: 1, Data: []byte{1}}).IPPayload(); !errors.Is(err, ErrMalformedFrame) {
		t.Fatalf("short Ethernet error = %v", err)
	}
	frame := make([]byte, 14)
	frame[12], frame[13] = 0x08, 0x06 // ARP.
	if _, err := (Packet{LinkType: 1, Data: frame}).IPPayload(); !errors.Is(err, ErrUnsupportedLinkType) {
		t.Fatalf("ARP error = %v", err)
	}
	if _, err := (Packet{LinkType: 999, Data: frame}).IPPayload(); !errors.Is(err, ErrUnsupportedLinkType) {
		t.Fatalf("link type error = %v", err)
	}
}
