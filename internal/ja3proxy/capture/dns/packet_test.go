package dns

import (
	"encoding/binary"
	"net/netip"
	"testing"
)

func TestParseDNSIPv4UDPPacketsAndBidirectionalFlow(t *testing.T) {
	query := []byte{0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0,
		7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, 0, 1, 0, 1}
	request := makeIPv4UDP([4]byte{192, 0, 2, 10}, [4]byte{192, 0, 2, 53}, 53000, 53, query)
	response := makeIPv4UDP([4]byte{192, 0, 2, 53}, [4]byte{192, 0, 2, 10}, 53, 53000, query)

	gotRequest, err := ParseUDPPacket(request)
	if err != nil {
		t.Fatal(err)
	}
	gotResponse, err := ParseUDPPacket(response)
	if err != nil {
		t.Fatal(err)
	}
	if gotRequest.FlowID != gotResponse.FlowID || gotRequest.Client != netip.MustParseAddr("192.0.2.10") || gotResponse.Client != gotRequest.Client {
		t.Fatalf("request/response flow mismatch: %#v / %#v", gotRequest, gotResponse)
	}
	if string(gotRequest.Payload) != string(query) || string(gotResponse.Payload) != string(query) {
		t.Fatal("DNS payload boundaries were not preserved")
	}
}

func TestParseDNSIPv6UDPAndRejectFragment(t *testing.T) {
	query := []byte{0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1}
	packet := make([]byte, 40+8+len(query))
	packet[0] = 0x60
	binary.BigEndian.PutUint16(packet[4:6], uint16(8+len(query)))
	packet[6], packet[7] = 17, 64
	copy(packet[8:24], netip.MustParseAddr("2001:db8::10").AsSlice())
	copy(packet[24:40], netip.MustParseAddr("2001:db8::53").AsSlice())
	binary.BigEndian.PutUint16(packet[40:42], 53000)
	binary.BigEndian.PutUint16(packet[42:44], 53)
	binary.BigEndian.PutUint16(packet[44:46], uint16(8+len(query)))
	copy(packet[48:], query)
	parsed, err := ParseUDPPacket(packet)
	if err != nil || parsed.Client != netip.MustParseAddr("2001:db8::10") {
		t.Fatalf("ParseUDPPacket() = %#v, %v", parsed, err)
	}

	packet[6] = 44
	if _, err := ParseUDPPacket(packet); err == nil {
		t.Fatal("fragmented IPv6 packet was accepted")
	}
}

func TestParseUDPRejectsMalformedLengthsAndNonDNS(t *testing.T) {
	packet := makeIPv4UDP([4]byte{192, 0, 2, 1}, [4]byte{192, 0, 2, 2}, 53000, 53, make([]byte, 12))
	binary.BigEndian.PutUint16(packet[24:26], 7)
	if _, err := ParseUDPPacket(packet); err == nil {
		t.Fatal("invalid UDP length was accepted")
	}
	packet = makeIPv4UDP([4]byte{192, 0, 2, 1}, [4]byte{192, 0, 2, 2}, 53000, 5353, make([]byte, 12))
	if _, err := ParseUDPPacket(packet); err == nil {
		t.Fatal("non-DNS UDP packet was accepted")
	}
}

func makeIPv4UDP(source, destination [4]byte, sourcePort, destinationPort uint16, payload []byte) []byte {
	packet := make([]byte, 20+8+len(payload))
	packet[0] = 0x45
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	packet[8], packet[9] = 64, 17
	copy(packet[12:16], source[:])
	copy(packet[16:20], destination[:])
	binary.BigEndian.PutUint16(packet[20:22], sourcePort)
	binary.BigEndian.PutUint16(packet[22:24], destinationPort)
	binary.BigEndian.PutUint16(packet[24:26], uint16(8+len(payload)))
	copy(packet[28:], payload)
	return packet
}
