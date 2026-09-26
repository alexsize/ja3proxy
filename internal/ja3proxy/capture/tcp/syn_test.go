package tcp

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"net/netip"
	"testing"
)

func tcpSegment(flags byte, options []byte) []byte {
	segment := make([]byte, 20+len(options))
	binary.BigEndian.PutUint16(segment[0:2], 54321)
	binary.BigEndian.PutUint16(segment[2:4], 443)
	segment[12] = byte(len(segment)/4) << 4
	segment[13] = flags
	binary.BigEndian.PutUint16(segment[14:16], 64240)
	copy(segment[20:], options)
	return segment
}

func ipv4Packet(segment []byte, protocol byte, fragment uint16) []byte {
	packet := make([]byte, 20+len(segment))
	packet[0] = 0x45
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	binary.BigEndian.PutUint16(packet[6:8], fragment)
	packet[9] = protocol
	copy(packet[12:16], []byte{192, 0, 2, 10})
	copy(packet[16:20], []byte{198, 51, 100, 20})
	copy(packet[20:], segment)
	return packet
}

func ipv6Packet(segment []byte, next byte) []byte {
	packet := make([]byte, 40+len(segment))
	packet[0] = 0x60
	binary.BigEndian.PutUint16(packet[4:6], uint16(len(segment)))
	packet[6] = next
	copy(packet[8:24], netip.MustParseAddr("2001:db8::10").AsSlice())
	copy(packet[24:40], netip.MustParseAddr("2001:db8::20").AsSlice())
	copy(packet[40:], segment)
	return packet
}

func TestParseIPv4SYNOptionsAndPrivacy(t *testing.T) {
	options := []byte{2, 4, 0x05, 0xb4, 1, 3, 3, 7, 4, 2, 8, 10, 1, 2, 3, 4, 5, 6, 7, 8}
	packet := ipv4Packet(tcpSegment(0xc2, options), 6, 0)
	packet = append(packet, []byte("PRIVATE_TCP_SYN_PAYLOAD")...)
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	original := append([]byte(nil), packet...)
	got, err := ParsePacket(packet)
	if err != nil {
		t.Fatal(err)
	}
	if got == nil || got.IPVersion != 4 || got.Source.String() != "192.0.2.10" || got.Destination.String() != "198.51.100.20" || got.SourcePort != 54321 || got.DestPort != 443 || got.Window != 64240 {
		t.Fatalf("SYN metadata = %+v", got)
	}
	if got.MSS == nil || *got.MSS != 1460 || got.WindowScale == nil || *got.WindowScale != 7 || !got.SACKPermitted || !got.HasTimestamp {
		t.Fatalf("TCP option metadata = %+v", got)
	}
	if got.JA4T != "64240_2-1-3-4-8_1460_7" {
		t.Fatalf("JA4T = %q", got.JA4T)
	}
	if want := []uint8{2, 1, 3, 4, 8}; len(got.OptionKinds) != len(want) {
		t.Fatalf("option kinds = %v", got.OptionKinds)
	} else {
		for i := range want {
			if got.OptionKinds[i] != want[i] {
				t.Fatalf("option kinds = %v, want %v", got.OptionKinds, want)
			}
		}
	}
	if !bytes.Equal(packet, original) {
		t.Fatal("parser mutated the source packet")
	}
	encoded, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encoded, []byte("PRIVATE_TCP_SYN_PAYLOAD")) {
		t.Fatalf("packet payload leaked into metadata: %s", encoded)
	}
}

func TestJA4TFormattingForMissingAndDuplicateOptions(t *testing.T) {
	noOptions, err := ParsePacket(ipv4Packet(tcpSegment(0x02, nil), 6, 0))
	if err != nil || noOptions == nil || noOptions.JA4T != "64240_00_00_00" {
		t.Fatalf("empty-options JA4T = %+v, error = %v", noOptions, err)
	}
	options := []byte{2, 4, 0x05, 0xb4, 2, 4, 0x04, 0xd0, 3, 3, 5, 3, 3, 9, 1, 1}
	duplicate, err := ParsePacket(ipv4Packet(tcpSegment(0x02, options), 6, 0))
	if err != nil || duplicate == nil || duplicate.JA4T != "64240_2-2-3-3-1-1_1232_9" {
		t.Fatalf("duplicate-options JA4T = %+v, error = %v", duplicate, err)
	}
}

func TestParseIPv6WithDestinationOptions(t *testing.T) {
	segment := tcpSegment(0x02, []byte{2, 4, 0x05, 0xb4})
	packet := make([]byte, 40+8+len(segment))
	packet[0] = 0x60
	binary.BigEndian.PutUint16(packet[4:6], uint16(8+len(segment)))
	packet[6] = 60 // Destination Options.
	copy(packet[8:24], netip.MustParseAddr("2001:db8::10").AsSlice())
	copy(packet[24:40], netip.MustParseAddr("2001:db8::20").AsSlice())
	packet[40] = 6
	packet[41] = 0 // Extension header length = 8 bytes.
	copy(packet[48:], segment)
	got, err := ParsePacket(packet)
	if err != nil {
		t.Fatal(err)
	}
	if got == nil || got.IPVersion != 6 || got.Source.String() != "2001:db8::10" || got.Destination.String() != "2001:db8::20" || got.MSS == nil || *got.MSS != 1460 {
		t.Fatalf("IPv6 SYN metadata = %+v", got)
	}
}

func TestParsePacketRejectsFragmentsAndMalformedOptions(t *testing.T) {
	if _, err := ParsePacket(ipv4Packet(tcpSegment(2, nil), 6, 0x2000)); !errors.Is(err, ErrFragmented) {
		t.Fatalf("fragment error = %v", err)
	}
	if _, err := ParsePacket(ipv4Packet(tcpSegment(2, []byte{2, 1, 0, 0}), 6, 0)); !errors.Is(err, ErrMalformedPacket) {
		t.Fatalf("malformed TCP option error = %v", err)
	}
	if _, err := ParsePacket(ipv6Packet(tcpSegment(2, nil), 44)); !errors.Is(err, ErrFragmented) {
		t.Fatalf("IPv6 fragment error = %v", err)
	}
}

func TestParsePacketIgnoresNonInitialSYN(t *testing.T) {
	for _, flags := range []byte{0x10, 0x12} { // ACK and SYN-ACK.
		got, err := ParsePacket(ipv4Packet(tcpSegment(flags, nil), 6, 0))
		if err != nil || got != nil {
			t.Fatalf("flags %#x: metadata=%+v error=%v", flags, got, err)
		}
	}
}

func FuzzParsePacket(f *testing.F) {
	f.Add(ipv4Packet(tcpSegment(2, nil), 6, 0))
	f.Add(ipv6Packet(tcpSegment(0xc2, []byte{2, 4, 5, 180}), 6))
	f.Fuzz(func(t *testing.T, packet []byte) {
		_, _ = ParsePacket(packet)
	})
}
