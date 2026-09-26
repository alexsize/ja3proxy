package dns

import (
	"encoding/binary"
	"errors"
	"math"
	"net/netip"
	"testing"
	"time"
)

func TestTCPStreamAssemblerReordersSegmentsAndExtractsMultipleFrames(t *testing.T) {
	message := []byte{0x12, 0x34, 0x01, 0, 0, 1, 0, 0, 0, 0, 0, 0,
		7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, 0, 1, 0, 1}
	frame := make([]byte, 2+len(message))
	binary.BigEndian.PutUint16(frame, uint16(len(message)))
	copy(frame[2:], message)
	combined := append(append([]byte(nil), frame...), frame...)
	at := time.Now().UTC()
	assembler := NewTCPStreamAssembler(TCPStreamConfig{})
	flow := "192.0.2.10:53000|192.0.2.53:53"
	if got, err := assembler.Push(tcpSegmentEvent(flow, "client", 100, true, nil), at); err != nil || len(got) != 0 {
		t.Fatalf("SYN frames=%d error=%v", len(got), err)
	}
	if got, err := assembler.Push(tcpSegmentEvent(flow, "client", 101+16, false, combined[16:]), at.Add(time.Millisecond)); err != nil || len(got) != 0 {
		t.Fatalf("out-of-order segment frames=%d error=%v", len(got), err)
	}
	if got, err := assembler.Push(tcpSegmentEvent(flow, "client", 101, false, combined[:8]), at.Add(2*time.Millisecond)); err != nil || len(got) != 0 {
		t.Fatalf("first segment frames=%d error=%v", len(got), err)
	}
	got, err := assembler.Push(tcpSegmentEvent(flow, "client", 109, false, combined[8:16]), at.Add(3*time.Millisecond))
	if err != nil || len(got) != 2 {
		t.Fatalf("assembled frames=%d error=%v", len(got), err)
	}
	for _, framed := range got {
		if string(framed) != string(frame) {
			t.Fatalf("frame = %x, want %x", framed, frame)
		}
		if _, err := ParseTCPFrame(framed); err != nil {
			t.Fatalf("reassembled DNS frame rejected: %v", err)
		}
	}
	if assembler.bytes != 0 {
		t.Fatalf("buffered bytes after complete frames = %d", assembler.bytes)
	}
}

func TestTCPStreamAssemblerHandlesWraparoundAndRetransmission(t *testing.T) {
	frame := []byte{0, 12, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	at := time.Now().UTC()
	assembler := NewTCPStreamAssembler(TCPStreamConfig{})
	flow := "a:53000|b:53"
	start := uint32(math.MaxUint32 - 5)
	_, _ = assembler.Push(tcpSegmentEvent(flow, "client", start, true, nil), at)
	part := append([]byte(nil), frame[:6]...)
	got, err := assembler.Push(tcpSegmentEvent(flow, "client", start+1, false, part), at.Add(time.Millisecond))
	if err != nil || len(got) != 0 {
		t.Fatalf("first fragment frames=%d error=%v", len(got), err)
	}
	_, err = assembler.Push(tcpSegmentEvent(flow, "client", start+1, false, part), at.Add(2*time.Millisecond))
	if err != nil {
		t.Fatalf("retransmission error=%v", err)
	}
	got, err = assembler.Push(tcpSegmentEvent(flow, "client", start+7, false, frame[6:]), at.Add(3*time.Millisecond))
	if err != nil || len(got) != 1 || string(got[0]) != string(frame) {
		t.Fatalf("wrapped frame=%x error=%v", got, err)
	}
}

func TestTCPStreamAssemblerChecksPendingOverlapAndReleasesConsumedChunk(t *testing.T) {
	message := dnsQuery(42, "overlap.example", 1)
	frame := make([]byte, len(message)+2)
	binary.BigEndian.PutUint16(frame[:2], uint16(len(message)))
	copy(frame[2:], message)
	at := time.Now().UTC()
	flow := "a:53000|b:53"
	for _, conflicting := range []bool{false, true} {
		assembler := NewTCPStreamAssembler(TCPStreamConfig{})
		_, _ = assembler.Push(tcpSegmentEvent(flow, "client", 100, true, nil), at)
		pending := append([]byte(nil), frame[6:10]...)
		if conflicting {
			pending[0] ^= 0xff
		}
		if _, err := assembler.Push(tcpSegmentEvent(flow, "client", 107, false, pending), at); err != nil {
			t.Fatal(err)
		}
		got, err := assembler.Push(tcpSegmentEvent(flow, "client", 101, false, frame), at.Add(time.Millisecond))
		if conflicting {
			if !errors.Is(err, ErrTCPSequence) || assembler.bytes != 0 {
				t.Fatalf("conflicting overlap: frames=%d error=%v buffered=%d", len(got), err, assembler.bytes)
			}
			continue
		}
		if err != nil || len(got) != 1 || string(got[0]) != string(frame) || assembler.bytes != 0 {
			t.Fatalf("matching overlap: frames=%d error=%v buffered=%d", len(got), err, assembler.bytes)
		}
	}
}

func TestTCPStreamAssemblerRejectsBadLengthAndBoundsMemory(t *testing.T) {
	at := time.Now().UTC()
	assembler := NewTCPStreamAssembler(TCPStreamConfig{MaxBufferedBytes: 8})
	flow := "a:53000|b:53"
	_, _ = assembler.Push(tcpSegmentEvent(flow, "client", 500, true, nil), at)
	if _, err := assembler.Push(tcpSegmentEvent(flow, "client", 501, false, make([]byte, 9)), at.Add(time.Millisecond)); !errors.Is(err, ErrTCPStreamLimit) {
		t.Fatalf("buffer limit error = %v", err)
	}

	assembler = NewTCPStreamAssembler(TCPStreamConfig{})
	_, _ = assembler.Push(tcpSegmentEvent(flow, "client", 900, true, nil), at)
	if _, err := assembler.Push(tcpSegmentEvent(flow, "client", 901, false, []byte{0, 11}), at.Add(time.Millisecond)); !errors.Is(err, ErrMalformedMessage) {
		t.Fatalf("malformed frame length error = %v", err)
	}
}

func TestTCPStreamAssemblerResynchronizesAfterMidstreamCapture(t *testing.T) {
	message := dnsQuery(91, "resync.example", 1)
	frame := make([]byte, len(message)+2)
	binary.BigEndian.PutUint16(frame[:2], uint16(len(message)))
	copy(frame[2:], message)
	at := time.Now().UTC()
	assembler := NewTCPStreamAssembler(TCPStreamConfig{})
	flow := "a:53000|b:53"
	// The initial payload starts in the middle of an unrelated DNS frame.
	prefix := []byte{0xff, 0x73, 0x01, 0x02, 0x03}
	got, err := assembler.Push(tcpSegmentEvent(flow, "client", 1000, false, append(prefix, frame[:8]...)), at)
	if err != nil || len(got) != 0 {
		t.Fatalf("midstream prefix frames=%d error=%v", len(got), err)
	}
	got, err = assembler.Push(tcpSegmentEvent(flow, "client", 1000+uint32(len(prefix)+8), false, frame[8:]), at.Add(time.Millisecond))
	if err != nil || len(got) != 1 || string(got[0]) != string(frame) {
		t.Fatalf("resynchronized frames=%d error=%v", len(got), err)
	}
	if assembler.bytes != 0 {
		t.Fatalf("buffered bytes after resynchronization = %d", assembler.bytes)
	}
}

func tcpSegmentEvent(flow, direction string, sequence uint32, syn bool, payload []byte) TCPSegment {
	return TCPSegment{FlowID: flow, Client: netip.MustParseAddr("192.0.2.10"), Direction: direction, Sequence: sequence, SYN: syn, Payload: payload}
}

func TestParseDNSTCPPacket(t *testing.T) {
	request := makeIPv4TCPDNS([4]byte{192, 0, 2, 10}, [4]byte{192, 0, 2, 53}, 53000, 53, 1234, 0x02, []byte{0, 12, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0})
	response := makeIPv4TCPDNS([4]byte{192, 0, 2, 53}, [4]byte{192, 0, 2, 10}, 53, 53000, 4321, 0x18, nil)
	gotRequest, err := ParseTCPPacket(request)
	if err != nil {
		t.Fatal(err)
	}
	gotResponse, err := ParseTCPPacket(response)
	if err != nil {
		t.Fatal(err)
	}
	if gotRequest.FlowID != gotResponse.FlowID || gotRequest.Direction != "client" || gotResponse.Direction != "server" || gotRequest.Client != netip.MustParseAddr("192.0.2.10") || gotRequest.Sequence != 1234 || len(gotRequest.Payload) != 14 {
		t.Fatalf("parsed TCP DNS segments = %#v / %#v", gotRequest, gotResponse)
	}
}

func makeIPv4TCPDNS(source, destination [4]byte, sourcePort, destinationPort uint16, sequence uint32, flags byte, payload []byte) []byte {
	packet := make([]byte, 40+len(payload))
	packet[0] = 0x45
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	packet[8], packet[9] = 64, 6
	copy(packet[12:16], source[:])
	copy(packet[16:20], destination[:])
	binary.BigEndian.PutUint16(packet[20:22], sourcePort)
	binary.BigEndian.PutUint16(packet[22:24], destinationPort)
	binary.BigEndian.PutUint32(packet[24:28], sequence)
	packet[32], packet[33] = 0x50, flags
	copy(packet[40:], payload)
	return packet
}
