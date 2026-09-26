package live

import (
	"context"
	"encoding/binary"
	"io"
	"net/netip"
	"testing"
	"time"

	"github.com/lylemi/ja3proxy/internal/ja3proxy/capture/pcap"
	tcpcapture "github.com/lylemi/ja3proxy/internal/ja3proxy/capture/tcp"
	"github.com/lylemi/ja3proxy/internal/ja3proxy/recorder"
)

func TestTCPMetaDescribesInitiatingSYN(t *testing.T) {
	meta := tcpMeta(&tcpcapture.SYN{
		Source: netip.MustParseAddr("192.0.2.5"), Destination: netip.MustParseAddr("2001:db8::1"),
		SourcePort: 53000, DestPort: 443,
	})
	if meta.CapturePoint != "CLIENT_TCP_SYN" || meta.HandshakeEvent != "TCP_SYN" || meta.IdentityValue != "192.0.2.5" || meta.Destination != "[2001:db8::1]:443" || meta.DestinationPort != 443 {
		t.Fatalf("passive SYN metadata = %+v", meta)
	}
	if meta.ConnectionID == "" || meta.Mode != "PASSIVE" {
		t.Fatalf("passive flow identity = %+v", meta)
	}
}

func TestRunTCPRecordsCorrelatedLiveDNSUDP(t *testing.T) {
	query := []byte{0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0,
		7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, 0, 1, 0, 1}
	response := append([]byte(nil), query...)
	response[2] = 0x81
	response[3] = 0x80
	requestIP := makeIPUDP([4]byte{192, 0, 2, 10}, [4]byte{192, 0, 2, 53}, 53000, 53, query)
	responseIP := makeIPUDP([4]byte{192, 0, 2, 53}, [4]byte{192, 0, 2, 10}, 53, 53000, response)
	stamp := time.Date(2026, 9, 25, 12, 0, 0, 0, time.UTC)
	input := &packetSource{packets: []pcap.Packet{
		{Timestamp: stamp, LinkType: 101, Data: makeIPv4Fragment(requestIP, 0, 16, true)},
		{Timestamp: stamp.Add(5 * time.Millisecond), LinkType: 101, Data: makeIPv4Fragment(responseIP, 0, 16, true)},
		{Timestamp: stamp.Add(10 * time.Millisecond), LinkType: 101, Data: makeIPv4Fragment(requestIP, 16, len(requestIP)-20-16, false)},
		{Timestamp: stamp.Add(25 * time.Millisecond), LinkType: 101, Data: makeIPv4Fragment(responseIP, 16, len(responseIP)-20-16, false)},
	}}
	output, err := recorder.New(recorder.Options{Raw: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := RunTCP(context.Background(), input, output); err != io.EOF {
		t.Fatalf("RunTCP() error = %v, want EOF", err)
	}
	if got := output.Stats().Accepted; got != 1 {
		t.Fatalf("accepted observations = %d, want one DNS exchange", got)
	}
	if err := output.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestRunTCPRecordsDNSOverTCPAcrossSegments(t *testing.T) {
	query := []byte{0x45, 0x67, 0x01, 0, 0, 1, 0, 0, 0, 0, 0, 0,
		7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, 0, 1, 0, 1}
	response := append([]byte(nil), query...)
	response[2] = 0x81
	response[3] = 0x80
	queryFrame, responseFrame := dnsTCPFrame(query), dnsTCPFrame(response)
	client, server := [4]byte{192, 0, 2, 10}, [4]byte{192, 0, 2, 53}
	stamp := time.Date(2026, 9, 25, 12, 30, 0, 0, time.UTC)
	input := &packetSource{packets: []pcap.Packet{
		{Timestamp: stamp, LinkType: 101, Data: makeIPTCP(client, server, 53000, 53, 100, 0x02, nil)},
		{Timestamp: stamp.Add(time.Millisecond), LinkType: 101, Data: makeIPTCP(server, client, 53, 53000, 300, 0x12, nil)},
		{Timestamp: stamp.Add(2 * time.Millisecond), LinkType: 101, Data: makeIPTCP(client, server, 53000, 53, 101, 0x10, nil)},
		{Timestamp: stamp.Add(3 * time.Millisecond), LinkType: 101, Data: makeIPTCP(client, server, 53000, 53, 117, 0x18, queryFrame[16:])},
		{Timestamp: stamp.Add(4 * time.Millisecond), LinkType: 101, Data: makeIPTCP(client, server, 53000, 53, 101, 0x18, queryFrame[:16])},
		{Timestamp: stamp.Add(5 * time.Millisecond), LinkType: 101, Data: makeIPTCP(server, client, 53, 53000, 301, 0x18, responseFrame)},
	}}
	output, err := recorder.New(recorder.Options{Raw: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := RunTCP(context.Background(), input, output); err != io.EOF {
		t.Fatalf("RunTCP() error = %v, want EOF", err)
	}
	if got := output.Stats().Accepted; got != 2 {
		t.Fatalf("accepted observations = %d, want SYN and DNS exchange", got)
	}
	if err := output.Close(); err != nil {
		t.Fatal(err)
	}
}

type packetSource struct {
	packets []pcap.Packet
}

func (source *packetSource) ReadPacket(context.Context) (pcap.Packet, error) {
	if len(source.packets) == 0 {
		return pcap.Packet{}, io.EOF
	}
	packet := source.packets[0]
	source.packets = source.packets[1:]
	return packet, nil
}

func (*packetSource) Close() error { return nil }

func makeIPUDP(source, destination [4]byte, sourcePort, destinationPort uint16, payload []byte) []byte {
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

func makeIPv4Fragment(packet []byte, offset, length int, more bool) []byte {
	fragment := append([]byte(nil), packet[:20]...)
	fragment = append(fragment, packet[20+offset:20+offset+length]...)
	binary.BigEndian.PutUint16(fragment[2:4], uint16(len(fragment)))
	field := uint16(offset / 8)
	if more {
		field |= 0x2000
	}
	binary.BigEndian.PutUint16(fragment[6:8], field)
	return fragment
}

func makeIPTCP(source, destination [4]byte, sourcePort, destinationPort uint16, sequence uint32, flags byte, payload []byte) []byte {
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

func dnsTCPFrame(message []byte) []byte {
	frame := make([]byte, 2+len(message))
	binary.BigEndian.PutUint16(frame, uint16(len(message)))
	copy(frame[2:], message)
	return frame
}
