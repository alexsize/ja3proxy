package dns

import (
	"encoding/binary"
	"errors"
	"net/netip"
)

const maxPacketExtensionHeaders = 16

var ErrNotDNSPacket = errors.New("packet is not an unfragmented UDP DNS message")

// UDPPacket describes a DNS datagram without retaining its packet bytes.
type UDPPacket struct {
	Source      netip.AddrPort
	Destination netip.AddrPort
	Client      netip.Addr
	FlowID      string
	Payload     []byte
}

// ParseUDPPacket extracts DNS payloads from complete IPv4/IPv6 UDP packets.
// IP fragments are rejected; callers must not feed partial datagrams to the
// DNS parser or correlator.
func ParseUDPPacket(packet []byte) (UDPPacket, error) {
	if len(packet) == 0 {
		return UDPPacket{}, ErrNotDNSPacket
	}
	switch packet[0] >> 4 {
	case 4:
		return parseDNSIPv4(packet)
	case 6:
		return parseDNSIPv6(packet)
	default:
		return UDPPacket{}, ErrNotDNSPacket
	}
}

func parseDNSIPv4(packet []byte) (UDPPacket, error) {
	if len(packet) < 20 {
		return UDPPacket{}, ErrMalformedMessage
	}
	headerLen := int(packet[0]&0x0f) * 4
	totalLen := int(binary.BigEndian.Uint16(packet[2:4]))
	fragment := binary.BigEndian.Uint16(packet[6:8])
	if headerLen < 20 || headerLen > len(packet) || totalLen < headerLen || totalLen > len(packet) {
		return UDPPacket{}, ErrMalformedMessage
	}
	if fragment&0x3fff != 0 || packet[9] != 17 {
		return UDPPacket{}, ErrNotDNSPacket
	}
	return parseDNSUDP(packet[headerLen:totalLen], netip.AddrFrom4([4]byte(packet[12:16])), netip.AddrFrom4([4]byte(packet[16:20])))
}

func parseDNSIPv6(packet []byte) (UDPPacket, error) {
	if len(packet) < 40 {
		return UDPPacket{}, ErrMalformedMessage
	}
	payloadLen := int(binary.BigEndian.Uint16(packet[4:6]))
	end := 40 + payloadLen
	if payloadLen == 0 || end > len(packet) {
		return UDPPacket{}, ErrMalformedMessage
	}
	next, offset := packet[6], 40
	for count := 0; isDNSIPv6Extension(next); count++ {
		if count >= maxPacketExtensionHeaders || offset+2 > end {
			return UDPPacket{}, ErrMalformedMessage
		}
		headerType := next
		next = packet[offset]
		if headerType == 44 { // Fragmented datagrams require reassembly.
			return UDPPacket{}, ErrNotDNSPacket
		}
		length := (int(packet[offset+1]) + 1) * 8
		if headerType == 51 { // Authentication Header.
			length = (int(packet[offset+1]) + 2) * 4
		}
		if length < 8 || offset+length > end {
			return UDPPacket{}, ErrMalformedMessage
		}
		offset += length
	}
	if next != 17 {
		return UDPPacket{}, ErrNotDNSPacket
	}
	var source, destination [16]byte
	copy(source[:], packet[8:24])
	copy(destination[:], packet[24:40])
	return parseDNSUDP(packet[offset:end], netip.AddrFrom16(source), netip.AddrFrom16(destination))
}

func isDNSIPv6Extension(next byte) bool {
	switch next {
	case 0, 43, 44, 51, 60, 135, 139, 140:
		return true
	default:
		return false
	}
}

func parseDNSUDP(segment []byte, source, destination netip.Addr) (UDPPacket, error) {
	if len(segment) < 8 {
		return UDPPacket{}, ErrMalformedMessage
	}
	sourcePort, destinationPort := binary.BigEndian.Uint16(segment[:2]), binary.BigEndian.Uint16(segment[2:4])
	if sourcePort != 53 && destinationPort != 53 {
		return UDPPacket{}, ErrNotDNSPacket
	}
	length := int(binary.BigEndian.Uint16(segment[4:6]))
	if length < 8 || length > len(segment) {
		return UDPPacket{}, ErrMalformedMessage
	}
	sourceAddr := netip.AddrPortFrom(source, sourcePort)
	destinationAddr := netip.AddrPortFrom(destination, destinationPort)
	first, second := sourceAddr, destinationAddr
	if second.String() < first.String() {
		first, second = second, first
	}
	client := source
	if sourcePort == 53 {
		client = destination
	}
	return UDPPacket{
		Source: sourceAddr, Destination: destinationAddr, Client: client,
		FlowID: first.String() + "|" + second.String(), Payload: segment[8:length],
	}, nil
}
