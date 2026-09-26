package dns

import (
	"encoding/binary"
	"errors"
	"net/netip"
)

var ErrNotDNSTCPPacket = errors.New("packet is not a DNS-over-TCP segment")

type TCPSegment struct {
	Source      netip.AddrPort
	Destination netip.AddrPort
	Client      netip.Addr
	FlowID      string
	Direction   string
	Sequence    uint32
	SYN         bool
	FIN         bool
	RST         bool
	Payload     []byte
}

// ParseTCPPacket extracts TCP segments belonging to DNS port 53 connections.
// Callers should first pass IP fragments through the packet reassembler.
func ParseTCPPacket(packet []byte) (TCPSegment, error) {
	if len(packet) == 0 {
		return TCPSegment{}, ErrNotDNSTCPPacket
	}
	switch packet[0] >> 4 {
	case 4:
		if len(packet) < 20 {
			return TCPSegment{}, ErrMalformedMessage
		}
		headerLength := int(packet[0]&0x0f) * 4
		totalLength := int(binary.BigEndian.Uint16(packet[2:4]))
		if headerLength < 20 || headerLength > len(packet) || totalLength < headerLength || totalLength > len(packet) {
			return TCPSegment{}, ErrMalformedMessage
		}
		if packet[6]&0x3f != 0 || packet[7] != 0 || packet[9] != 6 {
			return TCPSegment{}, ErrNotDNSTCPPacket
		}
		return parseDNSIPTCP(packet[headerLength:totalLength], netip.AddrFrom4([4]byte(packet[12:16])), netip.AddrFrom4([4]byte(packet[16:20])))
	case 6:
		if len(packet) < 40 {
			return TCPSegment{}, ErrMalformedMessage
		}
		payloadLength := int(binary.BigEndian.Uint16(packet[4:6]))
		end := 40 + payloadLength
		if payloadLength == 0 || end > len(packet) {
			return TCPSegment{}, ErrMalformedMessage
		}
		next, offset := packet[6], 40
		for count := 0; isDNSIPv6Extension(next); count++ {
			if count >= maxPacketExtensionHeaders || offset+2 > end || next == 44 {
				return TCPSegment{}, ErrNotDNSTCPPacket
			}
			headerType := next
			next = packet[offset]
			length := (int(packet[offset+1]) + 1) * 8
			if headerType == 51 {
				length = (int(packet[offset+1]) + 2) * 4
			}
			if length < 8 || offset+length > end {
				return TCPSegment{}, ErrMalformedMessage
			}
			offset += length
		}
		if next != 6 {
			return TCPSegment{}, ErrNotDNSTCPPacket
		}
		var source, destination [16]byte
		copy(source[:], packet[8:24])
		copy(destination[:], packet[24:40])
		return parseDNSIPTCP(packet[offset:end], netip.AddrFrom16(source), netip.AddrFrom16(destination))
	default:
		return TCPSegment{}, ErrNotDNSTCPPacket
	}
}

func parseDNSIPTCP(segment []byte, source, destination netip.Addr) (TCPSegment, error) {
	if len(segment) < 20 {
		return TCPSegment{}, ErrMalformedMessage
	}
	sourcePort, destinationPort := binary.BigEndian.Uint16(segment[:2]), binary.BigEndian.Uint16(segment[2:4])
	if sourcePort != 53 && destinationPort != 53 {
		return TCPSegment{}, ErrNotDNSTCPPacket
	}
	headerLength := int(segment[12]>>4) * 4
	if headerLength < 20 || headerLength > len(segment) {
		return TCPSegment{}, ErrMalformedMessage
	}
	client, direction := source, "client"
	if sourcePort == 53 {
		client, direction = destination, "server"
	}
	sourceAddr, destinationAddr := netip.AddrPortFrom(source, sourcePort), netip.AddrPortFrom(destination, destinationPort)
	first, second := sourceAddr, destinationAddr
	if second.String() < first.String() {
		first, second = second, first
	}
	flags := segment[13]
	return TCPSegment{
		Source: sourceAddr, Destination: destinationAddr, Client: client,
		FlowID: first.String() + "|" + second.String(), Direction: direction,
		Sequence: binary.BigEndian.Uint32(segment[4:8]),
		SYN:      flags&0x02 != 0, FIN: flags&0x01 != 0, RST: flags&0x04 != 0,
		Payload: segment[headerLength:],
	}, nil
}
