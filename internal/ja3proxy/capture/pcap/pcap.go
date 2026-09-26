// Package pcap provides a small live-capture adapter over the host packet
// capture library. Protocol parsing remains in capture/tcp and capture/dns.
package pcap

import (
	"context"
	"errors"
	"time"
)

const (
	defaultSnapLength = 65535
	maxPacketLength   = 1 << 20
)

var ErrUnsupported = errors.New("live packet capture is not supported on this platform")

var ErrUnsupportedLinkType = errors.New("unsupported packet capture link type")

var ErrMalformedFrame = errors.New("malformed captured frame")

type Device struct {
	Name        string
	Description string
}

type Packet struct {
	Timestamp time.Time
	LinkType  int
	Data      []byte
}

type Source interface {
	ReadPacket(context.Context) (Packet, error)
	Close() error
}

// IPPayload extracts the network-layer packet from common Ethernet and raw-IP
// captures. It handles up to two VLAN tags and returns IP bytes without copying.
func (packet Packet) IPPayload() ([]byte, error) {
	data := packet.Data
	switch packet.LinkType {
	case 1: // DLT_EN10MB (Ethernet).
		if len(data) < 14 {
			return nil, ErrMalformedFrame
		}
		etherType, offset := uint16(data[12])<<8|uint16(data[13]), 14
		for tags := 0; etherType == 0x8100 || etherType == 0x88a8 || etherType == 0x9100; tags++ {
			if tags >= 2 || len(data) < offset+4 {
				return nil, ErrMalformedFrame
			}
			etherType = uint16(data[offset+2])<<8 | uint16(data[offset+3])
			offset += 4
		}
		if etherType != 0x0800 && etherType != 0x86dd {
			return nil, ErrUnsupportedLinkType
		}
		if len(data) <= offset || data[offset]>>4 != 4 && data[offset]>>4 != 6 {
			return nil, ErrMalformedFrame
		}
		return data[offset:], nil
	case 12, 101, 228, 229: // DLT_RAW / DLT_RAW_ALT / IPv4 / IPv6.
		if len(data) == 0 || data[0]>>4 != 4 && data[0]>>4 != 6 {
			return nil, ErrMalformedFrame
		}
		return data, nil
	default:
		return nil, ErrUnsupportedLinkType
	}
}
