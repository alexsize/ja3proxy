// Package tcp extracts descriptive metadata from supplied IPv4/IPv6 TCP packets.
// It does not open capture devices, retain packet payloads, or affect forwarding.
package tcp

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"strings"
)

const (
	NormalizationVersion    = "TCP-SYN-NORM-1"
	JA4TVersion             = "JA4T/1"
	maxIPv6ExtensionHeaders = 16
	flagSYN                 = 0x02
	flagACK                 = 0x10
)

var (
	ErrMalformedPacket = errors.New("malformed IP/TCP packet")
	ErrFragmented      = errors.New("fragmented IP packet is not analyzed")
)

// SYN contains only metadata from an initial TCP SYN. Packet payload and
// mutable TCP option values such as timestamp clocks are never retained.
type SYN struct {
	IPVersion     uint8      `json:"ip_version"`
	Source        netip.Addr `json:"source"`
	Destination   netip.Addr `json:"destination"`
	SourcePort    uint16     `json:"source_port"`
	DestPort      uint16     `json:"destination_port"`
	Window        uint16     `json:"window"`
	Flags         uint8      `json:"flags"`
	OptionKinds   []uint8    `json:"option_kinds"`
	MSS           *uint16    `json:"mss,omitempty"`
	WindowScale   *uint8     `json:"window_scale,omitempty"`
	SACKPermitted bool       `json:"sack_permitted"`
	HasTimestamp  bool       `json:"has_timestamp"`
	JA4T          string     `json:"ja4t"`
	JA4TVersion   string     `json:"ja4t_version"`
}

// ParsePacket analyzes one complete IP packet. It returns (nil, nil) for
// packets other than an initial SYN, and an error for malformed or fragmented
// packets that cannot be interpreted without reassembly.
func ParsePacket(packet []byte) (*SYN, error) {
	if len(packet) == 0 {
		return nil, ErrMalformedPacket
	}
	switch packet[0] >> 4 {
	case 4:
		return parseIPv4(packet)
	case 6:
		return parseIPv6(packet)
	default:
		return nil, ErrMalformedPacket
	}
}

func parseIPv4(packet []byte) (*SYN, error) {
	if len(packet) < 20 {
		return nil, ErrMalformedPacket
	}
	headerLen := int(packet[0]&0x0f) * 4
	totalLen := int(binary.BigEndian.Uint16(packet[2:4]))
	if headerLen < 20 || headerLen > len(packet) || totalLen < headerLen || totalLen > len(packet) {
		return nil, ErrMalformedPacket
	}
	fragment := binary.BigEndian.Uint16(packet[6:8])
	if fragment&0x3fff != 0 { // MF or nonzero fragment offset.
		return nil, ErrFragmented
	}
	if packet[9] != 6 {
		return nil, nil
	}
	return parseTCP(packet[headerLen:totalLen], 4,
		netip.AddrFrom4([4]byte(packet[12:16])), netip.AddrFrom4([4]byte(packet[16:20])))
}

func parseIPv6(packet []byte) (*SYN, error) {
	if len(packet) < 40 {
		return nil, ErrMalformedPacket
	}
	payloadLen := int(binary.BigEndian.Uint16(packet[4:6]))
	end := 40 + payloadLen
	if payloadLen == 0 || end > len(packet) { // Jumbograms are not supported.
		return nil, ErrMalformedPacket
	}
	next := packet[6]
	offset := 40
	for count := 0; isIPv6Extension(next); count++ {
		if count >= maxIPv6ExtensionHeaders || offset+2 > end {
			return nil, ErrMalformedPacket
		}
		headerType := next
		next = packet[offset]
		length := 0
		switch headerType {
		case 44: // Fragment header: this analyzer deliberately does not reassemble.
			return nil, ErrFragmented
		case 51: // Authentication Header length is in 32-bit words, minus 2.
			length = (int(packet[offset+1]) + 2) * 4
		default: // Hop-by-Hop, Routing, Destination, Mobility, HIP, Shim6.
			length = (int(packet[offset+1]) + 1) * 8
		}
		if length < 8 || offset+length > end {
			return nil, ErrMalformedPacket
		}
		offset += length
	}
	if next != 6 {
		return nil, nil
	}
	var source, destination [16]byte
	copy(source[:], packet[8:24])
	copy(destination[:], packet[24:40])
	return parseTCP(packet[offset:end], 6, netip.AddrFrom16(source), netip.AddrFrom16(destination))
}

func isIPv6Extension(next byte) bool {
	switch next {
	case 0, 43, 44, 51, 60, 135, 139, 140:
		return true
	default:
		return false
	}
}

func parseTCP(segment []byte, ipVersion uint8, source, destination netip.Addr) (*SYN, error) {
	if len(segment) < 20 {
		return nil, ErrMalformedPacket
	}
	headerLen := int(segment[12]>>4) * 4
	if headerLen < 20 || headerLen > len(segment) {
		return nil, ErrMalformedPacket
	}
	flags := segment[13]
	if flags&flagSYN == 0 || flags&flagACK != 0 {
		return nil, nil
	}
	result := &SYN{
		IPVersion: ipVersion, Source: source, Destination: destination,
		SourcePort: binary.BigEndian.Uint16(segment[0:2]),
		DestPort:   binary.BigEndian.Uint16(segment[2:4]),
		Window:     binary.BigEndian.Uint16(segment[14:16]), Flags: flags,
		OptionKinds: make([]uint8, 0, (headerLen-20)/2),
	}
	if err := parseOptions(segment[20:headerLen], result); err != nil {
		return nil, err
	}
	result.JA4T = formatJA4T(result)
	result.JA4TVersion = JA4TVersion
	return result, nil
}

func formatJA4T(syn *SYN) string {
	options := "00"
	if len(syn.OptionKinds) > 0 {
		parts := make([]string, len(syn.OptionKinds))
		for i, kind := range syn.OptionKinds {
			parts[i] = fmt.Sprintf("%d", kind)
		}
		options = strings.Join(parts, "-")
	}
	mss, scale := "00", "00"
	if syn.MSS != nil {
		mss = fmt.Sprintf("%d", *syn.MSS)
	}
	if syn.WindowScale != nil {
		scale = fmt.Sprintf("%d", *syn.WindowScale)
	}
	return fmt.Sprintf("%d_%s_%s_%s", syn.Window, options, mss, scale)
}

func parseOptions(options []byte, result *SYN) error {
	for len(options) > 0 {
		kind := options[0]
		result.OptionKinds = append(result.OptionKinds, kind)
		if kind == 0 { // End of option list; remaining bytes are padding.
			return nil
		}
		if kind == 1 { // NOP occupies one byte.
			options = options[1:]
			continue
		}
		if len(options) < 2 {
			return ErrMalformedPacket
		}
		length := int(options[1])
		if length < 2 || length > len(options) {
			return ErrMalformedPacket
		}
		value := options[2:length]
		switch kind {
		case 2: // Maximum Segment Size.
			if length != 4 {
				return ErrMalformedPacket
			}
			mss := binary.BigEndian.Uint16(value)
			result.MSS = &mss
		case 3: // Window scale.
			if length != 3 {
				return ErrMalformedPacket
			}
			windowScale := value[0]
			result.WindowScale = &windowScale
		case 4: // SACK permitted.
			if length != 2 {
				return ErrMalformedPacket
			}
			result.SACKPermitted = true
		case 8: // Timestamp values are intentionally not recorded.
			if length != 10 {
				return ErrMalformedPacket
			}
			result.HasTimestamp = true
		}
		options = options[length:]
	}
	return nil
}
