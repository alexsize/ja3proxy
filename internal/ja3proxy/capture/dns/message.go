// Package dns parses bounded DNS messages and correlates DNS answers with TLS
// destination IPs. It does not capture packets or retain raw DNS messages.
package dns

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"strings"
)

const (
	NormalizationVersion = "DNS-NORM-1"
	maxQuestions         = 64
	maxRecords           = 1024
	maxDNSMessageSize    = 65535
	maxNameLength        = 253
	maxLabelLength       = 63
	maxPointerHops       = 32
)

var ErrMalformedMessage = errors.New("malformed DNS message")

type Question struct {
	Name  string `json:"name"`
	Type  uint16 `json:"type"`
	Class uint16 `json:"class"`
}

type AddressAnswer struct {
	Name    string     `json:"name"`
	Address netip.Addr `json:"address"`
	TTL     uint32     `json:"ttl"`
}

type CNAMEAnswer struct {
	Name   string `json:"name"`
	Target string `json:"target"`
	TTL    uint32 `json:"ttl"`
}

type Message struct {
	ID        uint16          `json:"id"`
	Response  bool            `json:"response"`
	Opcode    uint8           `json:"opcode"`
	RCode     uint8           `json:"rcode"`
	Truncated bool            `json:"truncated"`
	Questions []Question      `json:"questions"`
	Addresses []AddressAnswer `json:"addresses,omitempty"`
	Aliases   []CNAMEAnswer   `json:"cname_answers,omitempty"`
}

// ParseMessage parses a DNS message payload (UDP payload or reassembled TCP
// message). Raw bytes, unknown RDATA and non-address records are not retained.
func ParseMessage(packet []byte) (Message, error) {
	if len(packet) < 12 || len(packet) > maxDNSMessageSize {
		return Message{}, ErrMalformedMessage
	}
	qdCount := int(binary.BigEndian.Uint16(packet[4:6]))
	anCount := int(binary.BigEndian.Uint16(packet[6:8]))
	nsCount := int(binary.BigEndian.Uint16(packet[8:10]))
	arCount := int(binary.BigEndian.Uint16(packet[10:12]))
	if qdCount > maxQuestions || anCount+nsCount+arCount > maxRecords {
		return Message{}, ErrMalformedMessage
	}
	flags := binary.BigEndian.Uint16(packet[2:4])
	message := Message{
		ID: binary.BigEndian.Uint16(packet[0:2]), Response: flags&0x8000 != 0,
		Opcode: uint8((flags >> 11) & 0x0f), RCode: uint8(flags & 0x0f), Truncated: flags&0x0200 != 0,
		Questions: make([]Question, 0, qdCount),
	}
	offset := 12
	for i := 0; i < qdCount; i++ {
		name, next, err := decodeName(packet, offset)
		if err != nil || next+4 > len(packet) {
			return Message{}, ErrMalformedMessage
		}
		message.Questions = append(message.Questions, Question{
			Name: name, Type: binary.BigEndian.Uint16(packet[next : next+2]),
			Class: binary.BigEndian.Uint16(packet[next+2 : next+4]),
		})
		offset = next + 4
	}
	for i := 0; i < anCount+nsCount+arCount; i++ {
		name, next, err := decodeName(packet, offset)
		if err != nil || next+10 > len(packet) {
			return Message{}, ErrMalformedMessage
		}
		typ := binary.BigEndian.Uint16(packet[next : next+2])
		class := binary.BigEndian.Uint16(packet[next+2 : next+4])
		ttl := binary.BigEndian.Uint32(packet[next+4 : next+8])
		rdataLen := int(binary.BigEndian.Uint16(packet[next+8 : next+10]))
		rdataOffset := next + 10
		if rdataLen > len(packet)-rdataOffset {
			return Message{}, ErrMalformedMessage
		}
		if i < anCount && class == 1 {
			switch typ {
			case 5:
				target, end, err := decodeName(packet, rdataOffset)
				if err != nil || end != rdataOffset+rdataLen {
					return Message{}, ErrMalformedMessage
				}
				message.Aliases = append(message.Aliases, CNAMEAnswer{Name: name, Target: target, TTL: ttl})
			case 1:
				if rdataLen != 4 {
					return Message{}, ErrMalformedMessage
				}
				var ip [4]byte
				copy(ip[:], packet[rdataOffset:rdataOffset+4])
				message.Addresses = append(message.Addresses, AddressAnswer{Name: name, Address: netip.AddrFrom4(ip), TTL: ttl})
			case 28:
				if rdataLen != 16 {
					return Message{}, ErrMalformedMessage
				}
				var ip [16]byte
				copy(ip[:], packet[rdataOffset:rdataOffset+16])
				message.Addresses = append(message.Addresses, AddressAnswer{Name: name, Address: netip.AddrFrom16(ip), TTL: ttl})
			}
		}
		offset = rdataOffset + rdataLen
	}
	if offset != len(packet) {
		return Message{}, ErrMalformedMessage
	}
	return message, nil
}

// ParseTCPFrame parses one complete two-byte-length-prefixed DNS-over-TCP
// frame. TCP byte-stream reassembly is the caller's responsibility.
func ParseTCPFrame(frame []byte) (Message, error) {
	if len(frame) < 2 {
		return Message{}, ErrMalformedMessage
	}
	length := int(binary.BigEndian.Uint16(frame[:2]))
	if length < 12 || length != len(frame)-2 {
		return Message{}, ErrMalformedMessage
	}
	return ParseMessage(frame[2:])
}

func decodeName(packet []byte, start int) (string, int, error) {
	if start < 0 || start >= len(packet) {
		return "", 0, ErrMalformedMessage
	}
	labels := make([]string, 0, 4)
	position, next, jumped, wireLength, hops := start, 0, false, 0, 0
	visited := make(map[int]struct{})
	for {
		if position >= len(packet) {
			return "", 0, ErrMalformedMessage
		}
		length := packet[position]
		switch length & 0xc0 {
		case 0xc0:
			if position+1 >= len(packet) || hops >= maxPointerHops {
				return "", 0, ErrMalformedMessage
			}
			target := int(length&0x3f)<<8 | int(packet[position+1])
			if target >= position || target >= len(packet) {
				return "", 0, ErrMalformedMessage
			}
			if _, exists := visited[target]; exists {
				return "", 0, ErrMalformedMessage
			}
			visited[target] = struct{}{}
			if !jumped {
				next = position + 2
			}
			position, jumped, hops = target, true, hops+1
		case 0x00:
			position++
			if !jumped {
				next = position
			}
			if length == 0 {
				name := strings.Join(labels, ".")
				if name == "" {
					name = "."
				}
				return strings.ToLower(name), next, nil
			}
			labelLen := int(length)
			if labelLen > maxLabelLength || position+labelLen > len(packet) {
				return "", 0, ErrMalformedMessage
			}
			wireLength += labelLen + 1
			if wireLength > maxNameLength+1 {
				return "", 0, ErrMalformedMessage
			}
			label := packet[position : position+labelLen]
			labels = append(labels, presentationLabel(label))
			position += labelLen
		default:
			return "", 0, ErrMalformedMessage
		}
	}
}

func presentationLabel(label []byte) string {
	var builder strings.Builder
	for _, value := range label {
		if value >= 'A' && value <= 'Z' {
			value += 'a' - 'A'
		}
		if value >= 'a' && value <= 'z' || value >= '0' && value <= '9' || value == '-' || value == '_' {
			builder.WriteByte(value)
			continue
		}
		fmt.Fprintf(&builder, "\\%03d", value)
	}
	return builder.String()
}

func questionKey(questions []Question) string {
	if len(questions) == 0 {
		return ""
	}
	parts := make([]string, len(questions))
	for i, question := range questions {
		parts[i] = fmt.Sprintf("%s/%d/%d", question.Name, question.Type, question.Class)
	}
	return strings.Join(parts, "|")
}
