// Package quic passively decrypts QUIC v1/v2 client Initial packets using the
// public Initial salts, assembles CRYPTO frames, and parses ClientHello.
package quic

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
)

const (
	Version1      uint32 = 1
	Version2      uint32 = 0x6b3343cf
	maxCIDLength         = 20
	maxPacketSize        = 65535
)

var (
	ErrMalformedPacket      = errors.New("malformed QUIC packet")
	ErrUnsupportedVersion   = errors.New("unsupported QUIC version")
	ErrNotInitial           = errors.New("QUIC packet is not an Initial")
	ErrAuthentication       = errors.New("QUIC Initial authentication failed")
	ErrUnsupportedFrame     = errors.New("unsupported QUIC Initial frame")
	ErrMalformedCRYPTO      = errors.New("malformed QUIC CRYPTO stream")
	ErrUnsupportedTransport = errors.New("unsupported IP/UDP packet")
)

type InitialPacket struct {
	Version      uint32
	DCID         []byte
	SCID         []byte
	PacketNumber uint64
	Plaintext    []byte
	PacketLength int
}

type CryptoFrame struct {
	Offset uint64
	Data   []byte
}

type UDPPacket struct {
	Source      string
	Destination string
	Payload     []byte
}

type initialHeader struct {
	version             uint32
	dcid, scid          []byte
	pnOffset, packetEnd int
}

func ParseInitialPacket(datagram []byte) (InitialPacket, error) {
	return parseInitialPacket(datagram, nil)
}

func parseInitialHeader(datagram []byte) (initialHeader, error) {
	if len(datagram) < 7 || len(datagram) > maxPacketSize || datagram[0]&0x80 == 0 || datagram[0]&0x40 == 0 {
		return initialHeader{}, ErrMalformedPacket
	}
	version := binary.BigEndian.Uint32(datagram[1:5])
	if version != Version1 && version != Version2 {
		return initialHeader{}, ErrUnsupportedVersion
	}
	typ := (datagram[0] >> 4) & 0x03
	if version == Version1 && typ != 0 || version == Version2 && typ != 1 {
		return initialHeader{}, ErrNotInitial
	}
	offset := 5
	dcid, offset, err := readCID(datagram, offset)
	if err != nil {
		return initialHeader{}, err
	}
	scid, offset, err := readCID(datagram, offset)
	if err != nil {
		return initialHeader{}, err
	}
	tokenLength, n, err := readVarint(datagram, offset)
	if err != nil || tokenLength > uint64(len(datagram)-n) {
		return initialHeader{}, ErrMalformedPacket
	}
	offset = n
	tokenEnd := offset + int(tokenLength)
	if tokenEnd > len(datagram) {
		return initialHeader{}, ErrMalformedPacket
	}
	length, n, err := readVarint(datagram, tokenEnd)
	if err != nil || length < 1+16 || length > uint64(len(datagram)-n) {
		return initialHeader{}, ErrMalformedPacket
	}
	pnOffset := n
	packetEnd := pnOffset + int(length)
	if packetEnd > len(datagram) {
		return initialHeader{}, ErrMalformedPacket
	}
	return initialHeader{version: version, dcid: dcid, scid: scid, pnOffset: pnOffset, packetEnd: packetEnd}, nil
}

func parseInitialPacket(datagram []byte, largestPN *uint64) (InitialPacket, error) {
	header, err := parseInitialHeader(datagram)
	if err != nil {
		return InitialPacket{}, err
	}
	keys, err := deriveInitialKeys(header.version, header.dcid, true)
	if err != nil {
		return InitialPacket{}, err
	}
	pnOffset, packetEnd := header.pnOffset, header.packetEnd
	if pnOffset+4+aes.BlockSize > packetEnd {
		return InitialPacket{}, ErrMalformedPacket
	}
	hpBlock, err := aes.NewCipher(keys.hp)
	if err != nil {
		return InitialPacket{}, err
	}
	var mask [aes.BlockSize]byte
	hpBlock.Encrypt(mask[:], datagram[pnOffset+4:pnOffset+4+aes.BlockSize])
	first := datagram[0] ^ (mask[0] & 0x0f)
	if first&0x0c != 0 {
		return InitialPacket{}, ErrMalformedPacket
	}
	pnLength := int(first&0x03) + 1
	if pnOffset+pnLength > packetEnd {
		return InitialPacket{}, ErrMalformedPacket
	}
	packetNumber := uint64(0)
	packetNumberBytes := append([]byte(nil), datagram[pnOffset:pnOffset+pnLength]...)
	for i := range packetNumberBytes {
		packetNumberBytes[i] ^= mask[i+1]
		packetNumber = packetNumber<<8 | uint64(packetNumberBytes[i])
	}
	if largestPN != nil {
		packetNumber = decodePacketNumber(packetNumber, pnLength, *largestPN)
	}
	aad := append([]byte(nil), datagram[:pnOffset]...)
	aad[0] = first
	aad = append(aad, packetNumberBytes...)
	block, err := aes.NewCipher(keys.key)
	if err != nil {
		return InitialPacket{}, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return InitialPacket{}, err
	}
	nonce := append([]byte(nil), keys.iv...)
	for i := 0; i < 8; i++ {
		nonce[len(nonce)-1-i] ^= byte(packetNumber >> (8 * i))
	}
	plaintext, err := aead.Open(nil, nonce, datagram[pnOffset+pnLength:packetEnd], aad)
	if err != nil {
		return InitialPacket{}, ErrAuthentication
	}
	return InitialPacket{
		Version: header.version, DCID: header.dcid, SCID: header.scid,
		PacketNumber: packetNumber, Plaintext: plaintext, PacketLength: packetEnd,
	}, nil
}

func decodePacketNumber(truncated uint64, length int, largest uint64) uint64 {
	window := uint64(1) << (8 * length)
	halfWindow := window / 2
	expected := largest + 1
	candidate := (expected & ^(window - 1)) | truncated
	if candidate+halfWindow <= expected && candidate < (uint64(1)<<62)-window {
		return candidate + window
	}
	if candidate > expected+halfWindow && candidate >= window {
		return candidate - window
	}
	return candidate
}

func ParseCryptoFrames(plaintext []byte) ([]CryptoFrame, error) {
	frames := make([]CryptoFrame, 0, 2)
	for offset := 0; offset < len(plaintext); {
		typ, n, err := readVarint(plaintext, offset)
		if err != nil {
			return nil, ErrMalformedPacket
		}
		offset = n
		switch typ {
		case 0: // PADDING
			continue
		case 1: // PING
		case 2, 3: // ACK / ACK_ECN
			for i := 0; i < 2; i++ { // largest acknowledged and ACK delay
				_, offset, err = readVarint(plaintext, offset)
				if err != nil {
					return nil, ErrMalformedPacket
				}
			}
			ranges, offset, err := readVarint(plaintext, offset)
			if err != nil {
				return nil, ErrMalformedPacket
			}
			_, offset, err = readVarint(plaintext, offset) // first_ack_range
			if err != nil || ranges > 4096 {
				return nil, ErrMalformedPacket
			}
			for i := uint64(0); i < ranges; i++ {
				for j := 0; j < 2; j++ {
					_, offset, err = readVarint(plaintext, offset)
					if err != nil {
						return nil, ErrMalformedPacket
					}
				}
			}
			if typ == 3 {
				for i := 0; i < 3; i++ {
					_, offset, err = readVarint(plaintext, offset)
					if err != nil {
						return nil, ErrMalformedPacket
					}
				}
			}
		case 6: // CRYPTO
			cryptoOffset, next, err := readVarint(plaintext, offset)
			if err != nil {
				return nil, ErrMalformedCRYPTO
			}
			length, next, err := readVarint(plaintext, next)
			if err != nil || length > uint64(len(plaintext)-next) || cryptoOffset > uint64(^uint(0)>>1)-length {
				return nil, ErrMalformedCRYPTO
			}
			data := append([]byte(nil), plaintext[next:next+int(length)]...)
			frames = append(frames, CryptoFrame{Offset: cryptoOffset, Data: data})
			offset = next + int(length)
		case 0x1c, 0x1d: // CONNECTION_CLOSE (transport / application)
			for i := 0; i < 1; i++ {
				_, offset, err = readVarint(plaintext, offset)
				if err != nil {
					return nil, ErrMalformedPacket
				}
			}
			if typ == 0x1c {
				_, offset, err = readVarint(plaintext, offset)
				if err != nil {
					return nil, ErrMalformedPacket
				}
			}
			reasonLength, next, err := readVarint(plaintext, offset)
			if err != nil || reasonLength > uint64(len(plaintext)-next) {
				return nil, ErrMalformedPacket
			}
			offset = next + int(reasonLength)
		default:
			return nil, fmt.Errorf("%w: 0x%x", ErrUnsupportedFrame, typ)
		}
	}
	return frames, nil
}

func ParseUDPPacket(packet []byte) (UDPPacket, error) {
	if len(packet) == 0 {
		return UDPPacket{}, ErrUnsupportedTransport
	}
	var source, destination netip.Addr
	var src, dst netip.AddrPort
	var payload []byte
	switch packet[0] >> 4 {
	case 4:
		if len(packet) < 20 {
			return UDPPacket{}, ErrMalformedPacket
		}
		headerLength := int(packet[0]&0x0f) * 4
		totalLength := int(binary.BigEndian.Uint16(packet[2:4]))
		if headerLength < 20 || headerLength > len(packet) || totalLength < headerLength || totalLength > len(packet) || packet[6]&0x3f != 0 || packet[9] != 17 {
			return UDPPacket{}, ErrUnsupportedTransport
		}
		source = netip.AddrFrom4([4]byte(packet[12:16]))
		destination = netip.AddrFrom4([4]byte(packet[16:20]))
		segment := packet[headerLength:totalLength]
		if len(segment) < 8 {
			return UDPPacket{}, ErrMalformedPacket
		}
		src = netip.AddrPortFrom(source, binary.BigEndian.Uint16(segment[:2]))
		dst = netip.AddrPortFrom(destination, binary.BigEndian.Uint16(segment[2:4]))
		length := int(binary.BigEndian.Uint16(segment[4:6]))
		if length < 8 || length > len(segment) {
			return UDPPacket{}, ErrMalformedPacket
		}
		payload = segment[8:length]
	case 6:
		if len(packet) < 40 {
			return UDPPacket{}, ErrMalformedPacket
		}
		end := 40 + int(binary.BigEndian.Uint16(packet[4:6]))
		if end > len(packet) || end == 40 {
			return UDPPacket{}, ErrMalformedPacket
		}
		next, offset := packet[6], 40
		for count := 0; next == 0 || next == 43 || next == 44 || next == 60 || next == 51; count++ {
			if count >= 16 || offset+2 > end || next == 44 {
				return UDPPacket{}, ErrUnsupportedTransport
			}
			headerType := next
			next = packet[offset]
			extLength := (int(packet[offset+1]) + 1) * 8
			if headerType == 51 {
				extLength = (int(packet[offset+1]) + 2) * 4
			}
			if extLength < 8 || offset+extLength > end {
				return UDPPacket{}, ErrMalformedPacket
			}
			offset += extLength
		}
		if next != 17 || offset+8 > end {
			return UDPPacket{}, ErrUnsupportedTransport
		}
		source = netip.AddrFrom16([16]byte(packet[8:24]))
		destination = netip.AddrFrom16([16]byte(packet[24:40]))
		segment := packet[offset:end]
		length := int(binary.BigEndian.Uint16(segment[4:6]))
		if length < 8 || length > len(segment) {
			return UDPPacket{}, ErrMalformedPacket
		}
		src = netip.AddrPortFrom(source, binary.BigEndian.Uint16(segment[:2]))
		dst = netip.AddrPortFrom(destination, binary.BigEndian.Uint16(segment[2:4]))
		payload = segment[8:length]
	default:
		return UDPPacket{}, ErrUnsupportedTransport
	}
	return UDPPacket{Source: src.String(), Destination: dst.String(), Payload: append([]byte(nil), payload...)}, nil
}

type initialKeys struct{ key, iv, hp []byte }

func deriveInitialKeys(version uint32, dcid []byte, client bool) (initialKeys, error) {
	var salt []byte
	labels := []string{"quic key", "quic iv", "quic hp"}
	switch version {
	case Version1:
		salt = mustHex("38762cf7f55934b34d179ae6a4c80cadccbb7f0a")
	case Version2:
		salt = mustHex("0dede3def700a6db819381be6e269dcbf9bd2ed9")
		labels = []string{"quicv2 key", "quicv2 iv", "quicv2 hp"}
	default:
		return initialKeys{}, ErrUnsupportedVersion
	}
	initialSecret := hkdfExtract(salt, dcid)
	role := "server in"
	if client {
		role = "client in"
	}
	trafficSecret := hkdfExpandLabel(initialSecret, role, 32)
	return initialKeys{
		key: hkdfExpandLabel(trafficSecret, labels[0], 16),
		iv:  hkdfExpandLabel(trafficSecret, labels[1], 12),
		hp:  hkdfExpandLabel(trafficSecret, labels[2], 16),
	}, nil
}

func hkdfExtract(salt, input []byte) []byte {
	h := hmac.New(sha256.New, salt)
	_, _ = h.Write(input)
	return h.Sum(nil)
}

func hkdfExpandLabel(secret []byte, label string, length int) []byte {
	fullLabel := append([]byte("tls13 "), label...)
	info := make([]byte, 2, 4+len(fullLabel))
	binary.BigEndian.PutUint16(info, uint16(length))
	info = append(info, byte(len(fullLabel)))
	info = append(info, fullLabel...)
	info = append(info, 0)
	return hkdfExpand(secret, info, length)
}

func hkdfExpand(secret, info []byte, length int) []byte {
	var output, previous []byte
	for counter := byte(1); len(output) < length; counter++ {
		h := hmac.New(sha256.New, secret)
		_, _ = h.Write(previous)
		_, _ = h.Write(info)
		_, _ = h.Write([]byte{counter})
		previous = h.Sum(nil)
		output = append(output, previous...)
	}
	return output[:length]
}

func readCID(packet []byte, offset int) ([]byte, int, error) {
	if offset >= len(packet) {
		return nil, 0, ErrMalformedPacket
	}
	length := int(packet[offset])
	if length > maxCIDLength || offset+1+length > len(packet) {
		return nil, 0, ErrMalformedPacket
	}
	return append([]byte(nil), packet[offset+1:offset+1+length]...), offset + 1 + length, nil
}

func readVarint(packet []byte, offset int) (uint64, int, error) {
	if offset < 0 || offset >= len(packet) {
		return 0, 0, ErrMalformedPacket
	}
	length := 1 << (packet[offset] >> 6)
	if offset+length > len(packet) {
		return 0, 0, ErrMalformedPacket
	}
	value := uint64(packet[offset] & 0x3f)
	for _, b := range packet[offset+1 : offset+length] {
		value = value<<8 | uint64(b)
	}
	return value, offset + length, nil
}

func appendVarint(dst []byte, value uint64) []byte {
	switch {
	case value < 1<<6:
		return append(dst, byte(value))
	case value < 1<<14:
		return append(dst, byte(value>>8)|0x40, byte(value))
	case value < 1<<30:
		return append(dst, byte(value>>24)|0x80, byte(value>>16), byte(value>>8), byte(value))
	default:
		var encoded [8]byte
		binary.BigEndian.PutUint64(encoded[:], value|0xc000000000000000)
		return append(dst, encoded[:]...)
	}
}

func mustHex(value string) []byte {
	decoded, _ := hex.DecodeString(value)
	return decoded
}
