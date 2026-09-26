package tcp

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"sort"
	"time"
)

const (
	defaultFragmentTimeout      = 30 * time.Second
	defaultFragmentMaxDatagrams = 256
	defaultFragmentMaxBytes     = 4 << 20
	maxIPDatagramPayload        = 65535
)

var ErrFragmentLimit = errors.New("IP fragment reassembly limit reached")

type FragmentConfig struct {
	Timeout      time.Duration
	MaxDatagrams int
	MaxBytes     int
}

// FragmentReassembler reconstructs fragmented IP datagrams. It is intended
// for one passive capture stream and never retains a packet after completion.
type FragmentReassembler struct {
	cfg     FragmentConfig
	entries map[string]*fragmentSet
	bytes   int
}

type fragmentSet struct {
	version            uint8
	header             []byte
	firstHeader        []byte
	previousNextHeader int
	fragmentNextHeader byte
	hasFirst           bool
	finalLength        int
	hasFinal           bool
	fragments          map[int][]byte
	bytes              int
	updatedAt          time.Time
}

func NewFragmentReassembler(config FragmentConfig) *FragmentReassembler {
	if config.Timeout <= 0 {
		config.Timeout = defaultFragmentTimeout
	}
	if config.MaxDatagrams <= 0 {
		config.MaxDatagrams = defaultFragmentMaxDatagrams
	}
	if config.MaxBytes <= 0 {
		config.MaxBytes = defaultFragmentMaxBytes
	}
	return &FragmentReassembler{cfg: config, entries: make(map[string]*fragmentSet)}
}

// Push returns the original packet for unfragmented input, or a reconstructed
// packet when all fragments have arrived. Incomplete datagrams return
// (nil, false, nil). Malformed or overlapping fragments are rejected.
func (r *FragmentReassembler) Push(packet []byte, at time.Time) ([]byte, bool, error) {
	if r == nil || at.IsZero() || len(packet) == 0 {
		return nil, false, ErrMalformedPacket
	}
	r.expire(at)
	switch packet[0] >> 4 {
	case 4:
		return r.pushIPv4(packet, at)
	case 6:
		return r.pushIPv6(packet, at)
	default:
		return nil, false, ErrMalformedPacket
	}
}

func (r *FragmentReassembler) pushIPv4(packet []byte, at time.Time) ([]byte, bool, error) {
	if len(packet) < 20 {
		return nil, false, ErrMalformedPacket
	}
	headerLength := int(packet[0]&0x0f) * 4
	totalLength := int(binary.BigEndian.Uint16(packet[2:4]))
	if headerLength < 20 || headerLength > len(packet) || totalLength < headerLength || totalLength > len(packet) {
		return nil, false, ErrMalformedPacket
	}
	flagsOffset := binary.BigEndian.Uint16(packet[6:8])
	fragmentOffset := int(flagsOffset&0x1fff) * 8
	more := flagsOffset&0x2000 != 0
	if flagsOffset&0x8000 != 0 || (flagsOffset&0x4000 != 0 && (fragmentOffset != 0 || more)) {
		return nil, false, ErrMalformedPacket
	}
	if fragmentOffset == 0 && !more {
		return packet[:totalLength], true, nil
	}
	payload := packet[headerLength:totalLength]
	return r.addFragment(fragmentKey(4, packet[12:16], packet[16:20], binary.BigEndian.Uint16(packet[4:6]), packet[9]),
		4, packet[:headerLength], -1, packet[9], fragmentOffset, more, payload, at)
}

func (r *FragmentReassembler) pushIPv6(packet []byte, at time.Time) ([]byte, bool, error) {
	if len(packet) < 40 {
		return nil, false, ErrMalformedPacket
	}
	payloadLength := int(binary.BigEndian.Uint16(packet[4:6]))
	end := 40 + payloadLength
	if payloadLength == 0 || end > len(packet) {
		return nil, false, ErrMalformedPacket
	}
	nextHeader, offset, previousNextHeader := packet[6], 40, 6
	for count := 0; nextHeader != 44; count++ {
		if !isIPv6Extension(nextHeader) {
			return packet[:end], true, nil
		}
		if count >= maxIPv6ExtensionHeaders || offset+2 > end {
			return nil, false, ErrMalformedPacket
		}
		headerType := nextHeader
		nextHeader = packet[offset]
		headerLength := 0
		if headerType == 51 {
			headerLength = (int(packet[offset+1]) + 2) * 4
		} else {
			headerLength = (int(packet[offset+1]) + 1) * 8
		}
		if headerLength < 8 || offset+headerLength > end {
			return nil, false, ErrMalformedPacket
		}
		previousNextHeader = offset
		offset += headerLength
	}
	if offset+8 > end {
		return nil, false, ErrMalformedPacket
	}
	fragmentHeader := packet[offset : offset+8]
	fragmentOffsetField := binary.BigEndian.Uint16(fragmentHeader[2:4])
	if fragmentHeader[1] != 0 || fragmentOffsetField&0x0006 != 0 {
		return nil, false, ErrMalformedPacket
	}
	fragmentOffset := int(fragmentOffsetField & 0xfff8)
	more := fragmentOffsetField&1 != 0
	payload := packet[offset+8 : end]
	if fragmentOffset == 0 && !more { // Atomic fragment: strip the header.
		result := append([]byte(nil), packet[:offset]...)
		result[previousNextHeader] = fragmentHeader[0]
		result = append(result, payload...)
		binary.BigEndian.PutUint16(result[4:6], uint16(len(result)-40))
		return result, true, nil
	}
	var id [4]byte
	copy(id[:], fragmentHeader[4:8])
	key := fragmentKey(6, packet[8:24], packet[24:40], binary.BigEndian.Uint32(id[:]), fragmentHeader[0])
	prefix := packet[:offset]
	return r.addFragment(key, 6, prefix, previousNextHeader, fragmentHeader[0], fragmentOffset, more, payload, at)
}

func (r *FragmentReassembler) addFragment(key string, version uint8, header []byte, previousNextHeader int, nextHeader byte, offset int, more bool, payload []byte, at time.Time) ([]byte, bool, error) {
	if len(payload) == 0 || (more && len(payload)%8 != 0) || offset < 0 || offset+len(payload) > maxIPDatagramPayload {
		return nil, false, ErrMalformedPacket
	}
	entry := r.entries[key]
	if entry == nil {
		if len(r.entries) >= r.cfg.MaxDatagrams {
			return nil, false, ErrFragmentLimit
		}
		entry = &fragmentSet{version: version, header: append([]byte(nil), header...), previousNextHeader: previousNextHeader,
			fragmentNextHeader: nextHeader, finalLength: -1, fragments: make(map[int][]byte), updatedAt: at}
		r.entries[key] = entry
	} else if entry.version != version || entry.previousNextHeader != previousNextHeader || entry.fragmentNextHeader != nextHeader || !sameHeader(entry.header, header, version) {
		r.remove(key, entry)
		return nil, false, ErrMalformedPacket
	}
	end := offset + len(payload)
	if entry.hasFinal && end > entry.finalLength || !more && entry.hasFinal && entry.finalLength != end {
		r.remove(key, entry)
		return nil, false, ErrMalformedPacket
	}
	for existingOffset, existing := range entry.fragments {
		existingEnd := existingOffset + len(existing)
		if offset == existingOffset && end == existingEnd {
			wasFinal := entry.hasFinal && existingEnd == entry.finalLength
			if bytes.Equal(existing, payload) && more != wasFinal {
				entry.updatedAt = at
				if entry.hasFirst && entry.hasFinal && fragmentsCover(entry.fragments, entry.finalLength) {
					assembled, err := assembleFragments(entry)
					r.remove(key, entry)
					if err != nil {
						return nil, false, err
					}
					return assembled, true, nil
				}
				return nil, false, nil
			}
			r.remove(key, entry)
			return nil, false, ErrMalformedPacket
		}
		if offset < existingEnd && existingOffset < end {
			r.remove(key, entry)
			return nil, false, ErrMalformedPacket
		}
	}
	if !more {
		for existingOffset, existing := range entry.fragments {
			if existingOffset+len(existing) > end {
				r.remove(key, entry)
				return nil, false, ErrMalformedPacket
			}
		}
		entry.hasFinal, entry.finalLength = true, end
	}
	if entry.bytes+len(payload) > r.cfg.MaxBytes || r.bytes+len(payload) > r.cfg.MaxBytes {
		if entry.bytes == 0 {
			r.remove(key, entry)
		}
		return nil, false, ErrFragmentLimit
	}
	copyPayload := append([]byte(nil), payload...)
	entry.fragments[offset] = copyPayload
	entry.bytes += len(copyPayload)
	r.bytes += len(copyPayload)
	entry.updatedAt = at
	if offset == 0 {
		entry.hasFirst = true
		if version == 4 {
			entry.firstHeader = append(entry.firstHeader[:0], header...)
		}
	}
	if !entry.hasFirst || !entry.hasFinal || !fragmentsCover(entry.fragments, entry.finalLength) {
		return nil, false, nil
	}
	assembled, err := assembleFragments(entry)
	r.remove(key, entry)
	if err != nil {
		return nil, false, err
	}
	return assembled, true, nil
}

func assembleFragments(entry *fragmentSet) ([]byte, error) {
	header := entry.header
	if entry.version == 4 {
		header = entry.firstHeader
		if len(header) < 20 || len(header)+entry.finalLength > 65535 {
			return nil, ErrMalformedPacket
		}
		result := make([]byte, len(header)+entry.finalLength)
		copy(result, header)
		for offset, fragment := range entry.fragments {
			copy(result[len(header)+offset:], fragment)
		}
		binary.BigEndian.PutUint16(result[2:4], uint16(len(result)))
		flagsOffset := binary.BigEndian.Uint16(result[6:8]) & 0x4000 // Preserve DF only.
		binary.BigEndian.PutUint16(result[6:8], flagsOffset)
		result[10], result[11] = 0, 0
		binary.BigEndian.PutUint16(result[10:12], ipv4Checksum(result[:len(header)]))
		return result, nil
	}
	if entry.version != 6 || len(header) < 40 || len(header)-40+entry.finalLength > 65535 {
		return nil, ErrMalformedPacket
	}
	result := make([]byte, len(header)+entry.finalLength)
	copy(result, header)
	result[entry.previousNextHeader] = entry.fragmentNextHeader
	for offset, fragment := range entry.fragments {
		copy(result[len(header)+offset:], fragment)
	}
	binary.BigEndian.PutUint16(result[4:6], uint16(len(result)-40))
	return result, nil
}

func fragmentsCover(fragments map[int][]byte, finalLength int) bool {
	offsets := make([]int, 0, len(fragments))
	for offset := range fragments {
		offsets = append(offsets, offset)
	}
	sort.Ints(offsets)
	cursor := 0
	for _, offset := range offsets {
		if offset != cursor {
			return false
		}
		cursor += len(fragments[offset])
	}
	return cursor == finalLength
}

func sameHeader(first, current []byte, version uint8) bool {
	if version == 4 {
		return len(first) >= 20 && len(current) >= 20 && first[1] == current[1] &&
			bytes.Equal(first[4:6], current[4:6]) && bytes.Equal(first[8:10], current[8:10]) &&
			bytes.Equal(first[12:20], current[12:20])
	}
	return len(first) == len(current) && bytes.Equal(first[:4], current[:4]) &&
		bytes.Equal(first[6:40], current[6:40]) && bytes.Equal(first[40:], current[40:])
}

func (r *FragmentReassembler) expire(now time.Time) {
	for key, entry := range r.entries {
		if now.Sub(entry.updatedAt) > r.cfg.Timeout {
			r.remove(key, entry)
		}
	}
}

func (r *FragmentReassembler) remove(key string, entry *fragmentSet) {
	if current := r.entries[key]; current == entry {
		delete(r.entries, key)
		r.bytes -= entry.bytes
	}
}

func fragmentKey(version uint8, source, destination []byte, id any, protocol byte) string {
	return fmt.Sprintf("%d:%x:%x:%v:%d", version, source, destination, id, protocol)
}

func ipv4Checksum(header []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(header); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(header[i : i+2]))
	}
	if len(header)%2 != 0 {
		sum += uint32(header[len(header)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	return ^uint16(sum)
}
