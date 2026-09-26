package tcp

import (
	"encoding/binary"
	"errors"
	"testing"
	"time"
)

func TestFragmentReassemblerIPv4OutOfOrderAndDuplicate(t *testing.T) {
	whole := ipv4Packet(tcpSegment(0x02, []byte{2, 4, 5, 180}), 6, 0)
	first := ipv4Fragment(whole, 0, 16, true)
	last := ipv4Fragment(whole, 16, len(whole)-20-16, false)
	reassembler := NewFragmentReassembler(FragmentConfig{})
	at := time.Date(2026, 9, 25, 13, 0, 0, 0, time.UTC)
	if packet, complete, err := reassembler.Push(last, at); err != nil || complete || packet != nil {
		t.Fatalf("incomplete tail = %x, %v, %v", packet, complete, err)
	}
	if packet, complete, err := reassembler.Push(last, at.Add(time.Millisecond)); err != nil || complete {
		t.Fatalf("duplicate tail = %x, %v, %v", packet, complete, err)
	}
	packet, complete, err := reassembler.Push(first, at.Add(2*time.Millisecond))
	if err != nil || !complete {
		t.Fatalf("complete datagram = %x, %v, %v", packet, complete, err)
	}
	got, err := ParsePacket(packet)
	if err != nil || got == nil || got.JA4T != "64240_2_1460_00" {
		t.Fatalf("reassembled SYN = %+v, %v", got, err)
	}
	if reassembler.bytes != 0 || len(reassembler.entries) != 0 {
		t.Fatal("completed fragment state was not released")
	}
}

func TestFragmentReassemblerIPv6RemovesFragmentHeader(t *testing.T) {
	segment := tcpSegment(0x02, nil)
	whole := make([]byte, 40+8+len(segment))
	whole[0] = 0x60
	binary.BigEndian.PutUint16(whole[4:6], uint16(8+len(segment)))
	whole[6] = 44
	copy(whole[8:24], []byte{0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1})
	copy(whole[24:40], []byte{0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2})
	whole[40] = 6
	binary.BigEndian.PutUint32(whole[44:48], 0x01020304)
	copy(whole[48:], segment)
	first := ipv6Fragment(whole, 0, 16, true)
	last := ipv6Fragment(whole, 16, len(segment)-16, false)
	reassembler := NewFragmentReassembler(FragmentConfig{})
	at := time.Now().UTC()
	if _, complete, err := reassembler.Push(first, at); err != nil || complete {
		t.Fatalf("first fragment = complete %v, error %v", complete, err)
	}
	packet, complete, err := reassembler.Push(last, at.Add(time.Millisecond))
	if err != nil || !complete {
		t.Fatalf("reassembled IPv6 = complete %v, error %v", complete, err)
	}
	if packet[6] != 6 || binary.BigEndian.Uint16(packet[4:6]) != uint16(len(packet)-40) {
		t.Fatalf("fragment header/length not normalized: next=%d length=%d", packet[6], binary.BigEndian.Uint16(packet[4:6]))
	}
	got, err := ParsePacket(packet)
	if err != nil || got == nil || got.IPVersion != 6 {
		t.Fatalf("reassembled IPv6 SYN = %+v, %v", got, err)
	}
}

func TestFragmentReassemblerRejectsOverlapAndEnforcesLimits(t *testing.T) {
	whole := ipv4Packet(tcpSegment(0x02, nil), 6, 0)
	reassembler := NewFragmentReassembler(FragmentConfig{MaxBytes: 64})
	at := time.Now().UTC()
	if _, _, err := reassembler.Push(ipv4Fragment(whole, 0, 16, true), at); err != nil {
		t.Fatal(err)
	}
	if _, _, err := reassembler.Push(ipv4Fragment(whole, 8, 12, false), at.Add(time.Millisecond)); !errors.Is(err, ErrMalformedPacket) {
		t.Fatalf("overlapping fragments error = %v", err)
	}
	limited := NewFragmentReassembler(FragmentConfig{MaxBytes: 8})
	if _, _, err := limited.Push(ipv4Fragment(whole, 0, 16, true), at); !errors.Is(err, ErrFragmentLimit) {
		t.Fatalf("fragment byte limit error = %v", err)
	}
}

func TestFragmentReassemblerExpiresIncompleteDatagrams(t *testing.T) {
	whole := ipv4Packet(tcpSegment(0x02, nil), 6, 0)
	reassembler := NewFragmentReassembler(FragmentConfig{Timeout: time.Second})
	at := time.Now().UTC()
	if _, _, err := reassembler.Push(ipv4Fragment(whole, 0, 16, true), at); err != nil {
		t.Fatal(err)
	}
	if _, complete, err := reassembler.Push(ipv4Packet(tcpSegment(0x02, nil), 6, 0), at.Add(2*time.Second)); err != nil || !complete {
		t.Fatalf("unfragmented packet = complete %v, error %v", complete, err)
	}
	if len(reassembler.entries) != 0 || reassembler.bytes != 0 {
		t.Fatal("expired fragment state was not released")
	}
}

func ipv4Fragment(packet []byte, offset, length int, more bool) []byte {
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

func ipv6Fragment(packet []byte, offset, length int, more bool) []byte {
	fragment := append([]byte(nil), packet[:48]...)
	fragment = append(fragment, packet[48+offset:48+offset+length]...)
	binary.BigEndian.PutUint16(fragment[4:6], uint16(len(fragment)-40))
	field := uint16(offset)
	if more {
		field |= 1
	}
	binary.BigEndian.PutUint16(fragment[42:44], field)
	return fragment
}
