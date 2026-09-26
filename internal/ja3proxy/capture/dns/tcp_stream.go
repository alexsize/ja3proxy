package dns

import (
	"bytes"
	"encoding/binary"
	"errors"
	"time"
)

const (
	defaultTCPStreamTimeout    = 2 * time.Minute
	defaultTCPStreamCount      = 1024
	defaultTCPStreamBufferSize = 4 << 20
	maxTCPDNSFrameSize         = maxDNSMessageSize + 2
)

var (
	ErrTCPStreamLimit = errors.New("DNS TCP stream buffer limit reached")
	ErrTCPSequence    = errors.New("invalid or overlapping DNS TCP sequence data")
)

type TCPStreamConfig struct {
	Timeout          time.Duration
	MaxStreams       int
	MaxBufferedBytes int
}

type TCPStreamAssembler struct {
	cfg     TCPStreamConfig
	streams map[string]*dnsTCPStream
	bytes   int
}

type dnsTCPStream struct {
	next      uint32
	started   bool
	synced    bool
	pending   []tcpChunk
	data      []byte
	bytes     int
	updatedAt time.Time
}

type tcpChunk struct {
	sequence uint32
	data     []byte
}

func NewTCPStreamAssembler(config TCPStreamConfig) *TCPStreamAssembler {
	if config.Timeout <= 0 {
		config.Timeout = defaultTCPStreamTimeout
	}
	if config.MaxStreams <= 0 {
		config.MaxStreams = defaultTCPStreamCount
	}
	if config.MaxBufferedBytes <= 0 {
		config.MaxBufferedBytes = defaultTCPStreamBufferSize
	}
	return &TCPStreamAssembler{cfg: config, streams: make(map[string]*dnsTCPStream)}
}

// Push accepts one observed TCP segment and returns complete length-prefixed
// DNS frames in stream order. The output contains frame prefix and message.
func (a *TCPStreamAssembler) Push(segment TCPSegment, at time.Time) ([][]byte, error) {
	if a == nil || at.IsZero() || segment.FlowID == "" || (segment.Direction != "client" && segment.Direction != "server") {
		return nil, ErrInvalidEvent
	}
	a.expire(at)
	key := segment.FlowID + "\x00" + segment.Direction
	stream := a.streams[key]
	if stream == nil {
		if segment.RST || segment.FIN && len(segment.Payload) == 0 {
			return nil, nil
		}
		if len(a.streams) >= a.cfg.MaxStreams {
			return nil, ErrTCPStreamLimit
		}
		stream = &dnsTCPStream{updatedAt: at}
		a.streams[key] = stream
	}
	if segment.SYN && !stream.started {
		stream.next, stream.started, stream.synced = segment.Sequence+1, true, true
	} else if !stream.started {
		stream.next, stream.started = segment.Sequence, true
	}
	sequence := segment.Sequence
	if segment.SYN {
		sequence++
	}
	var err error
	if len(segment.Payload) > 0 {
		err = a.addSegment(key, stream, sequence, segment.Payload, at)
	}
	if err != nil {
		return nil, err
	}
	frames, err := a.extractDNSFrames(stream)
	if err != nil {
		a.remove(key, stream)
		return nil, err
	}
	stream.updatedAt = at
	if segment.FIN || segment.RST {
		a.remove(key, stream)
	}
	return frames, nil
}

func (a *TCPStreamAssembler) addSegment(key string, stream *dnsTCPStream, sequence uint32, payload []byte, at time.Time) error {
	delta := int32(sequence - stream.next)
	if delta < 0 {
		trim := int(-delta)
		if trim >= len(payload) { // Retransmission already consumed.
			stream.updatedAt = at
			return nil
		}
		sequence += uint32(trim)
		payload = payload[trim:]
		delta = 0
	}
	if delta > 0 {
		for _, existing := range stream.pending {
			existingDelta := int32(existing.sequence - sequence)
			if existing.sequence == sequence && bytes.Equal(existing.data, payload) {
				return nil
			}
			if existingDelta < int32(len(payload)) && existingDelta > -int32(len(existing.data)) {
				a.remove(key, stream)
				return ErrTCPSequence
			}
		}
		if stream.bytes+len(payload) > a.cfg.MaxBufferedBytes || a.bytes+len(payload) > a.cfg.MaxBufferedBytes {
			a.remove(key, stream)
			return ErrTCPStreamLimit
		}
		copyPayload := append([]byte(nil), payload...)
		stream.pending = append(stream.pending, tcpChunk{sequence: sequence, data: copyPayload})
		stream.bytes += len(copyPayload)
		a.bytes += len(copyPayload)
		return nil
	}
	if stream.bytes+len(payload) > a.cfg.MaxBufferedBytes || a.bytes+len(payload) > a.cfg.MaxBufferedBytes {
		a.remove(key, stream)
		return ErrTCPStreamLimit
	}
	for _, pending := range stream.pending {
		start := int(int32(pending.sequence - sequence))
		overlapStart := max(0, start)
		overlapEnd := min(len(payload), start+len(pending.data))
		if overlapStart < overlapEnd && !bytes.Equal(payload[overlapStart:overlapEnd], pending.data[overlapStart-start:overlapEnd-start]) {
			a.remove(key, stream)
			return ErrTCPSequence
		}
	}
	stream.data = append(stream.data, payload...)
	stream.next += uint32(len(payload))
	stream.bytes += len(payload)
	a.bytes += len(payload)
	for {
		index := -1
		for i, pending := range stream.pending {
			chunkDelta := int32(pending.sequence - stream.next)
			if chunkDelta <= 0 {
				index = i
				break
			}
		}
		if index < 0 {
			break
		}
		pending := stream.pending[index]
		stream.pending = append(stream.pending[:index], stream.pending[index+1:]...)
		stream.bytes -= len(pending.data)
		a.bytes -= len(pending.data)
		trim := int32(stream.next - pending.sequence)
		if trim < 0 {
			trim = 0
		}
		if int(trim) >= len(pending.data) {
			continue
		}
		remaining := pending.data[trim:]
		stream.data = append(stream.data, remaining...)
		stream.next += uint32(len(remaining))
		stream.bytes += len(remaining)
		a.bytes += len(remaining)
	}
	return nil
}

func (a *TCPStreamAssembler) extractDNSFrames(stream *dnsTCPStream) ([][]byte, error) {
	var frames [][]byte
	if !stream.synced {
		for offset := 0; offset+2 <= len(stream.data); offset++ {
			length := int(binary.BigEndian.Uint16(stream.data[offset : offset+2]))
			if length < 12 || length > maxDNSMessageSize {
				continue
			}
			frameLength := length + 2
			if len(stream.data)-offset < frameLength {
				continue
			}
			candidate := stream.data[offset : offset+frameLength]
			if _, err := ParseTCPFrame(candidate); err != nil {
				continue
			}
			if offset > 0 {
				stream.data = stream.data[offset:]
				stream.bytes -= offset
				a.bytes -= offset
			}
			stream.synced = true
			break
		}
		if !stream.synced {
			// Preserve enough trailing bytes for a maximum-size frame to finish
			// after the next segment, but discard older unsynchronized prefix.
			if len(stream.data) > maxTCPDNSFrameSize {
				discard := len(stream.data) - maxTCPDNSFrameSize
				stream.data = stream.data[discard:]
				stream.bytes -= discard
				a.bytes -= discard
			}
			return nil, nil
		}
	}
	consumed := 0
	for len(stream.data) >= 2 {
		length := int(binary.BigEndian.Uint16(stream.data[:2]))
		if length < 12 {
			return nil, ErrMalformedMessage
		}
		frameLength := length + 2
		if frameLength > maxTCPDNSFrameSize {
			return nil, ErrMalformedMessage
		}
		if len(stream.data) < frameLength {
			break
		}
		frames = append(frames, append([]byte(nil), stream.data[:frameLength]...))
		stream.data = stream.data[frameLength:]
		consumed += frameLength
	}
	if consumed > 0 {
		stream.data = append([]byte(nil), stream.data...)
		stream.bytes -= consumed
		a.bytes -= consumed
	}
	return frames, nil
}

func (a *TCPStreamAssembler) expire(now time.Time) {
	for key, stream := range a.streams {
		if now.Sub(stream.updatedAt) > a.cfg.Timeout {
			a.remove(key, stream)
		}
	}
}

func (a *TCPStreamAssembler) remove(key string, stream *dnsTCPStream) {
	if a.streams[key] != stream {
		return
	}
	delete(a.streams, key)
	a.bytes -= stream.bytes
}
