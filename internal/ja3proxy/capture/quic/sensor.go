package quic

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/lylemi/ja3proxy/internal/ja3proxy/capture/tlshello"
)

const (
	NormalizationVersion = "QUIC-INITIAL/1"
	defaultMaxFlows      = 256
	defaultCryptoBytes   = 256 << 10
	defaultTotalBytes    = 16 << 20
	defaultFlowTimeout   = 2 * time.Minute
)

var (
	ErrNotQUICDatagram = errors.New("UDP datagram is not a QUIC client Initial")
	ErrCryptoOverlap   = errors.New("conflicting QUIC CRYPTO stream data")
	ErrFlowLimit       = errors.New("QUIC Initial flow or buffer limit reached")
	ErrNotClientHello  = errors.New("QUIC Initial CRYPTO stream does not contain ClientHello")
)

type Config struct {
	MaxFlows       int
	MaxCryptoBytes int
	MaxTotalBytes  int
	FlowTimeout    time.Duration
}

type Sensor struct {
	mu    sync.Mutex
	cfg   Config
	flows map[string]*cryptoFlow
	bytes int
}

type cryptoFlow struct {
	data      []byte
	present   []bool
	largestPN uint64
	havePN    bool
	updatedAt time.Time
}

type Observation struct {
	Metadata
	FlowID      string          `json:"flow_id"`
	Source      string          `json:"source"`
	Destination string          `json:"destination"`
	ClientIP    string          `json:"client_ip"`
	Hello       *tlshello.Hello `json:"decoded_client_hello"`
}

type Metadata struct {
	Version             uint32               `json:"version"`
	PacketNumber        uint64               `json:"completion_packet_number"`
	CryptoBytes         int                  `json:"crypto_bytes"`
	TransportParameters []TransportParameter `json:"transport_parameters"`
}

type TransportParameter struct {
	ID       uint64  `json:"id"`
	Position int     `json:"position"`
	Name     string  `json:"name"`
	Kind     string  `json:"kind"`
	Length   int     `json:"length"`
	Value    *uint64 `json:"value,omitempty"`
	Present  bool    `json:"present,omitempty"`
}

func NewSensor(config Config) *Sensor {
	if config.MaxFlows <= 0 {
		config.MaxFlows = defaultMaxFlows
	}
	if config.MaxCryptoBytes <= 0 || config.MaxCryptoBytes > tlshello.MaxHelloSize {
		config.MaxCryptoBytes = defaultCryptoBytes
	}
	if config.MaxTotalBytes <= 0 {
		config.MaxTotalBytes = defaultTotalBytes
	}
	if config.FlowTimeout <= 0 {
		config.FlowTimeout = defaultFlowTimeout
	}
	return &Sensor{cfg: config, flows: make(map[string]*cryptoFlow)}
}

// ObserveIP consumes one complete, fragment-reassembled IP packet. Only a
// successfully authenticated client Initial with a complete ClientHello
// returns an observation; unsupported versions and incomplete flows do not.
func (s *Sensor) ObserveIP(packet []byte, at time.Time) (*Observation, error) {
	if s == nil || at.IsZero() {
		return nil, ErrMalformedPacket
	}
	udp, err := ParseUDPPacket(packet)
	if err != nil {
		return nil, err
	}
	if len(udp.Payload) < 1200 {
		return nil, ErrMalformedPacket
	}
	if len(udp.Payload) < 5 || udp.Payload[0]&0xc0 != 0xc0 {
		return nil, ErrNotQUICDatagram
	}
	remaining := udp.Payload
	var firstError error
	for len(remaining) > 0 {
		header, err := parseInitialHeader(remaining)
		if err != nil {
			if firstError == nil && !errors.Is(err, ErrNotInitial) {
				firstError = err
			}
			break
		}
		observation, err := s.observeInitial(udp, remaining[:header.packetEnd], header, at)
		if observation != nil {
			return observation, nil
		}
		if err != nil && firstError == nil {
			firstError = err
		}
		remaining = remaining[header.packetEnd:]
	}
	return nil, firstError
}

func (s *Sensor) observeInitial(udp UDPPacket, packet []byte, header initialHeader, at time.Time) (*Observation, error) {
	key := udp.Source + "|" + udp.Destination + fmt.Sprintf("|%08x|%x", header.version, header.dcid)
	s.mu.Lock()
	s.expireLocked(at)
	flow := s.flows[key]
	var largestPN *uint64
	if flow != nil && flow.havePN {
		value := flow.largestPN
		largestPN = &value
	}
	s.mu.Unlock()
	initial, err := parseInitialPacket(packet, largestPN)
	if err != nil {
		return nil, err
	}
	cryptoFrames, err := ParseCryptoFrames(initial.Plaintext)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	s.expireLocked(at)
	flow = s.flows[key]
	if flow == nil {
		if len(s.flows) >= s.cfg.MaxFlows {
			s.mu.Unlock()
			return nil, ErrFlowLimit
		}
		flow = &cryptoFlow{updatedAt: at}
		s.flows[key] = flow
	}
	if !flow.havePN || initial.PacketNumber > flow.largestPN {
		flow.largestPN, flow.havePN = initial.PacketNumber, true
	}
	flow.updatedAt = at
	if len(cryptoFrames) == 0 {
		s.mu.Unlock()
		return nil, nil
	}
	if err := s.addFramesLocked(flow, cryptoFrames); err != nil {
		s.removeLocked(key, flow)
		s.mu.Unlock()
		return nil, err
	}
	helloBytes, complete, err := completeClientHello(flow.data, flow.present)
	if err != nil {
		s.removeLocked(key, flow)
		s.mu.Unlock()
		return nil, err
	}
	if !complete {
		s.mu.Unlock()
		return nil, nil
	}
	s.removeLocked(key, flow)
	s.mu.Unlock()

	hello, err := tlshello.Parse(helloBytes)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrNotClientHello, err)
	}
	parameters, err := parseTransportParameters(hello)
	if err != nil {
		return nil, err
	}
	flowDigest := sha256.Sum256([]byte(key))
	return &Observation{
		Metadata: Metadata{Version: initial.Version, PacketNumber: initial.PacketNumber,
			CryptoBytes: len(helloBytes), TransportParameters: parameters},
		FlowID: "quic-" + hex.EncodeToString(flowDigest[:12]),
		Source: udp.Source, Destination: udp.Destination,
		ClientIP: endpointIP(udp.Source), Hello: hello,
	}, nil
}

func (s *Sensor) addFramesLocked(flow *cryptoFlow, frames []CryptoFrame) error {
	for _, frame := range frames {
		end := frame.Offset + uint64(len(frame.Data))
		if end > uint64(s.cfg.MaxCryptoBytes) || end > uint64(^uint(0)>>1) {
			return ErrFlowLimit
		}
		newLength := int(end)
		additional := newLength - len(flow.data)
		if additional > 0 && s.bytes+additional > s.cfg.MaxTotalBytes {
			return ErrFlowLimit
		}
		if additional > 0 {
			flow.data = append(flow.data, make([]byte, additional)...)
			flow.present = append(flow.present, make([]bool, additional)...)
			s.bytes += additional
		}
		start := int(frame.Offset)
		for i, value := range frame.Data {
			index := start + i
			if flow.present[index] && flow.data[index] != value {
				return ErrCryptoOverlap
			}
			flow.data[index], flow.present[index] = value, true
		}
	}
	return nil
}

func completeClientHello(data []byte, present []bool) ([]byte, bool, error) {
	if len(data) < 4 || len(present) < 4 || !allPresent(present[:4]) {
		return nil, false, nil
	}
	if data[0] != 1 {
		return nil, false, ErrNotClientHello
	}
	length := int(data[1])<<16 | int(data[2])<<8 | int(data[3])
	if length < 38 || length+4 > tlshello.MaxHelloSize {
		return nil, false, ErrMalformedCRYPTO
	}
	end := length + 4
	if len(data) < end || !allPresent(present[:end]) {
		return nil, false, nil
	}
	return append([]byte(nil), data[:end]...), true, nil
}

func allPresent(values []bool) bool {
	for _, value := range values {
		if !value {
			return false
		}
	}
	return true
}

func parseTransportParameters(hello *tlshello.Hello) ([]TransportParameter, error) {
	var raw []byte
	found := false
	for _, extension := range hello.Extensions {
		if extension.ID != 0x39 {
			continue
		}
		if found {
			return nil, ErrMalformedCRYPTO
		}
		found, raw = true, extension.Data
	}
	if !found {
		return nil, ErrMalformedCRYPTO
	}
	parameters := make([]TransportParameter, 0, 8)
	seen := make(map[uint64]struct{})
	for offset := 0; offset < len(raw); {
		id, next, err := readVarint(raw, offset)
		if err != nil {
			return nil, ErrMalformedCRYPTO
		}
		length, next, err := readVarint(raw, next)
		if err != nil || length > uint64(len(raw)-next) {
			return nil, ErrMalformedCRYPTO
		}
		if _, duplicate := seen[id]; duplicate {
			return nil, ErrMalformedCRYPTO
		}
		seen[id] = struct{}{}
		valueBytes := raw[next : next+int(length)]
		parameter := TransportParameter{ID: id, Position: len(parameters), Name: transportParameterName(id), Kind: "opaque", Length: len(valueBytes)}
		if isIntegerParameter(id) {
			value, end, err := readVarint(valueBytes, 0)
			if err != nil || end != len(valueBytes) {
				return nil, ErrMalformedCRYPTO
			}
			parameter.Kind = "integer"
			parameter.Value = &value
		} else if id == 0x0c {
			if len(valueBytes) != 0 {
				return nil, ErrMalformedCRYPTO
			}
			parameter.Kind, parameter.Present = "flag", true
		}
		parameters = append(parameters, parameter)
		offset = next + int(length)
	}
	return parameters, nil
}

func isIntegerParameter(id uint64) bool {
	switch id {
	case 0x01, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0e, 0x20:
		return true
	default:
		return false
	}
}

func transportParameterName(id uint64) string {
	names := map[uint64]string{
		0x00: "original_destination_connection_id", 0x01: "max_idle_timeout",
		0x02: "stateless_reset_token", 0x03: "max_udp_payload_size",
		0x04: "initial_max_data", 0x05: "initial_max_stream_data_bidi_local",
		0x06: "initial_max_stream_data_bidi_remote", 0x07: "initial_max_stream_data_uni",
		0x08: "initial_max_streams_bidi", 0x09: "initial_max_streams_uni",
		0x0a: "ack_delay_exponent", 0x0b: "max_ack_delay",
		0x0c: "disable_active_migration", 0x0d: "preferred_address",
		0x0e: "active_connection_id_limit", 0x0f: "initial_source_connection_id",
		0x10: "retry_source_connection_id", 0x20: "max_datagram_frame_size",
	}
	if name := names[id]; name != "" {
		return name
	}
	return "unknown"
}

func endpointIP(endpoint string) string {
	if strings.HasPrefix(endpoint, "[") {
		if address, err := netip.ParseAddrPort(endpoint); err == nil {
			return address.Addr().String()
		}
		return ""
	}
	address, err := netip.ParseAddrPort(endpoint)
	if err != nil {
		return ""
	}
	return address.Addr().String()
}

func (s *Sensor) expireLocked(now time.Time) {
	for key, flow := range s.flows {
		if now.Sub(flow.updatedAt) > s.cfg.FlowTimeout {
			s.removeLocked(key, flow)
		}
	}
}

func (s *Sensor) removeLocked(key string, flow *cryptoFlow) {
	if s.flows[key] != flow {
		return
	}
	delete(s.flows, key)
	s.bytes -= len(flow.data)
}
