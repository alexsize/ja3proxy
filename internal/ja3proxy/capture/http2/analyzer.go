// Package http2 extracts bounded HTTP/2 transport metadata without retaining
// application payloads or decoded header values; only bounded parsed version claims survive.
package http2

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"strings"

	"github.com/lylemi/ja3proxy/internal/ja3proxy/capture/appversion"
	"golang.org/x/net/http2/hpack"
)

const (
	NormalizationVersion = "H2-NORM-2"
	ClientPreface        = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
	maxFrameSize         = 1 << 20
	maxHeaderBlockSize   = 1 << 20
	maxObservedFrames    = 64
	maxDynamicTableSize  = 1 << 20
	maxMetadataItems     = 4096
)

type Setting struct {
	ID    uint16 `json:"id"`
	Value uint32 `json:"value"`
}

type WindowUpdate struct {
	StreamID   uint32 `json:"stream_id"`
	Increment  uint32 `json:"increment"`
	FrameIndex int    `json:"frame_index"`
}

type Priority struct {
	StreamID   uint32 `json:"stream_id"`
	Dependency uint32 `json:"dependency"`
	Exclusive  bool   `json:"exclusive"`
	Weight     uint16 `json:"weight"`
	FrameIndex int    `json:"frame_index"`
}

type FieldAvailability struct {
	Field  string `json:"field"`
	Status string `json:"status"`
}

type Fingerprint struct {
	Completeness      string                 `json:"completeness"`
	Direction         string                 `json:"direction"`
	Preface           bool                   `json:"preface"`
	Settings          []Setting              `json:"settings"`
	SettingsOrder     []uint16               `json:"settings_order"`
	WindowUpdates     []WindowUpdate         `json:"window_updates,omitempty"`
	Priorities        []Priority             `json:"priorities,omitempty"`
	DynamicTableSizes []uint32               `json:"dynamic_table_size_updates,omitempty"`
	FrameTypes        []uint8                `json:"frame_types"`
	PseudoHeaderOrder []string               `json:"pseudo_header_order,omitempty"`
	VersionEvidence   []appversion.Evidence  `json:"application_version_evidence,omitempty"`
	Availability      []FieldAvailability    `json:"availability"`
	Hash              string                 `json:"hash"`
}

type Analyzer struct {
	direction        string
	requirePref      bool
	prefaceSeen      bool
	buffer           []byte
	settings         []Setting
	settingsSeen     bool
	window           []WindowUpdate
	frameTypes       []uint8
	pseudo           []string
	headerBlock      []byte
	headerStream     uint32
	priorities       []Priority
	dynamicSizes     []uint32
	headersDecoded   bool
	decoder          *hpack.Decoder
	snapshotPending  bool
	initialSnapshot  bool
	metadataOverflow bool
	versionEvidence  []appversion.Evidence
	disabled         bool
}

func New(direction string) *Analyzer {
	analyzer := &Analyzer{direction: direction, requirePref: direction == "client_to_upstream"}
	analyzer.decoder = hpack.NewDecoder(maxDynamicTableSize, func(field hpack.HeaderField) {
		if direction == "client_to_upstream" && strings.EqualFold(field.Name, "user-agent") {
			analyzer.versionEvidence = appversion.AppendUserAgent(analyzer.versionEvidence, field.Value)
		}
		if strings.HasPrefix(field.Name, ":") {
			if len(analyzer.pseudo) >= maxMetadataItems {
				analyzer.metadataOverflow = true
				return
			}
			analyzer.pseudo = append(analyzer.pseudo, field.Name)
		}
	})
	analyzer.decoder.SetMaxStringLength(maxHeaderBlockSize)
	return analyzer
}

func (a *Analyzer) Observe(p []byte) *Fingerprint {
	if a == nil || a.disabled || len(p) == 0 {
		return nil
	}
	a.buffer = append(a.buffer, p...)
	if len(a.buffer) > 2*maxFrameSize {
		a.disabled = true
		return nil
	}
	if a.requirePref && !a.prefaceSeen {
		if len(a.buffer) < len(ClientPreface) {
			return nil
		}
		if string(a.buffer[:len(ClientPreface)]) != ClientPreface {
			a.disabled = true
			return nil
		}
		a.buffer = a.buffer[len(ClientPreface):]
		a.prefaceSeen = true
	} else if !a.requirePref {
		a.prefaceSeen = true
	}
	for len(a.buffer) >= 9 {
		length := int(a.buffer[0])<<16 | int(a.buffer[1])<<8 | int(a.buffer[2])
		if length > maxFrameSize {
			a.disabled = true
			return nil
		}
		if len(a.buffer) < 9+length {
			break
		}
		frame := a.buffer[:9+length]
		a.buffer = a.buffer[9+length:]
		frameType, flags := frame[3], frame[4]
		streamID := binary.BigEndian.Uint32(frame[5:9]) & 0x7fffffff
		a.frameTypes = append(a.frameTypes, frameType)
		payload := frame[9:]
		switch frameType {
		case 0x4: // SETTINGS
			if streamID != 0 || (flags&0x1 != 0 && len(payload) != 0) || (flags&0x1 == 0 && len(payload)%6 != 0) {
				a.disabled = true
				return nil
			}
			if flags&0x1 == 0 {
				if len(a.settings)+len(payload)/6 > maxMetadataItems {
					a.disabled = true
					return nil
				}
				a.settingsSeen = true
				for offset := 0; offset < len(payload); offset += 6 {
					a.settings = append(a.settings, Setting{ID: binary.BigEndian.Uint16(payload[offset:]), Value: binary.BigEndian.Uint32(payload[offset+2:])})
				}
			}
		case 0x8: // WINDOW_UPDATE
			if len(payload) != 4 {
				a.disabled = true
				return nil
			}
			increment := binary.BigEndian.Uint32(payload) & 0x7fffffff
			if increment == 0 {
				a.disabled = true
				return nil
			}
			a.window = append(a.window, WindowUpdate{StreamID: streamID, Increment: increment, FrameIndex: len(a.frameTypes)})
		case 0x2: // PRIORITY
			if streamID == 0 || len(payload) != 5 {
				a.disabled = true
				return nil
			}
			priority, err := parsePriority(streamID, payload, len(a.frameTypes))
			if err != nil {
				a.disabled = true
				return nil
			}
			a.priorities = append(a.priorities, priority)
		case 0x1, 0x9: // HEADERS / CONTINUATION
			if err := a.observeHeaders(frameType, flags, streamID, payload); err != nil {
				a.disabled = true
				return nil
			}
		}
	}
	if len(a.frameTypes) >= maxObservedFrames {
		if !a.settingsSeen {
			a.disabled = true
			return nil
		}
		result := a.snapshot()
		a.initialSnapshot = true
		a.snapshotPending = false
		a.disabled = true
		return &result
	}
	if a.settingsSeen && ((len(a.frameTypes) > 1 && !a.initialSnapshot) || a.snapshotPending) {
		result := a.snapshot()
		a.initialSnapshot = true
		a.snapshotPending = false
		return &result
	}
	return nil
}

func (a *Analyzer) observeHeaders(frameType, flags byte, streamID uint32, payload []byte) error {
	if frameType == 0x9 {
		if a.headerStream == 0 || a.headerStream != streamID {
			return errors.New("unexpected HTTP/2 CONTINUATION")
		}
	} else {
		if streamID == 0 {
			return errors.New("HTTP/2 HEADERS requires a stream")
		}
		if a.headerStream != 0 {
			return errors.New("interleaved HTTP/2 header block")
		}
		if flags&0x8 != 0 {
			if len(payload) == 0 || int(payload[0]) >= len(payload) {
				return errors.New("invalid HTTP/2 padding")
			}
			padding := int(payload[0])
			payload = payload[1 : len(payload)-padding]
		}
		if flags&0x20 != 0 {
			if len(payload) < 5 {
				return errors.New("invalid HTTP/2 priority")
			}
			priority, err := parsePriority(streamID, payload[:5], len(a.frameTypes))
			if err != nil {
				return err
			}
			a.priorities = append(a.priorities, priority)
			payload = payload[5:]
		}
		a.headerStream = streamID
	}
	a.headerBlock = append(a.headerBlock, payload...)
	if len(a.headerBlock) > maxHeaderBlockSize {
		return errors.New("HTTP/2 header block exceeds limit")
	}
	if flags&0x4 == 0 {
		return nil
	}
	sizes, err := dynamicTableSizeUpdates(a.headerBlock)
	if err != nil {
		return err
	}
	if _, err := a.decoder.Write(a.headerBlock); err != nil {
		return err
	}
	if a.metadataOverflow {
		return errors.New("HTTP/2 pseudo-header metadata exceeds limit")
	}
	if err := a.decoder.Close(); err != nil {
		return err
	}
	if len(a.dynamicSizes)+len(sizes) > maxMetadataItems {
		return errors.New("HTTP/2 dynamic table metadata exceeds limit")
	}
	a.dynamicSizes = append(a.dynamicSizes, sizes...)
	a.headersDecoded = true
	a.headerBlock = nil
	a.headerStream = 0
	a.snapshotPending = true
	return nil
}

func parsePriority(streamID uint32, payload []byte, frameIndex int) (Priority, error) {
	if len(payload) != 5 {
		return Priority{}, errors.New("invalid HTTP/2 priority length")
	}
	dependency := binary.BigEndian.Uint32(payload[:4])
	exclusive := dependency&0x80000000 != 0
	dependency &= 0x7fffffff
	if dependency == streamID {
		return Priority{}, errors.New("HTTP/2 stream cannot depend on itself")
	}
	return Priority{
		StreamID: streamID, Dependency: dependency, Exclusive: exclusive,
		Weight: uint16(payload[4]) + 1, FrameIndex: frameIndex,
	}, nil
}

func dynamicTableSizeUpdates(block []byte) ([]uint32, error) {
	var sizes []uint32
	for len(block) > 0 && block[0]&0xe0 == 0x20 {
		value := uint64(block[0] & 0x1f)
		block = block[1:]
		if value == 0x1f {
			var shift uint
			for {
				if len(block) == 0 || shift >= 63 {
					return nil, errors.New("invalid HPACK dynamic table size")
				}
				b := block[0]
				block = block[1:]
				part := uint64(b & 0x7f)
				if part > (^uint64(0)-value)>>shift {
					return nil, errors.New("HPACK dynamic table size overflows")
				}
				value += part << shift
				if b&0x80 == 0 {
					break
				}
				shift += 7
			}
		}
		if value > maxDynamicTableSize {
			return nil, errors.New("HPACK dynamic table size exceeds limit")
		}
		sizes = append(sizes, uint32(value))
	}
	return sizes, nil
}

func (a *Analyzer) snapshot() Fingerprint {
	result := Fingerprint{
		Completeness: "partial", Direction: a.direction, Preface: a.prefaceSeen,
		Settings: append([]Setting(nil), a.settings...), SettingsOrder: make([]uint16, 0, len(a.settings)),
		WindowUpdates: append([]WindowUpdate(nil), a.window...), FrameTypes: append([]uint8(nil), a.frameTypes...),
		Priorities: append([]Priority(nil), a.priorities...), DynamicTableSizes: append([]uint32(nil), a.dynamicSizes...),
		PseudoHeaderOrder: append([]string(nil), a.pseudo...),
		VersionEvidence:   append([]appversion.Evidence(nil), a.versionEvidence...),
		Availability:      a.fieldAvailability(),
	}
	for _, setting := range a.settings {
		result.SettingsOrder = append(result.SettingsOrder, setting.ID)
	}
	canonical, _ := json.Marshal(struct {
		Settings      []Setting           `json:"settings"`
		SettingsOrder []uint16            `json:"settings_order"`
		WindowUpdates []WindowUpdate      `json:"window_updates"`
		Priorities    []Priority          `json:"priorities"`
		DynamicSizes  []uint32            `json:"dynamic_table_size_updates"`
		FrameTypes    []uint8             `json:"frame_types"`
		Pseudo        []string            `json:"pseudo_header_order"`
		Completeness  string              `json:"completeness"`
		Availability  []FieldAvailability `json:"availability"`
	}{result.Settings, result.SettingsOrder, result.WindowUpdates, result.Priorities, result.DynamicTableSizes, result.FrameTypes, result.PseudoHeaderOrder, result.Completeness, result.Availability})
	digest := sha256.Sum256(canonical)
	result.Hash = hex.EncodeToString(digest[:])
	return result
}

func (a *Analyzer) fieldAvailability() []FieldAvailability {
	state := func(observed bool) string {
		if observed {
			return "observed"
		}
		return "not_observed"
	}
	return []FieldAvailability{
		{Field: "frame_types", Status: state(len(a.frameTypes) > 0)},
		{Field: "settings_values_and_order", Status: state(a.settingsSeen)},
		{Field: "window_update_stream_and_increment", Status: state(len(a.window) > 0)},
		{Field: "priority_parameters", Status: state(len(a.priorities) > 0)},
		{Field: "dynamic_table_size_updates", Status: state(len(a.dynamicSizes) > 0)},
		{Field: "pseudo_header_order", Status: state(a.headersDecoded)},
		{Field: "regular_header_names", Status: "not_recorded"},
		{Field: "decoded_header_values", Status: "not_recorded"},
		{Field: "frame_payloads", Status: "not_recorded"},
		{Field: "unknown_frame_semantics", Status: "not_recorded"},
		{Field: "flow_control_timing", Status: "not_measured"},
	}
}

type Conn struct {
	net.Conn
	analyzer *Analyzer
	on       func(Fingerprint)
}

func WrapConn(conn net.Conn, direction string, on func(Fingerprint)) net.Conn {
	if conn == nil || on == nil {
		return conn
	}
	return &Conn{Conn: conn, analyzer: New(direction), on: on}
}

func (c *Conn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		if fingerprint := c.analyzer.Observe(p[:n]); fingerprint != nil {
			c.on(*fingerprint)
		}
	}
	return n, err
}
