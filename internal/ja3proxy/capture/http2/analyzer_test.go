package http2

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"testing"

	"golang.org/x/net/http2/hpack"
)

func frame(frameType, flags byte, streamID uint32, payload []byte) []byte {
	result := make([]byte, 9+len(payload))
	result[0] = byte(len(payload) >> 16)
	result[1] = byte(len(payload) >> 8)
	result[2] = byte(len(payload))
	result[3], result[4] = frameType, flags
	binary.BigEndian.PutUint32(result[5:9], streamID)
	copy(result[9:], payload)
	return result
}

func TestAnalyzerCapturesPrefaceSettingsAndFrameOrder(t *testing.T) {
	payload := make([]byte, 12)
	binary.BigEndian.PutUint16(payload[0:], 0x2)
	binary.BigEndian.PutUint32(payload[2:], 0)
	binary.BigEndian.PutUint16(payload[6:], 0x4)
	binary.BigEndian.PutUint32(payload[8:], 65535)
	input := append([]byte(ClientPreface), frame(0x4, 0, 0, payload)...)
	input = append(input, frame(0x8, 0, 0, []byte{0, 0, 0, 10})...)
	a := New("client_to_upstream")
	var got *Fingerprint
	for offset := 0; offset < len(input); offset += 3 {
		end := offset + 3
		if end > len(input) {
			end = len(input)
		}
		if candidate := a.Observe(input[offset:end]); candidate != nil {
			got = candidate
		}
	}
	if got == nil || !got.Preface || len(got.Settings) != 2 || len(got.WindowUpdates) != 1 || len(got.FrameTypes) != 2 {
		t.Fatalf("fingerprint = %+v", got)
	}
	if got.SettingsOrder[0] != 0x2 || got.SettingsOrder[1] != 0x4 || got.WindowUpdates[0].Increment != 10 || got.Hash == "" {
		t.Fatalf("fingerprint details = %+v", got)
	}
	if got.Completeness != "partial" || got.Availability[0] != (FieldAvailability{Field: "frame_types", Status: "observed"}) {
		t.Fatalf("coverage metadata = completeness %q, availability %+v", got.Completeness, got.Availability)
	}
	if got.Hash != "dc6c5ac3bf6a129337026de751c55bdd23b9ac41148925381825b5030700944b" {
		t.Fatalf("H2 settings golden hash = %s", got.Hash)
	}
}

func TestAnalyzerRejectsSettingsAckWithPayload(t *testing.T) {
	a := New("server_to_client")
	if got := a.Observe(frame(0x4, 0x1, 0, []byte{0, 1, 0, 0, 0, 1})); got != nil {
		t.Fatalf("invalid SETTINGS ACK produced fingerprint = %+v", got)
	}
	if !a.disabled {
		t.Fatal("SETTINGS ACK with payload was accepted")
	}
}

func TestAnalyzerRejectsWrongClientPreface(t *testing.T) {
	a := New("client_to_upstream")
	if got := a.Observe(bytes.Repeat([]byte{'x'}, len(ClientPreface))); got != nil {
		t.Fatalf("wrong preface produced fingerprint = %+v", got)
	}
}

func TestAnalyzerDecodesPseudoHeaderOrder(t *testing.T) {
	// Literal-without-indexing: :method GET, :path /.
	headerBlock := []byte{0x00, 0x07, ':', 'm', 'e', 't', 'h', 'o', 'd', 0x03, 'G', 'E', 'T', 0x00, 0x05, ':', 'p', 'a', 't', 'h', 0x01, '/'}
	a := New("server_to_client")
	settings := frame(0x4, 0, 0, nil)
	if got := a.Observe(append(settings, frame(0x1, 0x4, 1, headerBlock)...)); got == nil || len(got.PseudoHeaderOrder) != 2 || got.PseudoHeaderOrder[0] != ":method" || got.PseudoHeaderOrder[1] != ":path" {
		t.Fatalf("pseudo-header order = %+v", got)
	}
}

func TestAnalyzerExtractsUnverifiedVersionFromClientUserAgent(t *testing.T) {
	var block bytes.Buffer
	encoder := hpack.NewEncoder(&block)
	for _, field := range []hpack.HeaderField{
		{Name: ":method", Value: "GET"},
		{Name: "user-agent", Value: "ExampleApp/4.2.1 okhttp/4.12.0"},
	} {
		if err := encoder.WriteField(field); err != nil {
			t.Fatal(err)
		}
	}
	input := append([]byte(ClientPreface), frame(0x4, 0, 0, nil)...)
	input = append(input, frame(0x1, 0x4, 1, block.Bytes())...)
	analyzer := New("client_to_upstream")
	fingerprint := analyzer.Observe(input)
	if fingerprint == nil || len(fingerprint.VersionEvidence) != 2 {
		t.Fatalf("fingerprint = %+v", fingerprint)
	}
	if fingerprint.VersionEvidence[0].Product != "ExampleApp" || fingerprint.VersionEvidence[0].Version != "4.2.1" || fingerprint.VersionEvidence[0].Status != "unverified" {
		t.Fatalf("version evidence = %+v", fingerprint.VersionEvidence)
	}
	serialized, err := json.Marshal(fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(serialized, []byte("ExampleApp/4.2.1 okhttp")) {
		t.Fatalf("raw user-agent leaked: %s", serialized)
	}
}

func TestAnalyzerCapturesPriorityAndKeepsHPACKStateAcrossBlocks(t *testing.T) {
	var encoded bytes.Buffer
	encoder := hpack.NewEncoder(&encoded)
	field := hpack.HeaderField{Name: ":path", Value: "/dynamic-secret-value"}
	if err := encoder.WriteField(field); err != nil {
		t.Fatal(err)
	}
	firstBlock := append([]byte{0x3f, 0xe1, 0x1f}, encoded.Bytes()...) // table size 4096
	encoded.Reset()
	if err := encoder.WriteField(field); err != nil {
		t.Fatal(err)
	}
	secondBlock := append([]byte(nil), encoded.Bytes()...)
	if len(secondBlock) != 1 || secondBlock[0]&0x80 == 0 {
		t.Fatalf("second HPACK block did not use indexed dynamic entry: %x", secondBlock)
	}

	input := frame(0x4, 0, 0, nil)
	input = append(input, frame(0x2, 0, 1, []byte{0x80, 0, 0, 3, 15})...)
	firstHeaders := append([]byte{0, 0, 0, 0, 7}, firstBlock...)
	input = append(input, frame(0x1, 0x24, 1, firstHeaders)...)
	input = append(input, frame(0x1, 0x4, 3, secondBlock)...)

	a := New("server_to_client")
	got := a.Observe(input)
	if got == nil {
		t.Fatal("fingerprint was not produced")
	}
	if len(got.DynamicTableSizes) != 1 || got.DynamicTableSizes[0] != 4096 {
		t.Fatalf("dynamic table size updates = %v", got.DynamicTableSizes)
	}
	if len(got.PseudoHeaderOrder) != 2 || got.PseudoHeaderOrder[0] != ":path" || got.PseudoHeaderOrder[1] != ":path" {
		t.Fatalf("pseudo-header order across blocks = %v", got.PseudoHeaderOrder)
	}
	if len(got.Priorities) != 2 || got.Priorities[0].Dependency != 3 || !got.Priorities[0].Exclusive || got.Priorities[0].Weight != 16 || got.Priorities[1].Weight != 8 {
		t.Fatalf("priorities = %+v", got.Priorities)
	}
	if got.Hash != "e589cdd407beccf468a7e5c84fd1781bc35894f2ee6b5c43d97ae47d4c67dc00" {
		t.Fatalf("H2 HPACK golden hash = %s", got.Hash)
	}
	serialized, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(serialized, []byte(field.Value)) {
		t.Fatalf("decoded HPACK header value leaked: %s", serialized)
	}
}

func TestAnalyzerRejectsPrioritySelfDependency(t *testing.T) {
	a := New("server_to_client")
	input := append(frame(0x4, 0, 0, nil), frame(0x2, 0, 1, []byte{0, 0, 0, 1, 0})...)
	a.Observe(input)
	if !a.disabled {
		t.Fatal("priority frame with self-dependency was accepted")
	}
}

func FuzzAnalyzer(f *testing.F) {
	f.Add([]byte(ClientPreface))
	f.Add(frame(0x4, 0, 0, nil))
	f.Fuzz(func(t *testing.T, input []byte) {
		a := New("client_to_upstream")
		for offset := 0; offset < len(input); {
			end := offset + 11
			if end > len(input) {
				end = len(input)
			}
			a.Observe(input[offset:end])
			offset = end
		}
	})
}
