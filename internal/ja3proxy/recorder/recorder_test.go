package recorder

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lylemi/ja3proxy/internal/ja3proxy/capture/appversion"
	dnscapture "github.com/lylemi/ja3proxy/internal/ja3proxy/capture/dns"
	"github.com/lylemi/ja3proxy/internal/ja3proxy/capture/http1"
	http2capture "github.com/lylemi/ja3proxy/internal/ja3proxy/capture/http2"
	quiccapture "github.com/lylemi/ja3proxy/internal/ja3proxy/capture/quic"
	tcpcapture "github.com/lylemi/ja3proxy/internal/ja3proxy/capture/tcp"
	"github.com/lylemi/ja3proxy/internal/ja3proxy/capture/tlshello"
)

func sample() tlshello.Capture {
	raw := []byte{1, 0, 0, 43, 3, 3}
	raw = append(raw, make([]byte, 32)...)
	raw = append(raw, 0, 0, 2, 0x13, 1, 1, 0, 0, 0)
	return tlshello.Capture{Status: "complete", Raw: raw, Records: append([]byte{22, 3, 1, 0, 47}, raw...), RecordVersion: 0x0301, RecordCount: 1}
}

func serverSample() tlshello.Capture {
	random := bytes.Repeat([]byte{0x11}, 32)
	extensions := []byte{
		0x00, 0x2b, 0x00, 0x02, 0x03, 0x04,
		0x00, 0x10, 0x00, 0x05, 0x00, 0x03, 0x02, 'h', '2',
		0x00, 0x29, 0x00, 0x02, 0x00, 0x00,
	}
	extensions = append(extensions[:15], append([]byte{0x00, 0x33, 0x00, 0x06, 0x00, 0x1d, 0x00, 0x02, 0x01, 0x02}, extensions[15:]...)...)
	body := make([]byte, 0, 4+2+32+1+2+1+2+len(extensions))
	body = append(body, 0x03, 0x03)
	body = append(body, random...)
	body = append(body, 0x00, 0xc0, 0x2f, 0x00)
	body = append(body, byte(len(extensions)>>8), byte(len(extensions)))
	body = append(body, extensions...)
	raw := make([]byte, 4, 4+len(body))
	raw[0] = tlshello.ServerHelloType
	raw[1] = byte(len(body) >> 16)
	raw[2] = byte(len(body) >> 8)
	raw[3] = byte(len(body))
	raw = append(raw, body...)
	return tlshello.Capture{Status: "complete", Raw: raw, Records: append([]byte{22, 3, 3, byte(len(raw) >> 8), byte(len(raw))}, raw...), RecordVersion: 0x0303, RecordCount: 1}
}

func TestRecorderServerHelloObservation(t *testing.T) {
	for _, raw := range []bool{false, true} {
		r, err := New(Options{Raw: raw})
		if err != nil {
			t.Fatal(err)
		}
		if !r.TryCaptureServer(Meta{ConnectionID: "server-hello", CapturePoint: "SERVER_IN", Direction: "inbound", ByteSource: "upstream_socket_read"}, serverSample()) {
			t.Fatal("enqueue server hello")
		}
		if err := r.Close(); err != nil {
			t.Fatal(err)
		}
		items := r.Snapshot()
		if len(items) != 1 {
			t.Fatalf("observations = %d", len(items))
		}
		o := items[0]
		if o.CapturePoint != "SERVER_IN" || o.ParserVersion != tlshello.JA3SVersion || o.JA3Version != "" || o.JA4Version != "" {
			t.Fatalf("server observation envelope = %+v", o)
		}
		if o.ServerFingerprints == nil || o.ServerFingerprints.JA3S != "772,49199,43-16-51-41" || o.ServerFingerprints.JA3SHash != "1c38646d61855d3b24190ada58acd240" {
			t.Fatalf("server fingerprints = %+v", o.ServerFingerprints)
		}
		if (len(o.RawServerHello) > 0) != raw || (len(o.ServerRecords) > 0) != raw {
			t.Fatalf("raw policy: raw=%v observation=%+v", raw, o)
		}
	}
}

func TestRecorderMergesDecryptedEncryptedExtensionsIntoServerHello(t *testing.T) {
	r, err := New(Options{})
	if err != nil {
		t.Fatal(err)
	}
	eeRaw := []byte{8, 0, 0, 11, 0, 9, 0, 16, 0, 5, 0, 3, 2, 'h', '2'}
	ee, err := tlshello.ParseEncryptedExtensions(eeRaw)
	if err != nil {
		t.Fatal(err)
	}
	capture := tlshello.EncryptedExtensionsCapture{Status: "complete", Extensions: ee}
	if !r.TryCaptureServerWithEncryptedExtensions(Meta{ConnectionID: "server-ee", CapturePoint: "SERVER_IN", Direction: "inbound", ByteSource: "upstream_socket_read"}, serverSample(), capture) {
		t.Fatal("enqueue enriched ServerHello")
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	items := r.Snapshot()
	if len(items) != 1 || items[0].ServerHello == nil {
		t.Fatalf("enriched server observation = %+v", items)
	}
	fields := items[0].ServerHello.Fields
	if !fields.EncryptedExtensions.Available || fields.EncryptedExtensions.Source != "decrypted_encrypted_extensions" || !fields.SelectedALPN.Available || fields.SelectedALPN.Value != "h2" || fields.SelectedALPN.Source != "decrypted_encrypted_extensions" {
		t.Fatalf("decrypted fields not merged: %+v", fields)
	}
}

func TestRecorderNegotiatedStateObservation(t *testing.T) {
	r, err := New(Options{Raw: true})
	if err != nil {
		t.Fatal(err)
	}
	if !r.TryCaptureNegotiated(Meta{
		ConnectionID: "negotiated-state", CapturePoint: "SERVER_IN", Direction: "inbound",
		ByteSource: "upstream_tls_negotiated_state", HandshakeEvent: "NEGOTIATED_STATE",
	}, NegotiatedState{
		ProtocolVersion: 0x0304, CipherSuite: 0x1301, NegotiatedProtocol: "h2",
		ServerName: "upstream.example", HandshakeType: tlshello.HandshakeTypeResumed, SessionResumption: true, HandshakeComplete: true,
		PeerApplicationSettingsSize: 7,
	}) {
		t.Fatal("enqueue negotiated state")
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	items := r.Snapshot()
	if len(items) != 1 {
		t.Fatalf("observations = %d", len(items))
	}
	o := items[0]
	if o.ParserVersion != NegotiatedStateVersion || o.Completeness != "complete" || o.NegotiatedState == nil {
		t.Fatalf("negotiated observation envelope = %+v", o)
	}
	if o.Verification != nil || o.Forwarding != nil {
		t.Fatalf("negotiated state has byte-level verification: %+v", o)
	}
	if o.NegotiatedState.NegotiatedProtocol != "h2" || o.NegotiatedState.CipherSuite != 0x1301 || o.NegotiatedState.PeerApplicationSettingsSize != 7 || o.NegotiatedState.HandshakeType != tlshello.HandshakeTypeResumed {
		t.Fatalf("negotiated state = %+v", o.NegotiatedState)
	}
	if len(o.Raw) != 0 || len(o.Records) != 0 || len(o.RawServerHello) != 0 || len(o.ServerRecords) != 0 {
		t.Fatalf("negotiated state unexpectedly retained raw bytes: %+v", o)
	}
}

func TestRecorderHTTP1Observation(t *testing.T) {
	r, err := New(Options{})
	if err != nil {
		t.Fatal(err)
	}
	message := http1.Message{Direction: "client_to_upstream", Kind: "request", Sequence: 1, Completeness: "partial", BodyFraming: "chunked", TrailerStatus: "not_fingerprinted", Method: "GET", RequestTarget: "/", HTTPVersion: "HTTP/1.1", HeaderOrder: []string{"Host"}, OriginalHeaderNames: []string{"Host"}, VersionEvidence: []appversion.Evidence{{Product: "Example", Version: "1.2", Source: appversion.SourceUserAgent, Confidence: appversion.ConfidenceLow, Status: appversion.StatusUnverified}}}
	if !r.TryCaptureHTTP1(Meta{ConnectionID: "http1", CapturePoint: "CLIENT_IN", Direction: "inbound", ByteSource: "client_socket_read", HandshakeEvent: "HTTP1_REQUEST"}, message) {
		t.Fatal("enqueue HTTP/1 fingerprint")
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	items := r.Snapshot()
	if len(items) != 1 || items[0].ParserVersion != http1.NormalizationVersion || items[0].HTTP1 == nil || items[0].HTTP1.Method != "GET" || items[0].Completeness != "partial" || items[0].HTTP1.TrailerStatus != "not_fingerprinted" || len(items[0].HTTP1.VersionEvidence) != 1 || items[0].HTTP1.VersionEvidence[0].Status != "unverified" {
		t.Fatalf("HTTP/1 observation = %+v", items)
	}
}

func TestRecorderHTTP2Observation(t *testing.T) {
	r, err := New(Options{})
	if err != nil {
		t.Fatal(err)
	}
	fingerprint := http2capture.Fingerprint{Completeness: "partial", Direction: "client_to_upstream", Preface: true, SettingsOrder: []uint16{0x2}, FrameTypes: []uint8{0x4}, VersionEvidence: []appversion.Evidence{{Product: "Example", Version: "1.2", Source: appversion.SourceUserAgent, Confidence: appversion.ConfidenceLow, Status: appversion.StatusUnverified}}, Hash: strings.Repeat("a", 64)}
	if !r.TryCaptureHTTP2(Meta{ConnectionID: "http2", CapturePoint: "CLIENT_IN", Direction: "inbound", ByteSource: "client_socket_read", HandshakeEvent: "HTTP2_CLIENT"}, fingerprint) {
		t.Fatal("enqueue HTTP/2 fingerprint")
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	items := r.Snapshot()
	if len(items) != 1 || items[0].ParserVersion != http2capture.NormalizationVersion || items[0].HTTP2 == nil || items[0].HTTP2.Hash != strings.Repeat("a", 64) || items[0].Completeness != "partial" || len(items[0].HTTP2.VersionEvidence) != 1 || items[0].HTTP2.VersionEvidence[0].Status != "unverified" {
		t.Fatalf("HTTP/2 observation = %+v", items)
	}
}

func TestRecorderTCPSYNObservationCopiesMetadataWithoutRawPacket(t *testing.T) {
	r, err := New(Options{Raw: true})
	if err != nil {
		t.Fatal(err)
	}
	mss, scale := uint16(1460), uint8(7)
	syn := &tcpcapture.SYN{
		IPVersion: 4, Source: netip.MustParseAddr("192.0.2.10"),
		Destination: netip.MustParseAddr("198.51.100.20"), SourcePort: 54321,
		DestPort: 443, Window: 64240, Flags: 2,
		OptionKinds: []uint8{2, 1, 3, 4}, MSS: &mss, WindowScale: &scale,
		SACKPermitted: true, JA4T: "64240_2-1-3-4_1460_7", JA4TVersion: tcpcapture.JA4TVersion,
	}
	if !r.TryCaptureTCPSYN(Meta{ConnectionID: "tcp-syn", CapturePoint: "CLIENT_TCP_SYN", Direction: "inbound", ByteSource: "passive_packet_source", HandshakeEvent: "TCP_SYN"}, syn) {
		t.Fatal("enqueue TCP SYN metadata")
	}
	syn.OptionKinds[0] = 99
	mss = 1200
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	items := r.Snapshot()
	if len(items) != 1 || items[0].ParserVersion != tcpcapture.NormalizationVersion || items[0].TCPSYN == nil || items[0].Completeness != "complete" {
		t.Fatalf("TCP SYN observation = %+v", items)
	}
	got := items[0].TCPSYN
	if got.OptionKinds[0] != 2 || got.MSS == nil || *got.MSS != 1460 || got.JA4T != "64240_2-1-3-4_1460_7" || got.JA4TVersion != tcpcapture.JA4TVersion || len(items[0].Raw) != 0 || len(items[0].Records) != 0 {
		t.Fatalf("TCP SYN metadata was not isolated from caller or packet bytes: %+v", got)
	}
}

func TestRecorderDNSExchangeObservationCopiesParsedFieldsOnly(t *testing.T) {
	r, err := New(Options{Raw: true})
	if err != nil {
		t.Fatal(err)
	}
	exchange := &dnscapture.Exchange{
		FlowID: "dns-flow", ClientKey: "client-1", Transport: dnscapture.TransportUDP,
		ID: 7, Questions: []dnscapture.Question{{Name: "example.org", Type: 1, Class: 1}},
		Addresses: []dnscapture.AddressAnswer{{Name: "example.org", Address: netip.MustParseAddr("203.0.113.10"), TTL: 60}},
		Aliases:   []dnscapture.CNAMEAnswer{{Name: "www.example.org", Target: "example.org", TTL: 30}},
		QueryAt:   time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC), ResponseAt: time.Date(2026, 1, 2, 3, 4, 6, 0, time.UTC), Status: "resolved",
	}
	if !r.TryCaptureDNSExchange(Meta{ConnectionID: "dns", CapturePoint: "DNS_SENSOR", Direction: "inbound", ByteSource: "passive_packet_source", HandshakeEvent: "DNS_EXCHANGE"}, exchange) {
		t.Fatal("enqueue DNS exchange")
	}
	exchange.Questions[0].Name = "mutated.invalid"
	exchange.Aliases[0].Target = "mutated.invalid"
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	items := r.Snapshot()
	if len(items) != 1 || items[0].ParserVersion != dnscapture.NormalizationVersion || items[0].DNS == nil || items[0].Completeness != "complete" {
		t.Fatalf("DNS observation = %+v", items)
	}
	if items[0].DNS.Questions[0].Name != "example.org" || len(items[0].DNS.Aliases) != 1 || items[0].DNS.Aliases[0].Target != "example.org" || len(items[0].Raw) != 0 || len(items[0].Records) != 0 {
		t.Fatalf("DNS event retained caller mutation or raw bytes: %+v", items[0])
	}
	if !items[0].CapturedAt.Equal(exchange.ResponseAt) {
		t.Fatalf("DNS captured_at=%v, want response timestamp %v", items[0].CapturedAt, exchange.ResponseAt)
	}
}

func TestRecorderQUICObservationStoresParsedMetadataWithoutRawBytes(t *testing.T) {
	r, err := New(Options{Raw: true})
	if err != nil {
		t.Fatal(err)
	}
	value := uint64(30)
	observation := &quiccapture.Observation{
		Metadata: quiccapture.Metadata{
			Version: quiccapture.Version2, PacketNumber: 4, CryptoBytes: 64,
			TransportParameters: []quiccapture.TransportParameter{{ID: 1, Name: "max_idle_timeout", Kind: "integer", Length: 1, Value: &value}},
		},
		Source: "192.0.2.10:53000", Destination: "192.0.2.53:443", ClientIP: "192.0.2.10",
		Hello: &tlshello.Hello{ServerName: "quic.example", CipherSuites: []uint16{0x1301}},
	}
	meta := Meta{ConnectionID: "quic-flow", CapturePoint: "QUIC_CLIENT_INITIAL", Direction: "inbound", ByteSource: "pcap_interface", HandshakeEvent: "QUIC_CLIENT_HELLO", Mode: "PASSIVE", Source: "PASSIVE_QUIC_CAPTURE", IdentityValue: "192.0.2.10"}
	if !r.TryCaptureQUIC(meta, observation, time.Now().UTC()) {
		t.Fatal("enqueue QUIC observation")
	}
	value = 99
	observation.Hello.ServerName = "mutated.invalid"
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	items := r.Snapshot()
	if len(items) != 1 || items[0].ParserVersion != quiccapture.NormalizationVersion || items[0].Completeness != "complete" || items[0].QUIC == nil || items[0].Hello == nil {
		t.Fatalf("QUIC observation = %+v", items)
	}
	if items[0].QUIC.Version != quiccapture.Version2 || items[0].QUIC.TransportParameters[0].Value == nil || *items[0].QUIC.TransportParameters[0].Value != 30 || items[0].Hello.ServerName != "quic.example" || items[0].Fingerprints != nil || len(items[0].Raw) != 0 || len(items[0].Records) != 0 {
		t.Fatalf("QUIC parsed metadata/raw retention = %+v", items[0])
	}
}

func TestRecorderExportAndPrivacy(t *testing.T) {
	for _, raw := range []bool{false, true} {
		t.Run(map[bool]string{false: "metadata", true: "raw"}[raw], func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "capture.jsonl")
			r, err := New(Options{Raw: raw, JSONLPath: path})
			if err != nil {
				t.Fatal(err)
			}
			id := NewID()
			if !r.TryCapture(Meta{ConnectionID: id, CapturePoint: "CLIENT_IN", Direction: "inbound",
				DestinationHost: "connect.example", DestinationIP: "192.0.2.10", DestinationPort: 443}, sample()) {
				t.Fatal("enqueue")
			}
			if err := r.Close(); err != nil {
				t.Fatal(err)
			}
			items := r.Snapshot()
			if len(items) != 1 || items[0].Fingerprints == nil || items[0].Fingerprints.JA4 == "" {
				t.Fatalf("%+v", items)
			}
			if (len(items[0].Raw) > 0) != raw {
				t.Fatal("raw policy")
			}
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			var stored Observation
			if err := json.Unmarshal(bytes.TrimSpace(data), &stored); err != nil {
				t.Fatal(err)
			}
			if stored.ConnectionID != id {
				t.Fatal("wrong file")
			}
			if stored.DestinationHost != "connect.example" || stored.DestinationIP != "192.0.2.10" || stored.DestinationPort != 443 {
				t.Fatalf("destination evidence = %+v", stored.Meta)
			}
			if stored.SchemaVersion != ObservationSchemaVersion || stored.CaptureVersion != CaptureVersion ||
				stored.ParserVersion != tlshello.ParserVersion || stored.JA3Version != tlshello.JA3Version ||
				stored.JA4Version != tlshello.JA4Version || stored.TLSNormVersion != tlshello.NormalizationVersion {
				t.Fatalf("missing or incorrect version envelope: %+v", stored)
			}
			if stored.TLSEngine != "external" || stored.TLSEngineVersion != "unknown" {
				t.Fatalf("incorrect inbound engine attribution: %s@%s", stored.TLSEngine, stored.TLSEngineVersion)
			}
			items[0].Fingerprints.JA3 = "mutated"
			if r.Snapshot()[0].Fingerprints.JA3 == "mutated" {
				t.Fatal("snapshot shares mutable data")
			}
			if _, err := New(Options{JSONLPath: path}); err == nil {
				t.Fatal("overwrote evidence")
			}
		})
	}
}

func TestRecorderRecordsErrorStage(t *testing.T) {
	r, err := New(Options{})
	if err != nil {
		t.Fatal(err)
	}
	if !r.TryCapture(Meta{CapturePoint: "CLIENT_IN", Direction: "inbound"}, tlshello.Capture{
		Status: "timeout", ErrorCode: "capture_timeout",
	}) {
		t.Fatal("enqueue")
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	items := r.Snapshot()
	if len(items) != 1 || items[0].ErrorStage != "capture" || items[0].ErrorCode != "capture_timeout" {
		t.Fatalf("error evidence = %+v", items)
	}
}

func TestObservationAttributesUTLSEngineOnlyToMITMOutbound(t *testing.T) {
	r, err := New(Options{})
	if err != nil {
		t.Fatal(err)
	}
	if !r.TryCapture(Meta{CapturePoint: "PROXY_OUT", Direction: "outbound", Mode: "MITM_REISSUE"}, sample()) {
		t.Fatal("enqueue MITM outbound")
	}
	if !r.TryCapture(Meta{CapturePoint: "PROXY_OUT", Direction: "outbound", Mode: "PASSTHROUGH"}, sample()) {
		t.Fatal("enqueue passthrough outbound")
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	items := r.Snapshot()
	if len(items) != 2 {
		t.Fatalf("observations = %d, want 2", len(items))
	}
	byMode := map[string]Observation{}
	for _, item := range items {
		byMode[item.Mode] = item
	}
	mitm := byMode["MITM_REISSUE"]
	if mitm.TLSEngine != "utls" || mitm.TLSEngineVersion != TLSEngineUTLSVersion {
		t.Fatalf("MITM engine = %s@%s", mitm.TLSEngine, mitm.TLSEngineVersion)
	}
	passthrough := byMode["PASSTHROUGH"]
	if passthrough.TLSEngine != "external" || passthrough.TLSEngineVersion != "unknown" {
		t.Fatalf("passthrough engine = %s@%s", passthrough.TLSEngine, passthrough.TLSEngineVersion)
	}
}

func TestRecorderReparseCreatesNewAnalysisRevision(t *testing.T) {
	r, err := New(Options{Raw: true, RecentLimit: 4})
	if err != nil {
		t.Fatal(err)
	}
	if !r.TryCapture(Meta{ConnectionID: "reparse", CapturePoint: "CLIENT_IN", Direction: "inbound"}, sample()) {
		t.Fatal("enqueue")
	}
	var original Observation
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		items := r.Snapshot()
		if len(items) == 1 {
			original = items[0]
			break
		}
		time.Sleep(time.Millisecond)
	}
	if original.ID == "" {
		t.Fatal("original observation was not processed")
	}
	derived, err := r.Reparse(original.ID)
	if err != nil {
		t.Fatal(err)
	}
	if derived.ID == original.ID || derived.AnalysisParentID != original.ID || derived.AnalysisRevision != 2 {
		t.Fatalf("invalid revision lineage: original=%+v derived=%+v", original, derived)
	}
	if derived.Fingerprints == nil || derived.Hello == nil || derived.Completeness != "complete" {
		t.Fatalf("reparse did not decode source: %+v", derived)
	}
	items := r.Snapshot()
	if len(items) != 2 {
		t.Fatalf("retained observations = %d, want 2", len(items))
	}
	var retainedOriginal *Observation
	for i := range items {
		if items[i].ID == original.ID {
			retainedOriginal = &items[i]
		}
	}
	if retainedOriginal == nil || retainedOriginal.AnalysisRevision != 1 {
		t.Fatalf("source observation was overwritten: %+v", items)
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestReparseRequiresRaw(t *testing.T) {
	_, err := ReparseObservation(Observation{ID: "without-raw"})
	if !errors.Is(err, ErrRawUnavailable) {
		t.Fatalf("error = %v, want ErrRawUnavailable", err)
	}
}

func TestTLSEngineVersionMatchesModulePin(t *testing.T) {
	module, err := os.ReadFile(filepath.Join("..", "..", "..", "go.mod"))
	if err != nil {
		t.Fatal(err)
	}
	want := "github.com/refraction-networking/utls " + TLSEngineUTLSVersion
	if !strings.Contains(string(module), want) {
		t.Fatalf("TLS engine metadata %q does not match go.mod", want)
	}
}

func TestRecorderBoundsAndConcurrentClose(t *testing.T) {
	r, err := New(Options{QueueSize: 8, RecentLimit: 2, MemoryBytes: 8192})
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				r.TryCapture(Meta{ConnectionID: NewID()}, sample())
				r.Snapshot()
			}
		}()
	}
	wg.Add(1)
	go func() { defer wg.Done(); r.Close() }()
	wg.Wait()
	r.Close()
	s := r.Stats()
	if s.Recent > 2 || s.MemoryBytes > 8192 || s.Processed != s.Accepted || s.Dropped == 0 || !s.RecordingDegraded {
		t.Fatalf("%+v", s)
	}
}

func TestQueueOverflowIsNonblocking(t *testing.T) {
	// Deliberately no consumer: the second call must return immediately.
	r := &Recorder{queue: make(chan queued, 1)}
	if !r.TryCapture(Meta{}, sample()) || r.TryCapture(Meta{DeliveryClass: DeliveryClassOptional}, sample()) || r.dropped.Load() != 1 {
		t.Fatal("queue overflow")
	}
	stats := r.Stats()
	if stats.DroppedByClass[DeliveryClassCritical] != 0 || stats.DroppedByClass[DeliveryClassOptional] != 1 {
		t.Fatalf("drop classes = %#v", stats.DroppedByClass)
	}
	if stats.LostByClass[DeliveryClassCritical] != 0 || stats.LostByClass[DeliveryClassOptional] != 0 {
		t.Fatalf("unexpected loss classes = %#v", stats.LostByClass)
	}
}

func TestCriticalDeliveryUsesBoundedSpillQueue(t *testing.T) {
	r := &Recorder{
		queue:         make(chan queued, 1),
		criticalQueue: make(chan queued, 1),
	}
	if !r.TryCapture(Meta{}, sample()) {
		t.Fatal("primary queue rejected first event")
	}
	if !r.TryCapture(Meta{}, sample()) {
		t.Fatal("critical spill queue rejected event")
	}
	if r.TryCapture(Meta{DeliveryClass: DeliveryClassImportant}, sample()) {
		t.Fatal("important event bypassed full primary queue")
	}
	stats := r.Stats()
	if stats.CriticalQueueDepth != 1 || stats.CriticalSpillAccepted != 1 || stats.DroppedByClass[DeliveryClassImportant] != 1 {
		t.Fatalf("critical spill stats = %+v", stats)
	}
}

func TestOutputQuotaAndMalformedCapture(t *testing.T) {
	r, err := New(Options{JSONLPath: filepath.Join(t.TempDir(), "c.jsonl"), MaxFileBytes: 1})
	if err != nil {
		t.Fatal(err)
	}
	r.TryCapture(Meta{}, tlshello.Capture{Status: "complete", Raw: []byte{1, 2, 3}})
	r.TryCapture(Meta{}, tlshello.Capture{Status: "complete", Raw: []byte{1, 2, 3}})
	if err := r.Close(); err == nil {
		t.Fatal("output quota reported success")
	}
	o := r.Snapshot()[0]
	if o.Completeness != "malformed" || o.Fingerprints != nil || r.Stats().WriteErrors != 1 {
		t.Fatalf("%+v", o)
	}
}

func TestEncryptedSpoolRoundTripAndQuarantine(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "spool")
	keyPath := filepath.Join(t.TempDir(), "spool.key")
	if err := os.WriteFile(keyPath, bytes.Repeat([]byte{0x42}, 32), 0600); err != nil {
		t.Fatal(err)
	}
	store, err := openSpool(dir, keyPath, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte(`{"secret":"should-not-be-plaintext"}`)
	if err := store.append("event-1", payload); err != nil {
		t.Fatal(err)
	}
	files, err := store.files()
	if err != nil || len(files) != 1 {
		t.Fatalf("spool files = %v, %v", files, err)
	}
	ciphertext, err := os.ReadFile(files[0])
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(ciphertext, payload) {
		t.Fatal("spool contains plaintext payload")
	}
	var gotID string
	var gotPayload []byte
	if err := store.replay(func(eventID string, got []byte) error {
		gotID, gotPayload = eventID, got
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if gotID != "event-1" || !bytes.Equal(gotPayload, payload) {
		t.Fatalf("replayed spool event = %q/%q", gotID, gotPayload)
	}
	if files, _ := store.files(); len(files) != 0 {
		t.Fatalf("replayed spool files = %v", files)
	}
	if bytesUsed, events, _ := store.stats(); bytesUsed != 0 || events != 0 {
		t.Fatalf("replayed spool accounting = %d bytes/%d events", bytesUsed, events)
	}
	if err := store.append("event-2", payload); err != nil {
		t.Fatal(err)
	}
	files, _ = store.files()
	corrupt, err := os.ReadFile(files[0])
	if err != nil {
		t.Fatal(err)
	}
	corrupt[len(corrupt)-2] = 'f'
	if err := os.WriteFile(files[0], corrupt, 0600); err != nil {
		t.Fatal(err)
	}
	if err := store.replay(func(string, []byte) error { t.Fatal("corrupt spool was replayed"); return nil }); err != nil {
		t.Fatal(err)
	}
	_, events, quarantined := store.stats()
	if events != 0 || quarantined != 1 {
		t.Fatalf("spool status = events %d, quarantined %d", events, quarantined)
	}
	if err := store.append("event-2", payload); err != nil {
		t.Fatalf("replace corrupt spool record: %v", err)
	}
	if _, events, quarantined := store.stats(); events != 1 || quarantined != 1 {
		t.Fatalf("replaced spool status = events %d, quarantined %d", events, quarantined)
	}
}

func TestSpoolReplaysSQLiteAfterTransientFailure(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "spool")
	dbPath := filepath.Join(t.TempDir(), "recorder.db")
	keyPath := filepath.Join(t.TempDir(), "spool.key")
	if err := os.WriteFile(keyPath, bytes.Repeat([]byte{0x37}, 32), 0600); err != nil {
		t.Fatal(err)
	}
	r, err := New(Options{SQLitePath: dbPath, SQLiteRetention: 10, SpoolPath: dir, SpoolKeyPath: keyPath, RecentLimit: 4})
	if err != nil {
		t.Fatal(err)
	}
	if err := r.store.db.Close(); err != nil {
		t.Fatal(err)
	}
	if !r.TryCapture(Meta{ConnectionID: "spool-replay"}, sample()) {
		t.Fatal("enqueue")
	}
	if err := r.Close(); err == nil {
		t.Fatal("transient SQLite failure was not reported")
	}
	if _, events, _ := r.spool.stats(); events != 1 {
		t.Fatalf("spool events after failure = %d", events)
	}
	reopened, err := New(Options{SQLitePath: dbPath, SQLiteRetention: 10, SpoolPath: dir, SpoolKeyPath: keyPath, RecentLimit: 4})
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	items := reopened.Snapshot()
	if len(items) != 1 || items[0].ConnectionID != "spool-replay" {
		t.Fatalf("replayed observations = %+v", items)
	}
	if _, events, _ := reopened.spool.stats(); events != 0 {
		t.Fatalf("spool events after replay = %d", events)
	}
}

func TestRecorderReportsDurableLossByDeliveryClass(t *testing.T) {
	r, err := New(Options{SQLitePath: filepath.Join(t.TempDir(), "recorder.db"), SQLiteRetention: 4})
	if err != nil {
		t.Fatal(err)
	}
	if err := r.store.db.Close(); err != nil {
		t.Fatal(err)
	}
	if !r.TryCapture(Meta{DeliveryClass: DeliveryClassImportant}, sample()) {
		t.Fatal("enqueue")
	}
	if err := r.Close(); err == nil {
		t.Fatal("durable loss was not reported")
	}
	if got := r.Stats().LostByClass[DeliveryClassImportant]; got != 1 {
		t.Fatalf("important durable losses = %d, want 1", got)
	}
}

func TestULID(t *testing.T) {
	seen := map[string]bool{}
	const alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
	for i := 0; i < 10000; i++ {
		id := NewID()
		if len(id) != 26 || id[0] > '7' || seen[id] {
			t.Fatal("invalid/colliding ULID")
		}
		for _, ch := range id {
			if !strings.ContainsRune(alphabet, ch) {
				t.Fatal("alphabet")
			}
		}
		seen[id] = true
	}
}

func obs(norm string) Observation {
	return Observation{Completeness: "complete", Fingerprints: &tlshello.Fingerprints{Normalized: json.RawMessage(norm), NormalizationVersion: "TLS-NORM-1"}}
}
func TestDiff(t *testing.T) {
	a := obs(`{"ciphers":[1,2,3],"old":1,"nested":{"a/b":1}}`)
	b := obs(`{"ciphers":[3,1,2],"new":2,"nested":{"a/b":2}}`)
	diff := Compare(a, b)
	if diff.Status != "MISMATCH" {
		t.Fatal(diff)
	}
	got, _ := json.Marshal(diff.Changes)
	want := `[{"op":"move","path":"/ciphers/0","from":"/ciphers/2"},{"op":"replace","path":"/nested/a~1b","before":1,"after":2},{"op":"add","path":"/new","after":2},{"op":"remove","path":"/old","before":1}]`
	if string(got) != want {
		t.Fatal(string(got))
	}
	if Compare(a, a).Status != "MATCH" {
		t.Fatal("equal mismatch")
	}
	b.Fingerprints.NormalizationVersion = "TLS-NORM-2"
	if Compare(a, b).Status != "UNKNOWN" {
		t.Fatal("version mismatch not unknown")
	}
	if Compare(a, Observation{}).Status != "UNKNOWN" {
		t.Fatal("missing capture not unknown")
	}
}

func TestExpectedProfileVerificationStatuses(t *testing.T) {
	normalized := json.RawMessage(`{"ciphers":[1,2],"extensions":[{"id":0}],"legacy_version":771,"session_id_length":32}`)
	expected := FingerprintExpected{
		ProfileSchemaVersion: SupportedProfileSchemaVersion,
		JA4:                  "expected-ja4",
		Normalized:           normalized,
		NormalizationVersion: "TLS-NORM-1",
		MaterializerVersion:  SupportedMaterializerVersion,
		MustMatch:            []string{"/ciphers", "/extensions"},
		ShouldMatch:          []string{"/session_id_length"},
	}
	actual := Observation{Completeness: "complete", Fingerprints: &tlshello.Fingerprints{JA4: "actual-ja4", NormalizationVersion: "TLS-NORM-1", Normalized: normalized}}
	if got := VerifyExpected(expected, actual); got.Status != "MATCH" {
		t.Fatalf("MATCH verification = %+v", got)
	}
	actual.Fingerprints.Normalized = json.RawMessage(`{"ciphers":[1,2],"extensions":[{"id":0}],"legacy_version":771,"session_id_length":0}`)
	if got := VerifyExpected(expected, actual); got.Status != "PARTIAL_MATCH" || len(got.MismatchedShouldMatch) != 1 || got.MismatchedShouldMatch[0] != "/session_id_length" {
		t.Fatalf("PARTIAL_MATCH verification = %+v", got)
	}
	actual.Fingerprints.Normalized = json.RawMessage(`{"ciphers":[2,1],"extensions":[{"id":0}],"legacy_version":771,"session_id_length":32}`)
	if got := VerifyExpected(expected, actual); got.Status != "MISMATCH" || len(got.MismatchedMustMatch) != 1 || got.MismatchedMustMatch[0] != "/ciphers" {
		t.Fatalf("MISMATCH verification = %+v", got)
	}
	actual.Fingerprints.Normalized = json.RawMessage(`{"ciphers":[2,1],"extensions":[{"id":0}],"legacy_version":771,"session_id_length":0}`)
	if got := VerifyExpected(expected, actual); got.Status != "MISMATCH" || len(got.MismatchedMustMatch) != 1 || len(got.MismatchedShouldMatch) != 1 {
		t.Fatalf("verification did not classify MUST and SHOULD differences: %+v", got)
	}
	actual.Completeness = "timeout"
	if got := VerifyExpected(expected, actual); got.Status != "UNKNOWN" {
		t.Fatalf("UNKNOWN verification = %+v", got)
	}
	actual.Completeness = "complete"
	expected.MaterializerVersion = "utls-template-materializer/2"
	if got := VerifyExpected(expected, actual); got.Status != "UNKNOWN" || got.Reason != "incompatible_materializer_version" {
		t.Fatalf("materializer version verification = %+v", got)
	}
	expected.MaterializerVersion = SupportedMaterializerVersion
	expected.MustMatch = []string{"/missing"}
	if got := VerifyExpected(expected, actual); got.Status != "MISMATCH" {
		t.Fatalf("missing MUST path verification = %+v", got)
	}
	expected.MustMatch = []string{"/ciphers"}
	expected.Constraints = []FingerprintConstraint{{Path: "/legacy_version", Operator: "one_of", Values: []json.RawMessage{json.RawMessage(`772`)}}}
	if got := VerifyExpected(expected, actual); got.Status != "MISMATCH" || got.Reason != "constraint_violation" || len(got.ViolatedConstraints) != 1 || got.ViolatedConstraints[0] != "/legacy_version" {
		t.Fatalf("constraint verification = %+v", got)
	}
}

func TestForwardingVerification(t *testing.T) {
	inbound := tlshello.Capture{Status: "complete", Raw: []byte("hello"), Records: []byte("record")}
	expected := ForwardingFromCapture(inbound)
	if got := VerifyForwarding(*expected, inbound); got.Status != "FORWARDED_UNCHANGED" {
		t.Fatalf("unchanged forwarding = %+v", got)
	}
	changed := inbound
	changed.Raw = []byte("changed")
	if got := VerifyForwarding(*expected, changed); got.Status != "MISMATCH" {
		t.Fatalf("changed forwarding = %+v", got)
	}
	incomplete := inbound
	incomplete.Status = "truncated"
	if got := VerifyForwarding(*expected, incomplete); got.Status != "UNVERIFIED" {
		t.Fatalf("incomplete forwarding = %+v", got)
	}
}
