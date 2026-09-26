package recorder

import (
	"net/netip"
	"testing"
	"time"

	"github.com/lylemi/ja3proxy/internal/ja3proxy/capture/appversion"
	"github.com/lylemi/ja3proxy/internal/ja3proxy/capture/dns"
	"github.com/lylemi/ja3proxy/internal/ja3proxy/capture/http1"
	http2capture "github.com/lylemi/ja3proxy/internal/ja3proxy/capture/http2"
	quiccapture "github.com/lylemi/ja3proxy/internal/ja3proxy/capture/quic"
	tcpcapture "github.com/lylemi/ja3proxy/internal/ja3proxy/capture/tcp"
)

func TestCompareHTTP1FingerprintIgnoresSequenceAndVersionEvidence(t *testing.T) {
	left := Observation{HTTP1: &http1.Message{Direction: "client_to_upstream", Kind: "request", Sequence: 1, Completeness: "complete", Method: "GET", RequestTarget: "/private?token=left", HTTPVersion: "1.1", HeaderOrder: []string{"host"}}}
	right := left
	right.HTTP1 = &http1.Message{Direction: "client_to_upstream", Kind: "request", Sequence: 9, Completeness: "complete", Method: "GET", RequestTarget: "/private?token=right", HTTPVersion: "1.1", HeaderOrder: []string{"host"}, VersionEvidence: []appversion.Evidence{{Product: "agent", Version: "2", Status: "unverified"}}}
	if got := Compare(left, right); got.Family != "http1" || got.Status != "PARTIAL_MATCH" || got.Reason != "captured_fingerprint_fields_only" {
		t.Fatalf("comparison = %+v", got)
	}
	right.HTTP1.Method = "POST"
	if got := Compare(left, right); got.Status != "MISMATCH" || len(got.Changes) == 0 {
		t.Fatalf("method difference not detected: %+v", got)
	}
}

func TestCompareHTTP2AndTCPFingerprintFamilies(t *testing.T) {
	h2a := Observation{HTTP2: &http2capture.Fingerprint{Completeness: "partial", Direction: "client_to_upstream", Preface: true, Hash: "same", WindowUpdates: []http2capture.WindowUpdate{{StreamID: 1, Increment: 100, FrameIndex: 4}}, Priorities: []http2capture.Priority{{StreamID: 1, Dependency: 0, Weight: 16, FrameIndex: 5}}}}
	h2b := Observation{HTTP2: &http2capture.Fingerprint{Completeness: "partial", Direction: "client_to_upstream", Preface: true, Hash: "same", WindowUpdates: []http2capture.WindowUpdate{{StreamID: 9, Increment: 100, FrameIndex: 30}}, Priorities: []http2capture.Priority{{StreamID: 9, Dependency: 7, Weight: 16, FrameIndex: 31}}, VersionEvidence: []appversion.Evidence{{Product: "agent", Status: "unverified"}}}}
	if got := Compare(h2a, h2b); got.Family != "http2" || got.Status != "PARTIAL_MATCH" {
		t.Fatalf("HTTP/2 comparison = %+v", got)
	}
	h2b.HTTP2.Settings = []http2capture.Setting{{ID: 1, Value: 4096}}
	if got := Compare(h2a, h2b); got.Status != "MISMATCH" {
		t.Fatalf("HTTP/2 SETTINGS difference not detected: %+v", got)
	}
	h2b.HTTP2.Settings = nil
	tcpa := Observation{TCPSYN: &tcpcapture.SYN{Source: netip.MustParseAddr("192.0.2.1"), Destination: netip.MustParseAddr("198.51.100.1"), SourcePort: 1000, DestPort: 443, JA4T: "65535_2-4-8-1_1460_8"}}
	tcpb := Observation{TCPSYN: &tcpcapture.SYN{Source: netip.MustParseAddr("192.0.2.2"), Destination: netip.MustParseAddr("203.0.113.2"), SourcePort: 2000, DestPort: 8443, JA4T: "65535_2-4-8-1_1460_8"}}
	if got := Compare(tcpa, tcpb); got.Family != "tcp_syn" || got.Status != "PARTIAL_MATCH" {
		t.Fatalf("TCP comparison included flow endpoints: %+v", got)
	}
	tcpb.TCPSYN.JA4T = "different"
	if got := Compare(tcpa, tcpb); got.Status != "MISMATCH" {
		t.Fatalf("TCP fingerprint difference not detected: %+v", got)
	}
}

func TestCompareDNSAndQUICFingerprintFamilies(t *testing.T) {
	dnsa := Observation{DNS: &dns.Exchange{FlowID: "flow-a", ClientKey: "client-a", ID: 12, Transport: dns.TransportUDP, QueryAt: time.Unix(1, 0), Status: "matched", Questions: []dns.Question{{Name: "example.test", Type: 1, Class: 1}}}}
	dnsb := Observation{DNS: &dns.Exchange{FlowID: "flow-b", ClientKey: "client-b", ID: 44, Transport: dns.TransportUDP, QueryAt: time.Unix(99, 0), Status: "matched", Questions: []dns.Question{{Name: "example.test", Type: 1, Class: 1}}}}
	if got := Compare(dnsa, dnsb); got.Family != "dns_exchange" || got.Status != "PARTIAL_MATCH" {
		t.Fatalf("DNS comparison included correlation fields: %+v", got)
	}
	dnsb.DNS.Questions[0].Name = "other.test"
	if got := Compare(dnsa, dnsb); got.Status != "MISMATCH" {
		t.Fatalf("DNS question difference not detected: %+v", got)
	}
	dnsb.DNS.Questions[0].Name = "example.test"
	quica := Observation{QUIC: &quiccapture.Metadata{Version: 1, PacketNumber: 10, CryptoBytes: 1200}}
	quicb := Observation{QUIC: &quiccapture.Metadata{Version: 1, PacketNumber: 27, CryptoBytes: 1300}}
	if got := Compare(quica, quicb); got.Family != "quic_initial" || got.Status != "PARTIAL_MATCH" {
		t.Fatalf("QUIC comparison included packet assembly fields: %+v", got)
	}
	quicb.QUIC.Version = 2
	if got := Compare(quica, quicb); got.Status != "MISMATCH" {
		t.Fatalf("QUIC version difference not detected: %+v", got)
	}
}

func TestCompareRejectsDifferentFingerprintFamilies(t *testing.T) {
	left := Observation{HTTP1: &http1.Message{Method: "GET"}}
	right := Observation{TCPSYN: &tcpcapture.SYN{JA4T: "example"}}
	if got := Compare(left, right); got.Status != "UNKNOWN" || got.Reason != "incompatible_fingerprint_family" {
		t.Fatalf("cross-family comparison = %+v", got)
	}
}

func TestCompareRequiresUsableFingerprintEvidence(t *testing.T) {
	left := Observation{HTTP2: &http2capture.Fingerprint{Completeness: "partial", Direction: "client_to_upstream"}}
	right := Observation{HTTP2: &http2capture.Fingerprint{Completeness: "partial", Direction: "client_to_upstream"}}
	if got := Compare(left, right); got.Status != "UNKNOWN" || got.Reason != "insufficient_fingerprint_data" {
		t.Fatalf("empty HTTP/2 metadata was treated as a match: %+v", got)
	}
}
