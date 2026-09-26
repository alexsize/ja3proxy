package tunnel

import (
	"net/netip"
	"testing"
	"time"

	dnscapture "github.com/lylemi/ja3proxy/internal/ja3proxy/capture/dns"
	"github.com/lylemi/ja3proxy/internal/ja3proxy/capture/tlshello"
	"github.com/lylemi/ja3proxy/internal/ja3proxy/recorder"
)

func TestTLSObservationPersistsMatchingDNSContext(t *testing.T) {
	output, err := recorder.New(recorder.Options{Raw: true})
	if err != nil {
		t.Fatal(err)
	}
	correlator := dnscapture.NewCorrelator(dnscapture.Config{})
	at := time.Now().UTC()
	question := dnscapture.Question{Name: "example.test", Type: 1, Class: 1}
	clientKey, flowID := "192.0.2.10", "192.0.2.10:53000|192.0.2.53:53"
	_, err = correlator.ObserveDNS(dnscapture.Event{
		FlowID: flowID, ClientKey: clientKey, Transport: dnscapture.TransportUDP, At: at.Add(-time.Second),
		Message: dnscapture.Message{ID: 11, Questions: []dnscapture.Question{question}},
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = correlator.ObserveDNS(dnscapture.Event{
		FlowID: flowID, ClientKey: clientKey, Transport: dnscapture.TransportUDP, At: at.Add(-500 * time.Millisecond),
		Message: dnscapture.Message{ID: 11, Response: true, Questions: []dnscapture.Question{question}, Addresses: []dnscapture.AddressAnswer{{Name: question.Name, Address: netip.MustParseAddr("203.0.113.8"), TTL: 60}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	handler := &TunnelHandler{Recorder: output, DNSCorrelator: correlator}
	meta := recorder.Meta{
		ConnectionID: "tls-1", CapturePoint: "CLIENT_IN", Source: "192.0.2.10:45000",
		IdentitySource: "source_ip", IdentityValue: clientKey, DestinationIP: "203.0.113.8",
	}
	if !handler.tryCapture(meta, tlshello.Capture{Status: "complete", Raw: []byte{1}}) {
		t.Fatal("TLS observation was not queued")
	}
	if err := output.Close(); err != nil {
		t.Fatal(err)
	}
	observations := output.Snapshot()
	if len(observations) != 1 || observations[0].DNSCorrelation == nil {
		t.Fatalf("saved DNS correlation missing: %+v", observations)
	}
	correlation := observations[0].DNSCorrelation
	if correlation.Status != "matched" || len(correlation.Names) != 1 || correlation.Names[0] != question.Name || len(correlation.DNSFlowIDs) != 1 || correlation.DNSFlowIDs[0] != flowID {
		t.Fatalf("saved DNS correlation = %+v", correlation)
	}
}
