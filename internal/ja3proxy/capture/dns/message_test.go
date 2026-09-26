package dns

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"testing"
	"time"
)

func dnsName(name string) []byte {
	var encoded []byte
	for _, label := range splitLabels(name) {
		encoded = append(encoded, byte(len(label)))
		encoded = append(encoded, label...)
	}
	return append(encoded, 0)
}

func splitLabels(name string) []string {
	var labels []string
	for start := 0; start < len(name); {
		end := start
		for end < len(name) && name[end] != '.' {
			end++
		}
		labels = append(labels, name[start:end])
		start = end + 1
	}
	return labels
}

func dnsQuery(id uint16, name string, qtype uint16) []byte {
	packet := make([]byte, 12)
	binary.BigEndian.PutUint16(packet[0:2], id)
	binary.BigEndian.PutUint16(packet[4:6], 1)
	packet = append(packet, dnsName(name)...)
	question := make([]byte, 4)
	binary.BigEndian.PutUint16(question[0:2], qtype)
	binary.BigEndian.PutUint16(question[2:4], 1)
	return append(packet, question...)
}

func dnsAResponse(query []byte, address [4]byte, ttl uint32) []byte {
	packet := append([]byte(nil), query...)
	binary.BigEndian.PutUint16(packet[2:4], 0x8180)
	binary.BigEndian.PutUint16(packet[6:8], 1)
	answer := []byte{0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 0, 0, 4, address[0], address[1], address[2], address[3]}
	binary.BigEndian.PutUint32(answer[6:10], ttl)
	return append(packet, answer...)
}

func dnsCNAMEResponse(query []byte, target string, ttl uint32) []byte {
	packet := append([]byte(nil), query...)
	binary.BigEndian.PutUint16(packet[2:4], 0x8180)
	binary.BigEndian.PutUint16(packet[6:8], 1)
	answer := append([]byte{0xc0, 0x0c}, 0, 5, 0, 1, 0, 0, 0, 0, 0, 0)
	binary.BigEndian.PutUint32(answer[6:10], ttl)
	data := dnsName(target)
	binary.BigEndian.PutUint16(answer[10:12], uint16(len(data)))
	return append(packet, append(answer, data...)...)
}

func TestParseDNSQueryAndCompressedAResponse(t *testing.T) {
	query := dnsQuery(0x1234, "Example.COM", 1)
	parsedQuery, err := ParseMessage(query)
	if err != nil || parsedQuery.Response || parsedQuery.ID != 0x1234 || len(parsedQuery.Questions) != 1 || parsedQuery.Questions[0].Name != "example.com" {
		t.Fatalf("parsed query = %+v, error = %v", parsedQuery, err)
	}
	response := dnsAResponse(query, [4]byte{203, 0, 113, 7}, 90)
	parsedResponse, err := ParseMessage(response)
	if err != nil || !parsedResponse.Response || len(parsedResponse.Addresses) != 1 || parsedResponse.Addresses[0].Address != netip.MustParseAddr("203.0.113.7") || parsedResponse.Addresses[0].TTL != 90 {
		t.Fatalf("parsed response = %+v, error = %v", parsedResponse, err)
	}
}

func TestParseDNSTCPFrameAndRejectsMalformedCompression(t *testing.T) {
	message := dnsQuery(10, "tcp.example", 1)
	frame := make([]byte, len(message)+2)
	binary.BigEndian.PutUint16(frame[:2], uint16(len(message)))
	copy(frame[2:], message)
	if parsed, err := ParseTCPFrame(frame); err != nil || parsed.Questions[0].Name != "tcp.example" {
		t.Fatalf("TCP DNS parse = %+v, error = %v", parsed, err)
	}
	loop := make([]byte, 18)
	binary.BigEndian.PutUint16(loop[4:6], 1)
	loop[12], loop[13] = 0xc0, 0x0c
	if _, err := ParseMessage(loop); !errors.Is(err, ErrMalformedMessage) {
		t.Fatalf("compression-loop error = %v", err)
	}
	if _, err := ParseTCPFrame(frame[:len(frame)-1]); !errors.Is(err, ErrMalformedMessage) {
		t.Fatalf("truncated TCP-frame error = %v", err)
	}
}

func TestParseDNSCompressedCNAMEAndRejectsMalformedRData(t *testing.T) {
	query := dnsQuery(7, "www.example.test", 1)
	response := dnsCNAMEResponse(query, "edge.example.test", 45)
	parsed, err := ParseMessage(response)
	if err != nil || len(parsed.Aliases) != 1 || parsed.Aliases[0] != (CNAMEAnswer{Name: "www.example.test", Target: "edge.example.test", TTL: 45}) {
		t.Fatalf("CNAME response = %+v, error = %v", parsed, err)
	}
	compressed := append([]byte(nil), query...)
	binary.BigEndian.PutUint16(compressed[2:4], 0x8180)
	binary.BigEndian.PutUint16(compressed[6:8], 1)
	compressed = append(compressed, 0xc0, 0x0c, 0, 5, 0, 1, 0, 0, 0, 45, 0, 7, 4, 'e', 'd', 'g', 'e', 0xc0, 0x10)
	if got, err := ParseMessage(compressed); err != nil || len(got.Aliases) != 1 || got.Aliases[0].Target != "edge.example.test" {
		t.Fatalf("compressed CNAME target = %+v, error = %v", got, err)
	}
	malformed := append([]byte(nil), response...)
	// Claim one byte less than the encoded target so trailing data is rejected.
	dataLengthOffset := len(malformed) - len(dnsName("edge.example.test")) - 2
	binary.BigEndian.PutUint16(malformed[dataLengthOffset:dataLengthOffset+2], uint16(len(dnsName("edge.example.test"))-1))
	if _, err := ParseMessage(malformed); !errors.Is(err, ErrMalformedMessage) {
		t.Fatalf("malformed CNAME RDATA error = %v", err)
	}
}

func TestCorrelatorHandlesReorderedEventsAndTTL(t *testing.T) {
	c := NewCorrelator(Config{MatchWindow: 5 * time.Second})
	query, _ := ParseMessage(dnsQuery(22, "example.net", 1))
	response, _ := ParseMessage(dnsAResponse(dnsQuery(22, "example.net", 1), [4]byte{203, 0, 113, 9}, 30))
	base := time.Date(2026, 9, 25, 10, 0, 0, 0, time.UTC)
	respEvent := Event{FlowID: "dns-flow-1", ClientKey: "client-1", Transport: TransportUDP, Message: response, At: base.Add(time.Second)}
	if exchange, err := c.ObserveDNS(respEvent); err != nil || exchange != nil {
		t.Fatalf("response-first event = %+v, error = %v", exchange, err)
	}
	exchange, err := c.ObserveDNS(Event{FlowID: "dns-flow-1", ClientKey: "client-1", Transport: TransportUDP, Message: query, At: base})
	if err != nil || exchange == nil || exchange.Status != "resolved" || exchange.QueryAt != base || exchange.ResponseAt != base.Add(time.Second) {
		t.Fatalf("reordered exchange = %+v, error = %v", exchange, err)
	}
	matched := c.CorrelateTLS("client-1", netip.MustParseAddr("203.0.113.9"), base.Add(2*time.Second))
	if matched.Status != "matched" || len(matched.Names) != 1 || matched.Names[0] != "example.net" {
		t.Fatalf("TLS correlation = %+v", matched)
	}
	if expired := c.CorrelateTLS("client-1", netip.MustParseAddr("203.0.113.9"), base.Add(32*time.Second)); expired.Status != "unmatched" {
		t.Fatalf("expired TLS correlation = %+v", expired)
	}
}

func TestSensorAcceptsReorderedUDPAndProducesTLSCorrelation(t *testing.T) {
	sensor := NewSensor(Config{}, nil)
	base := time.Date(2026, 9, 25, 12, 0, 0, 0, time.UTC)
	query := dnsQuery(31, "sensor.example", 1)
	response := dnsAResponse(query, [4]byte{198, 51, 100, 33}, 60)
	if err := sensor.ObserveUDP("udp-flow", "client-ip", base.Add(time.Second), response); err != nil {
		t.Fatal(err)
	}
	if err := sensor.ObserveUDP("udp-flow", "client-ip", base, query); err != nil {
		t.Fatal(err)
	}
	got := sensor.ObserveTLS("client-ip", netip.MustParseAddr("198.51.100.33"), base.Add(2*time.Second))
	if got.Status != "matched" || len(got.Names) != 1 || got.Names[0] != "sensor.example" {
		t.Fatalf("sensor TLS correlation = %+v", got)
	}
}

func TestCorrelatorReportsAmbiguityAndPacketLoss(t *testing.T) {
	c := NewCorrelator(Config{MatchWindow: time.Second})
	base := time.Date(2026, 9, 25, 11, 0, 0, 0, time.UTC)
	address := [4]byte{192, 0, 2, 55}
	for i, name := range []string{"one.example", "two.example"} {
		queryBytes := dnsQuery(uint16(100+i), name, 1)
		query, _ := ParseMessage(queryBytes)
		response, _ := ParseMessage(dnsAResponse(queryBytes, address, 120))
		flow := "dns-flow-" + name
		if _, err := c.ObserveDNS(Event{FlowID: flow, ClientKey: "same-client", Transport: TransportTCP, Message: query, At: base}); err != nil {
			t.Fatal(err)
		}
		if _, err := c.ObserveDNS(Event{FlowID: flow, ClientKey: "same-client", Transport: TransportTCP, Message: response, At: base.Add(100 * time.Millisecond)}); err != nil {
			t.Fatal(err)
		}
	}
	ambiguous := c.CorrelateTLS("same-client", netip.MustParseAddr("192.0.2.55"), base.Add(time.Second))
	if ambiguous.Status != "ambiguous" || len(ambiguous.Names) != 2 {
		t.Fatalf("ambiguous correlation = %+v", ambiguous)
	}
	query, _ := ParseMessage(dnsQuery(500, "lost.example", 1))
	if _, err := c.ObserveDNS(Event{FlowID: "lost-flow", ClientKey: "same-client", Transport: TransportUDP, Message: query, At: base}); err != nil {
		t.Fatal(err)
	}
	expired := c.Expire(base.Add(2 * time.Second))
	found := false
	for _, exchange := range expired {
		if exchange.FlowID == "lost-flow" && exchange.Status == "unmatched_query" {
			found = true
		}
	}
	if !found {
		t.Fatalf("lost DNS query was not reported: %+v", expired)
	}
}

func TestCorrelatorFollowsCNAMEAcrossExchangesAndHonorsEveryTTL(t *testing.T) {
	correlator := NewCorrelator(Config{})
	base := time.Date(2026, 9, 25, 13, 0, 0, 0, time.UTC)
	client := "client-cname"
	firstQueryBytes := dnsQuery(301, "www.example.test", 1)
	firstQuery, _ := ParseMessage(firstQueryBytes)
	firstResponse, err := ParseMessage(dnsCNAMEResponse(firstQueryBytes, "edge.example.test", 30))
	if err != nil {
		t.Fatal(err)
	}
	secondQueryBytes := dnsQuery(302, "edge.example.test", 1)
	secondQuery, _ := ParseMessage(secondQueryBytes)
	secondResponse, _ := ParseMessage(dnsAResponse(secondQueryBytes, [4]byte{203, 0, 113, 77}, 60))
	for _, event := range []Event{
		{FlowID: "cname-flow", ClientKey: client, Transport: TransportUDP, Message: firstQuery, At: base},
		{FlowID: "cname-flow", ClientKey: client, Transport: TransportUDP, Message: firstResponse, At: base.Add(time.Second)},
		{FlowID: "address-flow", ClientKey: client, Transport: TransportTCP, Message: secondQuery, At: base.Add(2 * time.Second)},
		{FlowID: "address-flow", ClientKey: client, Transport: TransportTCP, Message: secondResponse, At: base.Add(3 * time.Second)},
	} {
		if _, err := correlator.ObserveDNS(event); err != nil {
			t.Fatal(err)
		}
	}
	got := correlator.CorrelateTLS(client, netip.MustParseAddr("203.0.113.77"), base.Add(4*time.Second))
	if got.Status != "matched" || len(got.Names) != 1 || got.Names[0] != "www.example.test" || len(got.DNSFlowIDs) != 2 || got.DNSFlowIDs[0] != "address-flow" || got.DNSFlowIDs[1] != "cname-flow" {
		t.Fatalf("CNAME TLS correlation = %+v", got)
	}
	if targetOnly := correlator.CorrelateTLS(client, netip.MustParseAddr("203.0.113.77"), base.Add(32*time.Second)); targetOnly.Status != "matched" || len(targetOnly.Names) != 1 || targetOnly.Names[0] != "edge.example.test" {
		t.Fatalf("expired CNAME should leave active target answer only: %+v", targetOnly)
	}
	if expired := correlator.CorrelateTLS(client, netip.MustParseAddr("203.0.113.77"), base.Add(64*time.Second)); expired.Status != "unmatched" {
		t.Fatalf("expired address correlation = %+v", expired)
	}
}

func TestCorrelatorCNAMECycleAndAmbiguity(t *testing.T) {
	base := time.Date(2026, 9, 25, 14, 0, 0, 0, time.UTC)
	cycle := NewCorrelator(Config{})
	for i, pair := range [][2]string{{"a.example", "b.example"}, {"b.example", "a.example"}} {
		queryBytes := dnsQuery(uint16(400+i), pair[0], 1)
		query, _ := ParseMessage(queryBytes)
		response, _ := ParseMessage(dnsCNAMEResponse(queryBytes, pair[1], 60))
		flow := pair[0]
		_, _ = cycle.ObserveDNS(Event{FlowID: flow, ClientKey: "cycle-client", Transport: TransportUDP, Message: query, At: base.Add(time.Duration(i) * time.Second)})
		_, _ = cycle.ObserveDNS(Event{FlowID: flow, ClientKey: "cycle-client", Transport: TransportUDP, Message: response, At: base.Add(time.Duration(i)*time.Second + 100*time.Millisecond)})
	}
	if got := cycle.CorrelateTLS("cycle-client", netip.MustParseAddr("192.0.2.8"), base.Add(3*time.Second)); got.Status != "unmatched" {
		t.Fatalf("cycle correlation = %+v", got)
	}

	ambiguous := NewCorrelator(Config{})
	for i, name := range []string{"one.example", "two.example"} {
		queryBytes := dnsQuery(uint16(500+i), name, 1)
		query, _ := ParseMessage(queryBytes)
		response, err := ParseMessage(dnsCNAMEResponse(queryBytes, "shared.example", 60))
		if err != nil {
			t.Fatal(err)
		}
		flow := "alias-" + name
		for _, message := range []Message{query, response} {
			if _, err := ambiguous.ObserveDNS(Event{FlowID: flow, ClientKey: "ambiguous-client", Transport: TransportUDP, Message: message, At: base.Add(time.Duration(i)*time.Second + time.Millisecond)}); err != nil {
				t.Fatal(err)
			}
		}
	}
	addressQueryBytes := dnsQuery(510, "shared.example", 1)
	addressQuery, _ := ParseMessage(addressQueryBytes)
	addressResponse, _ := ParseMessage(dnsAResponse(addressQueryBytes, [4]byte{192, 0, 2, 8}, 60))
	for _, message := range []Message{addressQuery, addressResponse} {
		if _, err := ambiguous.ObserveDNS(Event{FlowID: "shared-address", ClientKey: "ambiguous-client", Transport: TransportUDP, Message: message, At: base.Add(3 * time.Second)}); err != nil {
			t.Fatal(err)
		}
	}
	if got := ambiguous.CorrelateTLS("ambiguous-client", netip.MustParseAddr("192.0.2.8"), base.Add(4*time.Second)); got.Status != "ambiguous" || len(got.Names) != 2 {
		t.Fatalf("ambiguous CNAME correlation = %+v", got)
	}
}

func FuzzParseDNSMessage(f *testing.F) {
	f.Add(dnsQuery(1, "fuzz.example", 1))
	f.Add([]byte{0, 0, 0xc0, 0x0c})
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = ParseMessage(data)
	})
}
