// Package live connects a platform packet source to the bounded TCP SYN parser.
package live

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"time"

	dnscapture "github.com/lylemi/ja3proxy/internal/ja3proxy/capture/dns"
	"github.com/lylemi/ja3proxy/internal/ja3proxy/capture/pcap"
	quiccapture "github.com/lylemi/ja3proxy/internal/ja3proxy/capture/quic"
	tcpcapture "github.com/lylemi/ja3proxy/internal/ja3proxy/capture/tcp"
	"github.com/lylemi/ja3proxy/internal/ja3proxy/recorder"
)

var ErrNoRecorder = errors.New("TCP capture requires a recorder")

// RunTCP consumes a passive interface source until cancellation or read error.
// Malformed/non-IP/non-SYN packets are skipped and never enter proxy forwarding.
func RunTCP(ctx context.Context, source pcap.Source, output *recorder.Recorder) error {
	return RunTCPWithCorrelator(ctx, source, output, nil)
}

func RunTCPWithCorrelator(ctx context.Context, source pcap.Source, output *recorder.Recorder, correlator *dnscapture.Correlator) error {
	if source == nil || output == nil {
		return ErrNoRecorder
	}
	defer source.Close()
	fragments := tcpcapture.NewFragmentReassembler(tcpcapture.FragmentConfig{})
	dnsTCP := dnscapture.NewTCPStreamAssembler(dnscapture.TCPStreamConfig{})
	quicSensor := quiccapture.NewSensor(quiccapture.Config{})
	dnsSensor := dnscapture.NewSensorWithCorrelator(correlator, func(exchange dnscapture.Exchange) {
		meta := recorder.Meta{
			ConnectionID:   dnsConnectionID(exchange.FlowID),
			CapturePoint:   "DNS_QUERY_RESPONSE",
			Direction:      "bidirectional",
			ByteSource:     "pcap_interface",
			HandshakeEvent: "DNS_EXCHANGE",
			Mode:           "PASSIVE",
			Source:         "PASSIVE_DNS_CAPTURE",
			IdentitySource: "dns_client_ip",
			IdentityValue:  exchange.ClientKey,
			Confidence:     "observed",
		}
		output.TryCaptureDNSExchange(meta, &exchange)
	})
	for {
		packet, err := source.ReadPacket(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		if packet.Timestamp.IsZero() {
			packet.Timestamp = time.Now().UTC()
		}
		ipPacket, err := packet.IPPayload()
		if err != nil {
			continue
		}
		ipPacket, complete, err := fragments.Push(ipPacket, packet.Timestamp)
		if err != nil || !complete {
			continue
		}
		dnsPacket, dnsErr := dnscapture.ParseUDPPacket(ipPacket)
		if dnsErr == nil {
			_ = dnsSensor.ObserveUDP(dnsPacket.FlowID, dnsPacket.Client.String(), packet.Timestamp, dnsPacket.Payload)
		}
		if quicObservation, quicErr := quicSensor.ObserveIP(ipPacket, packet.Timestamp); quicErr == nil && quicObservation != nil {
			destinationIP, destinationPort, _ := net.SplitHostPort(quicObservation.Destination)
			meta := recorder.Meta{
				ConnectionID:   quicObservation.FlowID,
				CapturePoint:   "QUIC_CLIENT_INITIAL",
				Direction:      "inbound",
				ByteSource:     "pcap_interface",
				HandshakeEvent: "QUIC_CLIENT_HELLO",
				Mode:           "PASSIVE",
				Destination:    quicObservation.Destination,
				DestinationIP:  destinationIP,
				Source:         "PASSIVE_QUIC_CAPTURE",
				IdentitySource: "quic_client_ip",
				IdentityValue:  quicObservation.ClientIP,
				Confidence:     "observed",
			}
			if port, parseErr := strconv.Atoi(destinationPort); parseErr == nil {
				meta.DestinationPort = port
			}
			output.TryCaptureQUIC(meta, quicObservation, packet.Timestamp)
		}
		if segment, tcpErr := dnscapture.ParseTCPPacket(ipPacket); tcpErr == nil {
			frames, streamErr := dnsTCP.Push(segment, packet.Timestamp)
			if streamErr == nil {
				for _, frame := range frames {
					_ = dnsSensor.ObserveTCPFrame(segment.FlowID, segment.Client.String(), packet.Timestamp, frame)
				}
			}
		}
		dnsSensor.Expire(packet.Timestamp)
		syn, err := tcpcapture.ParsePacket(ipPacket)
		if err != nil || syn == nil {
			continue
		}
		meta := tcpMeta(syn)
		output.TryCaptureTCPSYNAt(meta, syn, packet.Timestamp)
	}
}

func dnsConnectionID(flowID string) string {
	digest := sha256.Sum256([]byte(flowID))
	return "dns-" + hex.EncodeToString(digest[:12])
}

func tcpMeta(syn *tcpcapture.SYN) recorder.Meta {
	source := netip.AddrPortFrom(syn.Source, syn.SourcePort).String()
	destination := netip.AddrPortFrom(syn.Destination, syn.DestPort).String()
	flow := source + "|" + destination
	if destination < source {
		flow = destination + "|" + source
	}
	digest := sha256.Sum256([]byte(flow))
	connectionID := "tcp-syn-" + hex.EncodeToString(digest[:12])
	return recorder.Meta{
		ConnectionID:   connectionID,
		CapturePoint:   "CLIENT_TCP_SYN",
		Direction:      "inbound",
		ByteSource:     "pcap_interface",
		HandshakeEvent: "TCP_SYN",
		Mode:           "PASSIVE",
		Destination:    net.JoinHostPort(syn.Destination.String(), strconv.Itoa(int(syn.DestPort))),
		DestinationIP:  syn.Destination.String(), DestinationPort: int(syn.DestPort),
		Source: "PASSIVE_PACKET_CAPTURE", IdentitySource: "tcp_source_ip",
		IdentityValue: syn.Source.String(), Confidence: "observed",
	}
}

func OpenTCP(ctx context.Context, interfaceName string, output *recorder.Recorder) error {
	return OpenTCPWithCorrelator(ctx, interfaceName, output, nil)
}

func OpenTCPWithCorrelator(ctx context.Context, interfaceName string, output *recorder.Recorder, correlator *dnscapture.Correlator) error {
	source, err := pcap.OpenLive(interfaceName, 65535, 200)
	if err != nil {
		return fmt.Errorf("open passive TCP capture: %w", err)
	}
	return RunTCPWithCorrelator(ctx, source, output, correlator)
}
