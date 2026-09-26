package dns

import (
	"net/netip"
	"time"
)

// Sensor joins parsed UDP/TCP DNS messages and exposes DNS-to-TLS correlation.
// A capture adapter supplies complete UDP payloads or complete framed TCP
// messages; it remains outside the proxy forwarding path.
type Sensor struct {
	correlator *Correlator
	onExchange func(Exchange)
}

func NewSensor(config Config, onExchange func(Exchange)) *Sensor {
	return &Sensor{correlator: NewCorrelator(config), onExchange: onExchange}
}

func NewSensorWithCorrelator(correlator *Correlator, onExchange func(Exchange)) *Sensor {
	if correlator == nil {
		correlator = NewCorrelator(Config{})
	}
	return &Sensor{correlator: correlator, onExchange: onExchange}
}

func (s *Sensor) ObserveUDP(flowID, clientKey string, at time.Time, payload []byte) error {
	message, err := ParseMessage(payload)
	if err != nil {
		return err
	}
	return s.observe(Event{FlowID: flowID, ClientKey: clientKey, Transport: TransportUDP, Message: message, At: at})
}

func (s *Sensor) ObserveTCPFrame(flowID, clientKey string, at time.Time, frame []byte) error {
	message, err := ParseTCPFrame(frame)
	if err != nil {
		return err
	}
	return s.observe(Event{FlowID: flowID, ClientKey: clientKey, Transport: TransportTCP, Message: message, At: at})
}

func (s *Sensor) ObserveTLS(clientKey string, destination netip.Addr, at time.Time) TLSCorrelation {
	if s == nil || s.correlator == nil {
		return TLSCorrelation{Status: "unmatched"}
	}
	return s.correlator.CorrelateTLS(clientKey, destination, at)
}

// Expire flushes timed-out DNS events as explicit unmatched exchanges.
func (s *Sensor) Expire(now time.Time) []Exchange {
	if s == nil || s.correlator == nil {
		return nil
	}
	expired := s.correlator.Expire(now)
	for _, exchange := range expired {
		s.emit(exchange)
	}
	return expired
}

func (s *Sensor) observe(event Event) error {
	if s == nil || s.correlator == nil {
		return ErrInvalidEvent
	}
	exchange, err := s.correlator.ObserveDNS(event)
	if err != nil {
		return err
	}
	if exchange != nil {
		s.emit(*exchange)
	}
	return nil
}

func (s *Sensor) emit(exchange Exchange) {
	if s.onExchange == nil {
		return
	}
	exchange.Questions = append([]Question(nil), exchange.Questions...)
	exchange.Addresses = append([]AddressAnswer(nil), exchange.Addresses...)
	exchange.Aliases = append([]CNAMEAnswer(nil), exchange.Aliases...)
	s.onExchange(exchange)
}
