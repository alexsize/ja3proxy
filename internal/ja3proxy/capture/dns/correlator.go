package dns

import (
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	TransportUDP = "udp"
	TransportTCP = "tcp"

	defaultMatchWindow = 5 * time.Second
	defaultAnswerTTL   = 24 * time.Hour
	defaultPendingMax  = 4096
	defaultHistoryMax  = 8192
)

var (
	ErrInvalidEvent = errors.New("invalid DNS correlation event")
	ErrPendingLimit = errors.New("DNS correlation pending limit reached")
)

type Event struct {
	FlowID    string
	ClientKey string
	Transport string
	Message   Message
	At        time.Time
}

type Exchange struct {
	FlowID     string          `json:"flow_id"`
	ClientKey  string          `json:"client_key"`
	Transport  string          `json:"transport"`
	ID         uint16          `json:"id"`
	Questions  []Question      `json:"questions"`
	Addresses  []AddressAnswer `json:"addresses,omitempty"`
	Aliases    []CNAMEAnswer   `json:"cname_answers,omitempty"`
	QueryAt    time.Time       `json:"query_at,omitempty"`
	ResponseAt time.Time       `json:"response_at,omitempty"`
	Status     string          `json:"status"`
}

type TLSCorrelation struct {
	Status     string   `json:"status"`
	Names      []string `json:"names,omitempty"`
	DNSFlowIDs []string `json:"dns_flow_ids,omitempty"`
}

type Config struct {
	MatchWindow  time.Duration
	MaxAnswerTTL time.Duration
	PendingMax   int
	HistoryMax   int
}

type Correlator struct {
	mu           sync.Mutex
	cfg          Config
	pending      map[string][]Event
	pendingCount int
	history      []Exchange
}

func NewCorrelator(config Config) *Correlator {
	if config.MatchWindow <= 0 {
		config.MatchWindow = defaultMatchWindow
	}
	if config.MaxAnswerTTL <= 0 {
		config.MaxAnswerTTL = defaultAnswerTTL
	}
	if config.PendingMax <= 0 {
		config.PendingMax = defaultPendingMax
	}
	if config.HistoryMax <= 0 {
		config.HistoryMax = defaultHistoryMax
	}
	return &Correlator{cfg: config, pending: make(map[string][]Event)}
}

// ObserveDNS pairs queries and responses using the normalized bidirectional
// flow ID, client key, transport, DNS transaction ID and question set. Events
// may arrive out of timestamp order. Ambiguous matches are never guessed.
func (c *Correlator) ObserveDNS(event Event) (*Exchange, error) {
	if c == nil || event.At.IsZero() || (event.Transport != TransportUDP && event.Transport != TransportTCP) || len(event.Message.Questions) == 0 || len(event.Message.Questions) > maxQuestions || len(event.Message.Addresses)+len(event.Message.Aliases) > maxRecords || event.Message.Opcode != 0 {
		return nil, ErrInvalidEvent
	}
	event.FlowID = strings.TrimSpace(event.FlowID)
	event.ClientKey = strings.TrimSpace(event.ClientKey)
	if event.FlowID == "" || event.ClientKey == "" || len(event.FlowID) > 256 || len(event.ClientKey) > 256 {
		return nil, ErrInvalidEvent
	}
	event = cloneEvent(event)
	for i := range event.Message.Questions {
		name := strings.TrimSuffix(strings.ToLower(event.Message.Questions[i].Name), ".")
		if name == "" {
			name = "."
		}
		if len(name) > 1024 {
			return nil, ErrInvalidEvent
		}
		event.Message.Questions[i].Name = name
	}
	for i := range event.Message.Addresses {
		event.Message.Addresses[i].Name = strings.TrimSuffix(strings.ToLower(event.Message.Addresses[i].Name), ".")
	}
	for i := range event.Message.Aliases {
		event.Message.Aliases[i].Name = normalizeDNSName(event.Message.Aliases[i].Name)
		event.Message.Aliases[i].Target = normalizeDNSName(event.Message.Aliases[i].Target)
	}
	for _, question := range event.Message.Questions {
		if !questionNameValid(question.Name) {
			return nil, ErrInvalidEvent
		}
	}
	for _, answer := range event.Message.Addresses {
		if !answer.Address.IsValid() {
			return nil, ErrInvalidEvent
		}
	}
	for _, alias := range event.Message.Aliases {
		if !questionNameValid(alias.Name) || !questionNameValid(alias.Target) {
			return nil, ErrInvalidEvent
		}
	}
	key := fmt.Sprintf("%s\x00%s\x00%s\x00%d\x00%s", event.ClientKey, event.FlowID, event.Transport, event.Message.ID, questionKey(event.Message.Questions))
	c.mu.Lock()
	defer c.mu.Unlock()
	opposite := c.pending[key]
	matches := make([]int, 0, 1)
	for i := range opposite {
		if opposite[i].Message.Response != event.Message.Response && absDuration(opposite[i].At.Sub(event.At)) <= c.cfg.MatchWindow {
			matches = append(matches, i)
		}
	}
	if len(matches) == 0 {
		if c.pendingCount >= c.cfg.PendingMax {
			return nil, ErrPendingLimit
		}
		c.pending[key] = append(opposite, cloneEvent(event))
		c.pendingCount++
		return nil, nil
	}
	status := "resolved"
	var peer Event
	if len(matches) == 1 {
		peer = opposite[matches[0]]
	} else {
		status = "ambiguous"
	}
	remove := make(map[int]bool, len(matches))
	for _, index := range matches {
		remove[index] = true
	}
	remaining := make([]Event, 0, len(opposite)-len(matches))
	for i, pending := range opposite {
		if !remove[i] {
			remaining = append(remaining, pending)
		} else {
			c.pendingCount--
		}
	}
	if len(remaining) == 0 {
		delete(c.pending, key)
	} else {
		c.pending[key] = remaining
	}
	query, response := event, peer
	if event.Message.Response && len(matches) == 1 {
		query, response = peer, event
	}
	result := Exchange{
		FlowID: event.FlowID, ClientKey: event.ClientKey, Transport: event.Transport,
		ID: event.Message.ID, Questions: append([]Question(nil), query.Message.Questions...),
		Status: status,
	}
	if status == "resolved" {
		result.QueryAt = query.At
		result.ResponseAt = response.At
		result.Addresses = append([]AddressAnswer(nil), response.Message.Addresses...)
		result.Aliases = append([]CNAMEAnswer(nil), response.Message.Aliases...)
		if response.Message.Truncated {
			result.Status = "truncated"
			result.Addresses = nil
			result.Aliases = nil
		} else if response.Message.RCode != 0 {
			result.Status = "dns_error"
			result.Addresses = nil
			result.Aliases = nil
		}
	} else if !event.Message.Response {
		result.QueryAt = event.At
	}
	c.rememberLocked(result)
	return &result, nil
}

func questionNameValid(name string) bool {
	if name == "." {
		return true
	}
	if name == "" || len(name) > 1024 {
		return false
	}
	for _, value := range name {
		if value < 0x21 || value > 0x7e {
			return false
		}
	}
	return true
}

// Expire returns pending queries/responses older than the configured matching
// window as explicit unmatched results. Call periodically to report loss.
func (c *Correlator) Expire(now time.Time) []Exchange {
	if c == nil || now.IsZero() {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	var expired []Exchange
	for key, events := range c.pending {
		remaining := events[:0]
		for _, event := range events {
			if now.Sub(event.At) <= c.cfg.MatchWindow {
				remaining = append(remaining, event)
				continue
			}
			c.pendingCount--
			status := "unmatched_query"
			if event.Message.Response {
				status = "unmatched_response"
			}
			result := Exchange{
				FlowID: event.FlowID, ClientKey: event.ClientKey, Transport: event.Transport,
				ID: event.Message.ID, Questions: append([]Question(nil), event.Message.Questions...),
				Status: status,
			}
			if event.Message.Response {
				result.ResponseAt = event.At
			} else {
				result.QueryAt = event.At
			}
			expired = append(expired, result)
			c.rememberLocked(result)
		}
		if len(remaining) == 0 {
			delete(c.pending, key)
		} else {
			c.pending[key] = remaining
		}
	}
	sort.Slice(expired, func(i, j int) bool {
		if expired[i].QueryAt.Equal(expired[j].QueryAt) {
			return expired[i].FlowID < expired[j].FlowID
		}
		return expired[i].QueryAt.Before(expired[j].QueryAt)
	})
	return expired
}

// CorrelateTLS checks a TLS destination against recent successful DNS A/AAAA
// answers and CNAME chains for the same client key. It returns ambiguous rather
// than guessing when multiple different query names resolve to that address.
func (c *Correlator) CorrelateTLS(clientKey string, destination netip.Addr, at time.Time) TLSCorrelation {
	result := TLSCorrelation{Status: "unmatched"}
	if c == nil || clientKey == "" || !destination.IsValid() || at.IsZero() {
		return result
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	type cnameEdge struct {
		target string
		flowID string
	}
	type addressRecord struct {
		address netip.Addr
		flowID  string
	}
	aliases := make(map[string][]cnameEdge)
	addresses := make(map[string][]addressRecord)
	anchors := make(map[string]map[string]struct{})
	cnameTargets := make(map[string]struct{})
	for _, exchange := range c.history {
		if exchange.ClientKey != clientKey || exchange.Status != "resolved" || exchange.ResponseAt.After(at) {
			continue
		}
		for _, question := range exchange.Questions {
			if at.Sub(exchange.ResponseAt) <= c.cfg.MaxAnswerTTL {
				if anchors[question.Name] == nil {
					anchors[question.Name] = make(map[string]struct{})
				}
				anchors[question.Name][exchange.FlowID] = struct{}{}
			}
		}
		for _, answer := range exchange.Addresses {
			if answer.TTL == 0 || !recordActive(exchange.ResponseAt, answer.TTL, at, c.cfg.MaxAnswerTTL) {
				continue
			}
			addresses[answer.Name] = append(addresses[answer.Name], addressRecord{address: answer.Address.Unmap(), flowID: exchange.FlowID})
		}
		for _, alias := range exchange.Aliases {
			if alias.TTL == 0 || !recordActive(exchange.ResponseAt, alias.TTL, at, c.cfg.MaxAnswerTTL) {
				continue
			}
			aliases[alias.Name] = append(aliases[alias.Name], cnameEdge{target: alias.Target, flowID: exchange.FlowID})
			cnameTargets[alias.Target] = struct{}{}
		}
	}
	if len(anchors) == 0 {
		return result
	}
	names := make(map[string]map[string]struct{})
	const maxCNAMEHops = 16
	for name, anchorFlows := range anchors {
		// A target name is an intermediate resolver lookup in a CNAME chain;
		// report its queried alias owner instead to avoid false ambiguity.
		if _, isIntermediate := cnameTargets[name]; isIntermediate {
			continue
		}
		pathFlows := make(map[string]struct{})
		for flowID := range anchorFlows {
			pathFlows[flowID] = struct{}{}
		}
		visited := make(map[string]struct{})
		var walk func(string, int)
		walk = func(current string, hops int) {
			if _, seen := visited[current]; seen {
				return
			}
			visited[current] = struct{}{}
			defer delete(visited, current)
			for _, record := range addresses[current] {
				if record.address == destination.Unmap() {
					if names[name] == nil {
						names[name] = make(map[string]struct{})
					}
					for flowID := range pathFlows {
						names[name][flowID] = struct{}{}
					}
					names[name][record.flowID] = struct{}{}
				}
			}
			if hops >= maxCNAMEHops {
				return
			}
			for _, edge := range aliases[current] {
				_, alreadyPresent := pathFlows[edge.flowID]
				pathFlows[edge.flowID] = struct{}{}
				walk(edge.target, hops+1)
				if !alreadyPresent {
					delete(pathFlows, edge.flowID)
				}
			}
		}
		walk(name, 0)
	}
	if len(names) == 0 {
		return result
	}
	for name, flows := range names {
		result.Names = append(result.Names, name)
		for flowID := range flows {
			result.DNSFlowIDs = append(result.DNSFlowIDs, flowID)
		}
	}
	sort.Strings(result.Names)
	sort.Strings(result.DNSFlowIDs)
	result.DNSFlowIDs = unique(result.DNSFlowIDs)
	if len(result.Names) > 1 {
		result.Status = "ambiguous"
	} else {
		result.Status = "matched"
	}
	return result
}

func (c *Correlator) rememberLocked(exchange Exchange) {
	if len(c.history) >= c.cfg.HistoryMax {
		copy(c.history, c.history[1:])
		c.history = c.history[:len(c.history)-1]
	}
	exchange.Questions = append([]Question(nil), exchange.Questions...)
	exchange.Addresses = append([]AddressAnswer(nil), exchange.Addresses...)
	exchange.Aliases = append([]CNAMEAnswer(nil), exchange.Aliases...)
	c.history = append(c.history, exchange)
}

func cloneEvent(event Event) Event {
	event.Message.Questions = append([]Question(nil), event.Message.Questions...)
	event.Message.Addresses = append([]AddressAnswer(nil), event.Message.Addresses...)
	event.Message.Aliases = append([]CNAMEAnswer(nil), event.Message.Aliases...)
	return event
}

func normalizeDNSName(name string) string {
	name = strings.TrimSuffix(strings.ToLower(name), ".")
	if name == "" {
		return "."
	}
	return name
}

func recordActive(responseAt time.Time, ttl uint32, at time.Time, maxTTL time.Duration) bool {
	seconds := uint64(ttl)
	maxSeconds := uint64(maxTTL / time.Second)
	ttlDuration := maxTTL
	if maxTTL >= time.Second && seconds <= maxSeconds {
		ttlDuration = time.Duration(seconds) * time.Second
	}
	return !at.After(responseAt.Add(ttlDuration))
}

func absDuration(value time.Duration) time.Duration {
	if value < 0 {
		return -value
	}
	return value
}

func unique(values []string) []string {
	if len(values) < 2 {
		return values
	}
	result := values[:1]
	for _, value := range values[1:] {
		if value != result[len(result)-1] {
			result = append(result, value)
		}
	}
	return result
}
