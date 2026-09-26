// Package recorder provides an opt-in, bounded asynchronous TLS recorder.
package recorder

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"sync/atomic"
	"time"

	dnscapture "github.com/lylemi/ja3proxy/internal/ja3proxy/capture/dns"
	"github.com/lylemi/ja3proxy/internal/ja3proxy/capture/http1"
	http2capture "github.com/lylemi/ja3proxy/internal/ja3proxy/capture/http2"
	quiccapture "github.com/lylemi/ja3proxy/internal/ja3proxy/capture/quic"
	tcpcapture "github.com/lylemi/ja3proxy/internal/ja3proxy/capture/tcp"
	"github.com/lylemi/ja3proxy/internal/ja3proxy/capture/tlshello"
	"github.com/lylemi/ja3proxy/internal/ja3proxy/logutil"
	"github.com/lylemi/ja3proxy/internal/ja3proxy/secrets"
)

const (
	ObservationSchemaVersion = "tls-observation/2"
	CaptureVersion           = 1
	TLSEngineUTLSVersion     = "v1.8.2"
	InitialAnalysisRevision  = 1
	NegotiatedStateVersion   = "TLS-NEGOTIATED/2"
)

const (
	DeliveryClassCritical  = "CRITICAL"
	DeliveryClassImportant = "IMPORTANT"
	DeliveryClassOptional  = "OPTIONAL"
	defaultQueueSize       = 8192
	maxQueueSize           = 65536
	maxWriteBatchSize      = 1024
)

var (
	ErrObservationNotFound   = errors.New("observation not retained")
	ErrRawUnavailable        = errors.New("raw ClientHello is not retained")
	ErrReparseMalformed      = errors.New("stored raw ClientHello is malformed")
	ErrRecorderClosed        = errors.New("recorder is closed")
	ErrHistoricalUnavailable = errors.New("historical recorder storage is unavailable")
	ErrHistoricalCursor      = errors.New("historical observation cursor expired")
)

type Meta struct {
	ConnectionID            string                     `json:"connection_id"`
	DeliveryClass           string                     `json:"delivery_class,omitempty"`
	CapturePoint            string                     `json:"capture_point"`
	Direction               string                     `json:"direction"`
	ByteSource              string                     `json:"byte_source"`
	HandshakeEvent          string                     `json:"handshake_event,omitempty"`
	HandshakeSequence       int                        `json:"handshake_sequence,omitempty"`
	Mode                    string                     `json:"mode"`
	Destination             string                     `json:"destination"`
	DestinationHost         string                     `json:"destination_host,omitempty"`
	DestinationIP           string                     `json:"destination_ip,omitempty"`
	DestinationPort         int                        `json:"destination_port,omitempty"`
	ConnectHost             string                     `json:"connect_host,omitempty"`
	SNI                     string                     `json:"sni,omitempty"`
	AuthorityMismatch       bool                       `json:"authority_mismatch,omitempty"`
	Source                  string                     `json:"source"`
	IdentitySource          string                     `json:"identity_source,omitempty"`
	IdentityValue           string                     `json:"identity_value,omitempty"`
	Confidence              string                     `json:"confidence,omitempty"`
	DNSCorrelation          *dnscapture.TLSCorrelation `json:"dns_correlation,omitempty"`
	ResolvedDeviceID        string                     `json:"resolved_device_id,omitempty"`
	Application             string                     `json:"application,omitempty"`
	ApplicationVersion      string                     `json:"application_version,omitempty"`
	ApplicationID           string                     `json:"application_id,omitempty"`
	ApplicationAssignmentID string                     `json:"application_assignment_id,omitempty"`
	Profile                 string                     `json:"profile,omitempty"`
	ProfileType             string                     `json:"profile_type,omitempty"`
	ProfileID               string                     `json:"profile_id,omitempty"`
	ProfileVersion          uint64                     `json:"profile_version,omitempty"`
	ConfigVersion           uint64                     `json:"config_version,omitempty"`
	UpstreamConfigVersion   uint64                     `json:"upstream_config_version,omitempty"`
	MatchedRouteID          string                     `json:"matched_route_id,omitempty"`
	MatchedRoutePriority    *int                       `json:"matched_route_priority,omitempty"`
	RouteMatchReason        string                     `json:"route_match_reason,omitempty"`
	Routing                 *RoutingSnapshot           `json:"routing,omitempty"`
	RuntimeMutations        []RuntimeMutation          `json:"runtime_mutations,omitempty"`
	Expected                *FingerprintExpected       `json:"-"`
	Forwarded               *ForwardingExpected        `json:"-"`
}

// RoutingSnapshot records the immutable two-phase routing decisions used for
// one connection. It deliberately stores match evidence, not action payloads:
// route actions may contain proxy credentials and must never enter telemetry.
type RoutingSnapshot struct {
	PreTLS          *RouteDecision `json:"pre_tls,omitempty"`
	PostClientHello *RouteDecision `json:"post_clienthello,omitempty"`
}

type RouteDecision struct {
	// ConfigVersion is retained for compatibility with existing exports.
	ConfigVersion          uint64   `json:"config_version,omitempty"`
	EvaluatedConfigVersion uint64   `json:"evaluated_config_version,omitempty"`
	CandidateRuleIDs       []string `json:"candidate_rule_ids,omitempty"`
	MatchedRuleID          string   `json:"matched_rule_id,omitempty"`
	MatchedRulePriority    *int     `json:"matched_rule_priority,omitempty"`
	MatchReason            string   `json:"match_reason,omitempty"`
	ActionMode             string   `json:"action_mode,omitempty"`
	MatchPolicy            string   `json:"match_policy,omitempty"`
	CaptureFailurePolicy   string   `json:"capture_failure_policy,omitempty"`
}

type RuntimeMutation struct {
	Type   string   `json:"type"`
	Field  string   `json:"field"`
	Before []string `json:"before"`
	After  []string `json:"after"`
	Reason string   `json:"reason"`
}

type ForwardingExpected struct {
	Completeness  string
	RawSHA256     string
	RecordsSHA256 string
}

type ForwardingVerification struct {
	Status                string `json:"status"`
	Reason                string `json:"reason,omitempty"`
	InboundRawSHA256      string `json:"inbound_raw_sha256,omitempty"`
	OutboundRawSHA256     string `json:"outbound_raw_sha256,omitempty"`
	InboundRecordsSHA256  string `json:"inbound_records_sha256,omitempty"`
	OutboundRecordsSHA256 string `json:"outbound_records_sha256,omitempty"`
}

type FingerprintExpected struct {
	ProfileSchemaVersion string                  `json:"profile_schema_version"`
	JA3                  string                  `json:"ja3"`
	JA3Hash              string                  `json:"ja3_hash"`
	JA4                  string                  `json:"ja4"`
	NormalizedSHA256     string                  `json:"normalized_sha256"`
	Normalized           json.RawMessage         `json:"normalized"`
	NormalizationVersion string                  `json:"normalization_version"`
	MaterializerVersion  string                  `json:"materializer_version"`
	MustMatch            []string                `json:"must_match"`
	ShouldMatch          []string                `json:"should_match"`
	IgnoredDynamic       []string                `json:"ignored_dynamic"`
	Constraints          []FingerprintConstraint `json:"constraints"`
}

type FingerprintConstraint struct {
	Path     string            `json:"path"`
	Operator string            `json:"operator"`
	Value    json.RawMessage   `json:"value,omitempty"`
	Values   []json.RawMessage `json:"values,omitempty"`
}

// NegotiatedState records metadata obtained after a TLS handshake that this
// proxy terminated itself. It intentionally contains no key material, peer
// certificates or ALPS bytes.
type NegotiatedState struct {
	ProtocolVersion             uint16 `json:"protocol_version"`
	CipherSuite                 uint16 `json:"cipher_suite"`
	NegotiatedProtocol          string `json:"negotiated_protocol,omitempty"`
	ServerName                  string `json:"server_name,omitempty"`
	HandshakeType               string `json:"handshake_type,omitempty"`
	SessionResumption           bool   `json:"session_resumption"`
	HandshakeComplete           bool   `json:"handshake_complete"`
	PeerApplicationSettingsSize int    `json:"peer_application_settings_size,omitempty"`
}

type Verification struct {
	SchemaVersion          string              `json:"schema_version"`
	Status                 string              `json:"status"`
	Reason                 string              `json:"reason,omitempty"`
	MismatchedMustMatch    []string            `json:"mismatched_must_match,omitempty"`
	MismatchedShouldMatch  []string            `json:"mismatched_should_match,omitempty"`
	ViolatedConstraints    []string            `json:"violated_constraints,omitempty"`
	Expected               FingerprintExpected `json:"expected"`
	ActualJA3              string              `json:"actual_ja3,omitempty"`
	ActualJA3Hash          string              `json:"actual_ja3_hash,omitempty"`
	ActualJA4              string              `json:"actual_ja4,omitempty"`
	ActualNormalizedSHA256 string              `json:"actual_normalized_sha256,omitempty"`
	DiffAlgorithmVersion   string              `json:"diff_algorithm_version"`
	Changes                []Change            `json:"changes"`
}

type Observation struct {
	SchemaVersion    string `json:"schema_version"`
	CaptureVersion   int    `json:"capture_version"`
	ParserVersion    string `json:"parser_version"`
	JA3Version       string `json:"ja3_version"`
	JA4Version       string `json:"ja4_version"`
	TLSNormVersion   string `json:"tls_norm_version"`
	TLSEngine        string `json:"tls_engine"`
	TLSEngineVersion string `json:"tls_engine_version"`
	AnalysisRevision int    `json:"analysis_revision"`
	AnalysisParentID string `json:"analysis_parent_id,omitempty"`
	ID               string `json:"id"`
	Meta
	CapturedAt              time.Time                    `json:"captured_at"`
	PersistedAt             time.Time                    `json:"processed_at"`
	Completeness            string                       `json:"completeness"`
	ErrorStage              string                       `json:"error_stage,omitempty"`
	ErrorCode               string                       `json:"error_code,omitempty"`
	RecordVersion           uint16                       `json:"record_version"`
	RecordCount             int                          `json:"record_count"`
	DeclaredHelloLength     int                          `json:"declared_hello_length,omitempty"`
	Hello                   *tlshello.Hello              `json:"decoded,omitempty"`
	Fingerprints            *tlshello.Fingerprints       `json:"fingerprints,omitempty"`
	ServerHello             *tlshello.ServerHello        `json:"server_hello,omitempty"`
	ServerFingerprints      *tlshello.ServerFingerprints `json:"server_fingerprints,omitempty"`
	NegotiatedState         *NegotiatedState             `json:"negotiated_state,omitempty"`
	HTTP1                   *http1.Message               `json:"http1,omitempty"`
	HTTP2                   *http2capture.Fingerprint    `json:"http2,omitempty"`
	TCPSYN                  *tcpcapture.SYN              `json:"tcp_syn,omitempty"`
	DNS                     *dnscapture.Exchange         `json:"dns,omitempty"`
	QUIC                    *quiccapture.Metadata        `json:"quic,omitempty"`
	Verification            *Verification                `json:"verification,omitempty"`
	Forwarding              *ForwardingVerification      `json:"forwarding,omitempty"`
	Raw                     []byte                       `json:"raw_client_hello,omitempty"`
	RawClientHelloAvailable bool                         `json:"raw_client_hello_available,omitempty"`
	Records                 []byte                       `json:"raw_records,omitempty"`
	RawServerHello          []byte                       `json:"raw_server_hello,omitempty"`
	ServerRecords           []byte                       `json:"server_records,omitempty"`
}

type Options struct {
	QueueSize         int
	CriticalQueueSize int
	RecentLimit       int
	MemoryBytes       int
	Raw               bool
	JSONLPath         string
	MaxFileBytes      int64
	SQLitePath        string
	SQLiteRetention   int
	SpoolPath         string
	SpoolKeyPath      string
	SpoolMaxBytes     int64
	SpoolKeyMaxAge    time.Duration
	SecretProvider    secrets.Provider
}

// StoredQuery describes a bounded page over durable SQLite observations.
// Cursor order is newest-first and remains stable while retention is unchanged.
type StoredQuery struct {
	Limit              int
	Cursor             string
	AnalysisRevision   int
	Search             string
	DeviceID           string
	Application        string
	ApplicationID      string
	ApplicationVersion string
	From               *time.Time
	To                 *time.Time
}

type StoredPage struct {
	Items      []Observation
	NextCursor string
}

func (r *Recorder) QueryStored(query StoredQuery) (StoredPage, error) {
	if r == nil || r.store == nil {
		return StoredPage{}, ErrHistoricalUnavailable
	}
	return r.store.query(query)
}

func (r *Recorder) Stored(id string) (Observation, error) {
	if r == nil || r.store == nil {
		return Observation{}, ErrHistoricalUnavailable
	}
	return r.store.get(id)
}

type ReparsePageResult struct {
	Scanned    int    `json:"scanned"`
	Reparsed   int    `json:"reparsed"`
	Skipped    int    `json:"skipped"`
	Failed     int    `json:"failed"`
	NextCursor string `json:"next_cursor,omitempty"`
}

type queued struct {
	meta             Meta
	capture          tlshello.Capture
	server           bool
	negotiated       *NegotiatedState
	http1            *http1.Message
	http2            *http2capture.Fingerprint
	tcpSYN           *tcpcapture.SYN
	dns              *dnscapture.Exchange
	quic             *quiccapture.Observation
	serverExtensions *tlshello.EncryptedExtensionsCapture
	at               time.Time
}

type persistedObservation struct {
	observation Observation
	payload     []byte
}

type Stats struct {
	Accepted              uint64            `json:"accepted"`
	Processed             uint64            `json:"processed"`
	Dropped               uint64            `json:"dropped"`
	WriteErrors           uint64            `json:"write_errors"`
	QueueDepth            int               `json:"queue_depth"`
	CriticalQueueDepth    int               `json:"critical_queue_depth"`
	CriticalSpillAccepted uint64            `json:"critical_spill_accepted"`
	Recent                int               `json:"recent"`
	MemoryBytes           int               `json:"memory_bytes"`
	RecordingDegraded     bool              `json:"recording_degraded"`
	DroppedByClass        map[string]uint64 `json:"dropped_by_class"`
	LostByClass           map[string]uint64 `json:"lost_by_class"`
	SpoolBytes            int64             `json:"spool_bytes"`
	SpoolEvents           int               `json:"spool_events"`
	SpoolQuarantined      uint64            `json:"spool_quarantined"`
	SpoolQuotaFailures    uint64            `json:"spool_quota_failures"`
	SpoolKeyStatus        string            `json:"spool_key_status,omitempty"`
	SpoolKeyActivatedAt   *time.Time        `json:"spool_key_activated_at,omitempty"`
	SpoolKeyExpiresAt     *time.Time        `json:"spool_key_expires_at,omitempty"`
}

type Recorder struct {
	opts                  Options
	queue                 chan queued
	criticalQueue         chan queued
	done                  chan struct{}
	sendMu                sync.RWMutex
	closed                bool
	mu                    sync.RWMutex
	recent                [][]byte
	memory                int
	file                  *os.File
	fileMu                sync.Mutex
	fileBytes             int64
	exportFailed          bool
	store                 *sqliteStore
	spool                 *spoolStore
	accepted              atomic.Uint64
	processed             atomic.Uint64
	dropped               atomic.Uint64
	droppedCritical       atomic.Uint64
	droppedImportant      atomic.Uint64
	droppedOptional       atomic.Uint64
	lostCritical          atomic.Uint64
	lostImportant         atomic.Uint64
	lostOptional          atomic.Uint64
	writeErrors           atomic.Uint64
	spoolQuotaFailures    atomic.Uint64
	spoolFullReported     atomic.Bool
	criticalSpillAccepted atomic.Uint64
}

// ReloadSpoolKey applies a newly published key only when the durable spool is
// empty. Append and key replacement share the spool lock.
func (r *Recorder) ReloadSpoolKey() error {
	if r == nil || r.spool == nil {
		return ErrSpoolUnavailable
	}
	r.sendMu.RLock()
	defer r.sendMu.RUnlock()
	if r.closed {
		return ErrSpoolUnavailable
	}
	return r.spool.rotateKey(r.opts.SpoolKeyPath, r.opts.SecretProvider)
}

func New(opts Options) (*Recorder, error) {
	if opts.QueueSize == 0 {
		opts.QueueSize = defaultQueueSize
	}
	if opts.CriticalQueueSize == 0 {
		opts.CriticalQueueSize = opts.QueueSize
	}
	if opts.RecentLimit == 0 {
		opts.RecentLimit = 256
	}
	if opts.MemoryBytes == 0 {
		opts.MemoryBytes = 32 << 20
	}
	if opts.MaxFileBytes == 0 {
		opts.MaxFileBytes = 256 << 20
	}
	if opts.QueueSize < 1 || opts.QueueSize > maxQueueSize || opts.CriticalQueueSize < 1 || opts.CriticalQueueSize > maxQueueSize || opts.RecentLimit < 1 || opts.RecentLimit > 10000 || opts.MemoryBytes < 1024 || opts.MemoryBytes > 256<<20 || opts.MaxFileBytes < 1 {
		return nil, errors.New("invalid recorder limits")
	}
	r := &Recorder{opts: opts, queue: make(chan queued, opts.QueueSize), criticalQueue: make(chan queued, opts.CriticalQueueSize), done: make(chan struct{})}
	if opts.SpoolPath != "" || opts.SpoolKeyPath != "" {
		spool, err := openSpoolWithPolicy(opts.SpoolPath, opts.SpoolKeyPath, opts.SpoolMaxBytes, opts.SecretProvider, opts.SpoolKeyMaxAge)
		if err != nil {
			return nil, err
		}
		r.spool = spool
	}
	if opts.JSONLPath != "" {
		// Never overwrite previous evidence. Raw output requires explicit opt-in.
		f, err := os.OpenFile(opts.JSONLPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			return nil, err
		}
		r.file = f
	}
	if opts.SQLitePath != "" {
		store, err := openSQLiteStore(opts.SQLitePath, opts.SQLiteRetention)
		if err != nil {
			if r.file != nil {
				_ = r.file.Close()
			}
			return nil, err
		}
		r.store = store
		if r.spool != nil {
			if err := r.spool.replay(func(eventID string, payload []byte) error {
				var observation Observation
				if err := json.Unmarshal(payload, &observation); err != nil || observation.ID != eventID {
					return errors.New("invalid recorder spool observation")
				}
				return store.insert(observation, payload)
			}); err != nil {
				_ = store.close()
				if r.file != nil {
					_ = r.file.Close()
				}
				return nil, err
			}
		}
		if data, err := store.recent(opts.RecentLimit); err != nil {
			_ = store.close()
			if r.file != nil {
				_ = r.file.Close()
			}
			return nil, err
		} else {
			for _, item := range data {
				r.remember(item)
			}
		}
	}
	go r.run()
	return r, nil
}

// NewID returns a Crockford-base32 ULID with random entropy and millisecond UTC
// timestamp. IDs need not be strictly monotonic within a millisecond.
func NewID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	ms := uint64(time.Now().UnixMilli())
	for i := 5; i >= 0; i-- {
		b[i] = byte(ms)
		ms >>= 8
	}
	const alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
	var out [26]byte
	for i := range out {
		v := 0
		for j := 0; j < 5; j++ {
			bit := i*5 + j - 2
			v <<= 1
			if bit >= 0 {
				v |= int((b[bit/8] >> uint(7-bit%8)) & 1)
			}
		}
		out[i] = alphabet[v]
	}
	return string(out[:])
}

// TryCapture transfers ownership of capture buffers. It never waits for queue
// space, disk or parsing. The caller must not mutate the capture afterwards.
func (r *Recorder) TryCapture(meta Meta, capture tlshello.Capture) bool {
	if r == nil {
		return false
	}
	meta.DeliveryClass = normalizeDeliveryClass(meta.DeliveryClass)
	r.sendMu.RLock()
	defer r.sendMu.RUnlock()
	if r.closed {
		r.recordDrop(meta)
		return false
	}
	queued := queued{meta: meta, capture: capture, at: time.Now().UTC()}
	select {
	case r.queue <- queued:
		r.accepted.Add(1)
		return true
	default:
		if normalizeDeliveryClass(meta.DeliveryClass) == DeliveryClassCritical {
			select {
			case r.criticalQueue <- queued:
				r.accepted.Add(1)
				r.criticalSpillAccepted.Add(1)
				return true
			default:
			}
		}
		r.recordDrop(meta)
		return false
	}
}

// TryCaptureServer queues a bounded SERVER_IN ServerHello capture. It shares
// the recorder's non-blocking backpressure behavior with ClientHello events.
func (r *Recorder) TryCaptureServer(meta Meta, capture tlshello.Capture) bool {
	return r.tryCaptureServer(meta, capture, nil)
}

func (r *Recorder) TryCaptureServerWithEncryptedExtensions(meta Meta, capture tlshello.Capture, extensions tlshello.EncryptedExtensionsCapture) bool {
	copyExtensions := extensions
	copyExtensions.Extensions.Extensions.Value = append([]tlshello.ServerExtension(nil), extensions.Extensions.Extensions.Value...)
	return r.tryCaptureServer(meta, capture, &copyExtensions)
}

func (r *Recorder) tryCaptureServer(meta Meta, capture tlshello.Capture, extensions *tlshello.EncryptedExtensionsCapture) bool {
	if r == nil {
		return false
	}
	meta.DeliveryClass = normalizeDeliveryClass(meta.DeliveryClass)
	r.sendMu.RLock()
	defer r.sendMu.RUnlock()
	if r.closed {
		r.recordDrop(meta)
		return false
	}
	queued := queued{meta: meta, capture: capture, server: true, serverExtensions: extensions, at: time.Now().UTC()}
	select {
	case r.queue <- queued:
		r.accepted.Add(1)
		return true
	default:
		if normalizeDeliveryClass(meta.DeliveryClass) == DeliveryClassCritical {
			select {
			case r.criticalQueue <- queued:
				r.accepted.Add(1)
				r.criticalSpillAccepted.Add(1)
				return true
			default:
			}
		}
		r.recordDrop(meta)
		return false
	}
}

// TryCaptureNegotiated queues state learned from a TLS handshake terminated by
// this proxy. It uses the same bounded, non-blocking delivery semantics as
// wire captures, but never stores raw handshake bytes.
func (r *Recorder) TryCaptureNegotiated(meta Meta, state NegotiatedState) bool {
	if r == nil {
		return false
	}
	// Expected/Forwarded belong to byte-level ClientHello/PROXY_OUT
	// verification and do not apply to this metadata-only event.
	meta.Expected = nil
	meta.Forwarded = nil
	meta.DeliveryClass = normalizeDeliveryClass(meta.DeliveryClass)
	r.sendMu.RLock()
	defer r.sendMu.RUnlock()
	if r.closed {
		r.recordDrop(meta)
		return false
	}
	queued := queued{
		meta: meta, capture: tlshello.Capture{Status: "complete"},
		negotiated: &state, at: time.Now().UTC(),
	}
	select {
	case r.queue <- queued:
		r.accepted.Add(1)
		return true
	default:
		if normalizeDeliveryClass(meta.DeliveryClass) == DeliveryClassCritical {
			select {
			case r.criticalQueue <- queued:
				r.accepted.Add(1)
				r.criticalSpillAccepted.Add(1)
				return true
			default:
			}
		}
		r.recordDrop(meta)
		return false
	}
}

// TryCaptureHTTP1 queues a privacy-safe HTTP/1 observation. Header values are
// hashed; only bounded, explicitly unverified User-Agent version claims remain.
func (r *Recorder) TryCaptureHTTP1(meta Meta, message http1.Message) bool {
	if r == nil {
		return false
	}
	meta.Expected = nil
	meta.Forwarded = nil
	meta.DeliveryClass = normalizeDeliveryClass(meta.DeliveryClass)
	r.sendMu.RLock()
	defer r.sendMu.RUnlock()
	if r.closed {
		r.recordDrop(meta)
		return false
	}
	status := message.Completeness
	if status == "" {
		status = "complete"
	}
	queued := queued{meta: meta, capture: tlshello.Capture{Status: status}, http1: &message, at: time.Now().UTC()}
	select {
	case r.queue <- queued:
		r.accepted.Add(1)
		return true
	default:
		if normalizeDeliveryClass(meta.DeliveryClass) == DeliveryClassCritical {
			select {
			case r.criticalQueue <- queued:
				r.accepted.Add(1)
				r.criticalSpillAccepted.Add(1)
				return true
			default:
			}
		}
		r.recordDrop(meta)
		return false
	}
}

// TryCaptureHTTP2 queues bounded HTTP/2 transport metadata. It never stores
// frame payloads or decoded header values.
func (r *Recorder) TryCaptureHTTP2(meta Meta, fingerprint http2capture.Fingerprint) bool {
	if r == nil {
		return false
	}
	meta.Expected = nil
	meta.Forwarded = nil
	meta.DeliveryClass = normalizeDeliveryClass(meta.DeliveryClass)
	r.sendMu.RLock()
	defer r.sendMu.RUnlock()
	if r.closed {
		r.recordDrop(meta)
		return false
	}
	status := fingerprint.Completeness
	if status == "" {
		status = "complete"
	}
	queued := queued{meta: meta, capture: tlshello.Capture{Status: status}, http2: &fingerprint, at: time.Now().UTC()}
	select {
	case r.queue <- queued:
		r.accepted.Add(1)
		return true
	default:
		if normalizeDeliveryClass(meta.DeliveryClass) == DeliveryClassCritical {
			select {
			case r.criticalQueue <- queued:
				r.accepted.Add(1)
				r.criticalSpillAccepted.Add(1)
				return true
			default:
			}
		}
		r.recordDrop(meta)
		return false
	}
}

// TryCaptureTCPSYN queues header-only TCP SYN metadata from an external,
// passive packet source. It never retains the packet bytes or feeds forwarding.
func (r *Recorder) TryCaptureTCPSYN(meta Meta, syn *tcpcapture.SYN) bool {
	return r.TryCaptureTCPSYNAt(meta, syn, time.Now().UTC())
}

// TryCaptureTCPSYNAt preserves the packet timestamp from a passive source.
func (r *Recorder) TryCaptureTCPSYNAt(meta Meta, syn *tcpcapture.SYN, capturedAt time.Time) bool {
	if r == nil || syn == nil {
		return false
	}
	if capturedAt.IsZero() {
		capturedAt = time.Now().UTC()
	}
	meta.Expected = nil
	meta.Forwarded = nil
	meta.DeliveryClass = normalizeDeliveryClass(meta.DeliveryClass)
	copySYN := *syn
	copySYN.OptionKinds = append([]uint8(nil), syn.OptionKinds...)
	if syn.MSS != nil {
		value := *syn.MSS
		copySYN.MSS = &value
	}
	if syn.WindowScale != nil {
		value := *syn.WindowScale
		copySYN.WindowScale = &value
	}
	r.sendMu.RLock()
	defer r.sendMu.RUnlock()
	if r.closed {
		r.recordDrop(meta)
		return false
	}
	queued := queued{
		meta: meta, capture: tlshello.Capture{Status: "complete"},
		tcpSYN: &copySYN, at: capturedAt.UTC(),
	}
	select {
	case r.queue <- queued:
		r.accepted.Add(1)
		return true
	default:
		if normalizeDeliveryClass(meta.DeliveryClass) == DeliveryClassCritical {
			select {
			case r.criticalQueue <- queued:
				r.accepted.Add(1)
				r.criticalSpillAccepted.Add(1)
				return true
			default:
			}
		}
		r.recordDrop(meta)
		return false
	}
}

// TryCaptureDNSExchange queues parsed DNS query/response metadata. Raw DNS
// packets and unrecognized resource data are not retained.
func (r *Recorder) TryCaptureDNSExchange(meta Meta, exchange *dnscapture.Exchange) bool {
	if r == nil || exchange == nil {
		return false
	}
	meta.Expected = nil
	meta.Forwarded = nil
	meta.DeliveryClass = normalizeDeliveryClass(meta.DeliveryClass)
	copyExchange := *exchange
	copyExchange.Questions = append([]dnscapture.Question(nil), exchange.Questions...)
	copyExchange.Addresses = append([]dnscapture.AddressAnswer(nil), exchange.Addresses...)
	copyExchange.Aliases = append([]dnscapture.CNAMEAnswer(nil), exchange.Aliases...)
	status := "partial"
	if exchange.Status == "resolved" {
		status = "complete"
	}
	r.sendMu.RLock()
	defer r.sendMu.RUnlock()
	if r.closed {
		r.recordDrop(meta)
		return false
	}
	capturedAt := exchange.ResponseAt
	if capturedAt.IsZero() {
		capturedAt = exchange.QueryAt
	}
	if capturedAt.IsZero() {
		capturedAt = time.Now().UTC()
	}
	queued := queued{meta: meta, capture: tlshello.Capture{Status: status}, dns: &copyExchange, at: capturedAt.UTC()}
	select {
	case r.queue <- queued:
		r.accepted.Add(1)
		return true
	default:
		if normalizeDeliveryClass(meta.DeliveryClass) == DeliveryClassCritical {
			select {
			case r.criticalQueue <- queued:
				r.accepted.Add(1)
				r.criticalSpillAccepted.Add(1)
				return true
			default:
			}
		}
		r.recordDrop(meta)
		return false
	}
}

// TryCaptureQUIC queues a successfully decrypted QUIC client Initial
// observation. It never retains packet or ClientHello bytes.
func (r *Recorder) TryCaptureQUIC(meta Meta, observation *quiccapture.Observation, capturedAt time.Time) bool {
	if r == nil || observation == nil || observation.Hello == nil || capturedAt.IsZero() {
		return false
	}
	meta.Expected = nil
	meta.Forwarded = nil
	meta.DeliveryClass = normalizeDeliveryClass(meta.DeliveryClass)
	copyObservation := *observation
	copyObservation.TransportParameters = append([]quiccapture.TransportParameter(nil), observation.TransportParameters...)
	for i := range copyObservation.TransportParameters {
		if value := observation.TransportParameters[i].Value; value != nil {
			cloned := *value
			copyObservation.TransportParameters[i].Value = &cloned
		}
	}
	helloJSON, err := json.Marshal(observation.Hello)
	if err != nil {
		return false
	}
	var copiedHello tlshello.Hello
	if err := json.Unmarshal(helloJSON, &copiedHello); err != nil {
		return false
	}
	copyObservation.Hello = &copiedHello
	r.sendMu.RLock()
	defer r.sendMu.RUnlock()
	if r.closed {
		r.recordDrop(meta)
		return false
	}
	queued := queued{meta: meta, capture: tlshello.Capture{Status: "complete"}, quic: &copyObservation, at: capturedAt.UTC()}
	select {
	case r.queue <- queued:
		r.accepted.Add(1)
		return true
	default:
		if normalizeDeliveryClass(meta.DeliveryClass) == DeliveryClassCritical {
			select {
			case r.criticalQueue <- queued:
				r.accepted.Add(1)
				r.criticalSpillAccepted.Add(1)
				return true
			default:
			}
		}
		r.recordDrop(meta)
		return false
	}
}

func (r *Recorder) run() {
	defer close(r.done)
	defer func() {
		if r.file != nil {
			r.fileMu.Lock()
			if err := r.file.Close(); err != nil {
				r.writeErrors.Add(1)
			}
			r.fileMu.Unlock()
		}
		if r.store != nil {
			if err := r.store.close(); err != nil {
				r.writeErrors.Add(1)
			}
		}
	}()
	primary, critical := r.queue, r.criticalQueue
	for primary != nil || critical != nil {
		var q queued
		var ok bool
		select {
		case q, ok = <-primary:
			if !ok {
				primary = nil
				continue
			}
		case q, ok = <-critical:
			if !ok {
				critical = nil
				continue
			}
		}
		batch := make([]queued, 1, maxWriteBatchSize)
		batch[0] = q
	drain:
		for len(batch) < cap(batch) {
			select {
			case next, ok := <-primary:
				if !ok {
					primary = nil
					continue
				}
				batch = append(batch, next)
			case next, ok := <-critical:
				if !ok {
					critical = nil
					continue
				}
				batch = append(batch, next)
			default:
				break drain
			}
		}
		persisted := make([]persistedObservation, 0, len(batch))
		for _, item := range batch {
			o, data, ok := r.makeObservation(item)
			if !ok {
				r.recordDrop(item.meta)
				continue
			}
			r.writeJSONL(data)
			r.remember(data)
			persisted = append(persisted, persistedObservation{observation: o, payload: data})
		}
		r.persistBatch(persisted)
		r.processed.Add(uint64(len(persisted)))
	}
}

func (r *Recorder) makeObservation(q queued) (Observation, []byte, bool) {
	c := q.capture
	engine, engineVersion := observationTLSEngine(q.meta)
	o := Observation{
		SchemaVersion: ObservationSchemaVersion, CaptureVersion: CaptureVersion,
		ParserVersion: tlshello.ParserVersion, JA3Version: tlshello.JA3Version,
		JA4Version: tlshello.JA4Version, TLSNormVersion: tlshello.NormalizationVersion,
		TLSEngine: engine, TLSEngineVersion: engineVersion,
		AnalysisRevision: InitialAnalysisRevision,
		ID:               NewID(), Meta: q.meta, CapturedAt: q.at, PersistedAt: time.Now().UTC(),
		Completeness: c.Status, ErrorStage: c.ErrorStage, ErrorCode: c.ErrorCode, RecordVersion: c.RecordVersion,
		RecordCount: c.RecordCount, DeclaredHelloLength: c.DeclaredHelloLength, RawClientHelloAvailable: len(c.Raw) > 0,
	}
	if o.HandshakeSequence == 0 && c.HandshakeSequence > 0 {
		o.HandshakeSequence = c.HandshakeSequence
	}
	if o.ErrorCode != "" && o.ErrorStage == "" {
		o.ErrorStage = "capture"
	}
	if q.dns != nil {
		o.ParserVersion = dnscapture.NormalizationVersion
		o.JA3Version, o.JA4Version, o.TLSNormVersion = "", "", ""
		o.DNS = q.dns
	} else if q.quic != nil {
		o.ParserVersion = quiccapture.NormalizationVersion
		o.JA3Version, o.JA4Version, o.TLSNormVersion = "", "", ""
		o.QUIC = &q.quic.Metadata
		o.Hello = q.quic.Hello
	} else if q.tcpSYN != nil {
		o.ParserVersion = tcpcapture.NormalizationVersion
		o.JA3Version, o.JA4Version, o.TLSNormVersion = "", "", ""
		o.TCPSYN = q.tcpSYN
	} else if q.http2 != nil {
		o.ParserVersion = http2capture.NormalizationVersion
		o.JA3Version, o.JA4Version, o.TLSNormVersion = "", "", ""
		o.HTTP2 = q.http2
	} else if q.http1 != nil {
		o.ParserVersion = http1.NormalizationVersion
		o.JA3Version, o.JA4Version, o.TLSNormVersion = "", "", ""
		o.HTTP1 = q.http1
	} else if q.negotiated != nil {
		o.ParserVersion = NegotiatedStateVersion
		o.JA3Version, o.JA4Version, o.TLSNormVersion = "", "", ""
		o.NegotiatedState = q.negotiated
	} else if q.server {
		o.ParserVersion = tlshello.JA3SVersion
		o.JA3Version, o.JA4Version = "", ""
		if c.Status == "complete" {
			hello, err := tlshello.ParseServerHello(c.Raw)
			if err != nil {
				o.Completeness, o.ErrorStage, o.ErrorCode = "malformed", "parse", "malformed_server_hello"
			} else {
				if q.serverExtensions != nil {
					if q.serverExtensions.Status == "complete" {
						hello.Fields.EncryptedExtensions = q.serverExtensions.Extensions.Extensions
						hello.Fields.SelectedALPN = q.serverExtensions.Extensions.SelectedALPN
					} else if q.serverExtensions.Reason != "" {
						reason := q.serverExtensions.Reason
						hello.Fields.EncryptedExtensions = tlshello.ServerField[[]tlshello.ServerExtension]{Source: "decrypted_encrypted_extensions", Available: false, Reason: reason}
						if !hello.Fields.SelectedALPN.Available {
							hello.Fields.SelectedALPN.Source = "decrypted_encrypted_extensions"
							hello.Fields.SelectedALPN.Reason = reason
						}
					}
				}
				fingerprints, fingerprintErr := tlshello.CalculateServerFingerprints(&hello)
				if fingerprintErr != nil {
					o.ErrorStage, o.ErrorCode = "fingerprint", "calculation_failed"
				} else {
					o.ServerHello, o.ServerFingerprints = &hello, &fingerprints
				}
			}
		}
	} else if c.Status == "complete" {
		h, err := tlshello.Parse(c.Raw)
		if err != nil {
			o.Completeness, o.ErrorStage, o.ErrorCode = "malformed", "parse", "malformed_client_hello"
		} else if fp, fingerprintErr := tlshello.Calculate(h, c.Raw, c.Records); fingerprintErr != nil {
			o.ErrorStage, o.ErrorCode = "fingerprint", "calculation_failed"
		} else {
			o.Hello, o.Fingerprints = h, &fp
		}
	}
	if q.meta.Expected != nil {
		o.Verification = VerifyExpected(*q.meta.Expected, o)
	}
	if q.meta.Forwarded != nil {
		o.Forwarding = VerifyForwarding(*q.meta.Forwarded, c)
	}
	if r.opts.Raw && q.dns == nil && q.tcpSYN == nil && q.http2 == nil && q.http1 == nil && q.negotiated == nil {
		if q.server {
			o.RawServerHello, o.ServerRecords = c.Raw, c.Records
		} else {
			o.Raw, o.Records = c.Raw, c.Records
		}
	}
	data, err := json.Marshal(o)
	return o, data, err == nil
}

func observationTLSEngine(meta Meta) (string, string) {
	if meta.Mode == "MITM_REISSUE" && (meta.CapturePoint == "PROXY_OUT" || meta.HandshakeEvent == "NEGOTIATED_STATE") {
		return "utls", TLSEngineUTLSVersion
	}
	return "external", "unknown"
}

func normalizeDeliveryClass(class string) string {
	switch class {
	case DeliveryClassImportant:
		return DeliveryClassImportant
	case DeliveryClassOptional:
		return DeliveryClassOptional
	default:
		return DeliveryClassCritical
	}
}

func (r *Recorder) recordDrop(meta Meta) {
	if r == nil {
		return
	}
	r.dropped.Add(1)
	switch normalizeDeliveryClass(meta.DeliveryClass) {
	case DeliveryClassImportant:
		r.droppedImportant.Add(1)
	case DeliveryClassOptional:
		r.droppedOptional.Add(1)
	default:
		r.droppedCritical.Add(1)
	}
}

func (r *Recorder) recordLoss(meta Meta) {
	if r == nil {
		return
	}
	switch normalizeDeliveryClass(meta.DeliveryClass) {
	case DeliveryClassImportant:
		r.lostImportant.Add(1)
	case DeliveryClassOptional:
		r.lostOptional.Add(1)
	default:
		r.lostCritical.Add(1)
	}
}

func (r *Recorder) writeJSONL(data []byte) {
	r.fileMu.Lock()
	defer r.fileMu.Unlock()
	if r.file == nil || r.exportFailed {
		return
	}
	if r.fileBytes+int64(len(data)+1) > r.opts.MaxFileBytes {
		r.exportFailed = true
		r.writeErrors.Add(1)
		return
	}
	line := append(append([]byte(nil), data...), '\n')
	n, err := r.file.Write(line)
	r.fileBytes += int64(n)
	if err != nil || n != len(line) {
		r.exportFailed = true
		r.writeErrors.Add(1)
	}
}

func (r *Recorder) remember(data []byte) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for len(r.recent) > 0 && (len(r.recent) >= r.opts.RecentLimit || r.memory+len(data) > r.opts.MemoryBytes) {
		r.memory -= len(r.recent[0])
		r.recent[0] = nil
		r.recent = r.recent[1:]
	}
	if len(data) <= r.opts.MemoryBytes {
		r.recent = append(r.recent, data)
		r.memory += len(data)
	}
}

func (r *Recorder) persistBatch(batch []persistedObservation) {
	if r.store == nil || len(batch) == 0 {
		return
	}
	if err := r.store.insertBatch(batch); err != nil {
		for _, item := range batch {
			r.persistFailure(item.observation, item.payload, err)
		}
	}
}

func (r *Recorder) persistFailure(o Observation, data []byte, cause error) {
	r.writeErrors.Add(1)
	if r.spool == nil {
		r.recordLoss(o.Meta)
		return
	}
	if spoolErr := r.spool.append(o.ID, data); spoolErr != nil {
		r.writeErrors.Add(1)
		r.recordLoss(o.Meta)
		if errors.Is(spoolErr, errSpoolFull) && r.spoolFullReported.CompareAndSwap(false, true) {
			logutil.Error("recorder", "critical recorder spool quota exhausted", "event", "RECORDER_SPOOL_FULL", "severity", "HIGH", "cause", cause)
		}
	}
}

// ReparseObservation creates a new analysis revision without changing the source.
// The source must contain the raw ClientHello explicitly retained by the recorder.
func ReparseObservation(source Observation) (Observation, error) {
	if len(source.Raw) == 0 {
		return Observation{}, ErrRawUnavailable
	}
	h, err := tlshello.Parse(source.Raw)
	if err != nil {
		return Observation{}, fmt.Errorf("%w: %v", ErrReparseMalformed, err)
	}
	fp, err := tlshello.Calculate(h, source.Raw, source.Records)
	if err != nil {
		return Observation{}, fmt.Errorf("%w: fingerprint calculation: %v", ErrReparseMalformed, err)
	}
	revision := source.AnalysisRevision
	if revision < InitialAnalysisRevision {
		revision = InitialAnalysisRevision
	}
	derived := source
	derived.ID = NewID()
	derived.AnalysisParentID = source.ID
	derived.AnalysisRevision = revision + 1
	derived.ParserVersion = tlshello.ParserVersion
	derived.JA3Version = tlshello.JA3Version
	derived.JA4Version = tlshello.JA4Version
	derived.TLSNormVersion = tlshello.NormalizationVersion
	derived.PersistedAt = time.Now().UTC()
	derived.Completeness = "complete"
	derived.ErrorCode = ""
	derived.Hello = h
	derived.Fingerprints = &fp
	derived.Verification = nil
	return derived, nil
}

// Reparse retains the original observation and appends the derived revision.
func (r *Recorder) Reparse(id string) (Observation, error) {
	if r == nil {
		return Observation{}, ErrRecorderClosed
	}
	r.sendMu.RLock()
	defer r.sendMu.RUnlock()
	if r.closed {
		return Observation{}, ErrRecorderClosed
	}
	var source *Observation
	for _, candidate := range r.Snapshot() {
		if candidate.ID == id {
			copy := candidate
			source = &copy
			break
		}
	}
	if source == nil {
		return Observation{}, ErrObservationNotFound
	}
	return r.appendReparse(*source)
}

// ReparseStored reparses one observation loaded from durable SQLite storage.
func (r *Recorder) ReparseStored(id string) (Observation, error) {
	if r == nil {
		return Observation{}, ErrRecorderClosed
	}
	r.sendMu.RLock()
	defer r.sendMu.RUnlock()
	if r.closed {
		return Observation{}, ErrRecorderClosed
	}
	if r.store == nil {
		return Observation{}, ErrHistoricalUnavailable
	}
	source, err := r.store.get(id)
	if err != nil {
		return Observation{}, err
	}
	return r.appendReparse(source)
}

// ReparseStoredPage reparses one bounded page of original SQLite observations.
// Derived revisions are excluded so callers can safely continue with NextCursor.
func (r *Recorder) ReparseStoredPage(query StoredQuery) (ReparsePageResult, error) {
	if r == nil {
		return ReparsePageResult{}, ErrRecorderClosed
	}
	r.sendMu.RLock()
	defer r.sendMu.RUnlock()
	if r.closed {
		return ReparsePageResult{}, ErrRecorderClosed
	}
	if r.store == nil {
		return ReparsePageResult{}, ErrHistoricalUnavailable
	}
	if query.Limit == 0 {
		query.Limit = 100
	}
	query.AnalysisRevision = InitialAnalysisRevision
	page, err := r.store.query(query)
	if err != nil {
		return ReparsePageResult{}, err
	}
	result := ReparsePageResult{Scanned: len(page.Items), NextCursor: page.NextCursor}
	for _, source := range page.Items {
		_, reparseErr := r.appendReparse(source)
		if reparseErr != nil {
			if errors.Is(reparseErr, ErrRawUnavailable) || errors.Is(reparseErr, ErrReparseMalformed) {
				result.Skipped++
				continue
			}
			result.Failed++
		}
		if reparseErr == nil {
			result.Reparsed++
		}
	}
	return result, nil
}

func (r *Recorder) appendReparse(source Observation) (Observation, error) {
	derived, err := ReparseObservation(source)
	if err != nil {
		return Observation{}, err
	}
	data, err := json.Marshal(derived)
	if err != nil {
		return Observation{}, err
	}
	r.writeJSONL(data)
	r.persistBatch([]persistedObservation{{observation: derived, payload: data}})
	r.remember(data)
	r.processed.Add(1)
	return derived, nil
}

func ForwardingFromCapture(c tlshello.Capture) *ForwardingExpected {
	return &ForwardingExpected{
		Completeness: c.Status, RawSHA256: tlshello.SHA256(c.Raw), RecordsSHA256: tlshello.SHA256(c.Records),
	}
}

func VerifyForwarding(expected ForwardingExpected, actual tlshello.Capture) *ForwardingVerification {
	verification := &ForwardingVerification{
		Status: "UNVERIFIED", InboundRawSHA256: expected.RawSHA256, InboundRecordsSHA256: expected.RecordsSHA256,
		OutboundRawSHA256: tlshello.SHA256(actual.Raw), OutboundRecordsSHA256: tlshello.SHA256(actual.Records),
	}
	if expected.Completeness != "complete" || actual.Status != "complete" {
		verification.Reason = "incomplete_capture"
		return verification
	}
	if expected.RawSHA256 != verification.OutboundRawSHA256 || expected.RecordsSHA256 != verification.OutboundRecordsSHA256 {
		verification.Status = "MISMATCH"
		verification.Reason = "forwarded_bytes_differ"
		return verification
	}
	verification.Status = "FORWARDED_UNCHANGED"
	return verification
}

// Snapshot returns independent observations, newest first, bounded by retention.
func (r *Recorder) Snapshot() []Observation {
	if r == nil {
		return []Observation{}
	}
	r.mu.RLock()
	data := append([][]byte(nil), r.recent...)
	r.mu.RUnlock()
	out := make([]Observation, 0, len(data))
	for i := len(data) - 1; i >= 0; i-- {
		var o Observation
		if json.Unmarshal(data[i], &o) == nil {
			out = append(out, o)
		}
	}
	return out
}

func (r *Recorder) Stats() Stats {
	if r == nil {
		return Stats{}
	}
	r.mu.RLock()
	recent, memory := len(r.recent), r.memory
	r.mu.RUnlock()
	dropped, writes := r.dropped.Load(), r.writeErrors.Load()
	spoolBytes, spoolEvents, spoolQuarantined := r.spool.stats()
	spoolKeyStatus, spoolKeyActivatedAt, spoolKeyExpiresAt := r.spool.keyExpiryStatus(time.Now().UTC())
	spoolQuotaFailures := r.spoolQuotaFailures.Load()
	queueDepth := len(r.queue)
	criticalQueueDepth := 0
	if r.criticalQueue != nil {
		criticalQueueDepth = len(r.criticalQueue)
	}
	return Stats{
		Accepted: r.accepted.Load(), Processed: r.processed.Load(), Dropped: dropped,
		WriteErrors: writes, QueueDepth: queueDepth + criticalQueueDepth, CriticalQueueDepth: criticalQueueDepth,
		CriticalSpillAccepted: r.criticalSpillAccepted.Load(), Recent: recent, MemoryBytes: memory,
		RecordingDegraded: dropped > 0 || writes > 0 || spoolEvents > 0 || spoolQuarantined > 0 || spoolQuotaFailures > 0,
		DroppedByClass: map[string]uint64{
			DeliveryClassCritical:  r.droppedCritical.Load(),
			DeliveryClassImportant: r.droppedImportant.Load(),
			DeliveryClassOptional:  r.droppedOptional.Load(),
		},
		LostByClass: map[string]uint64{
			DeliveryClassCritical:  r.lostCritical.Load(),
			DeliveryClassImportant: r.lostImportant.Load(),
			DeliveryClassOptional:  r.lostOptional.Load(),
		},
		SpoolBytes: spoolBytes, SpoolEvents: spoolEvents, SpoolQuarantined: spoolQuarantined,
		SpoolQuotaFailures: spoolQuotaFailures,
		SpoolKeyStatus:     spoolKeyStatus, SpoolKeyActivatedAt: spoolKeyActivatedAt,
		SpoolKeyExpiresAt: spoolKeyExpiresAt,
	}
}

func (r *Recorder) Export(w io.Writer) error {
	for _, o := range r.Snapshot() {
		if err := json.NewEncoder(w).Encode(o); err != nil {
			return err
		}
	}
	return nil
}

// BackupSQLite writes a consistent standalone snapshot of the durable
// recorder database. The target must not already exist.
func (r *Recorder) BackupSQLite(path string) error {
	if r == nil {
		return ErrRecorderClosed
	}
	r.sendMu.RLock()
	defer r.sendMu.RUnlock()
	if r.closed {
		return ErrRecorderClosed
	}
	if r.store == nil {
		return ErrHistoricalUnavailable
	}
	return r.store.backup(path)
}

// RestoreSQLiteBackup imports a standalone SQLite snapshot into the active
// durable recorder database. Existing IDs are ignored and the target file is
// never replaced, making retries safe while the proxy keeps running.
func (r *Recorder) RestoreSQLiteBackup(path string) (int, error) {
	if r == nil {
		return 0, ErrRecorderClosed
	}
	r.sendMu.RLock()
	defer r.sendMu.RUnlock()
	if r.closed {
		return 0, ErrRecorderClosed
	}
	if r.store == nil {
		return 0, ErrHistoricalUnavailable
	}
	imported, err := r.store.restore(path)
	if err != nil {
		return 0, err
	}
	data, err := r.store.recent(r.opts.RecentLimit)
	if err != nil {
		return imported, err
	}
	r.mu.Lock()
	r.recent = nil
	r.memory = 0
	r.mu.Unlock()
	for _, item := range data {
		r.remember(item)
	}
	return imported, nil
}

func (r *Recorder) Close() error {
	if r == nil {
		return nil
	}
	r.sendMu.Lock()
	if !r.closed {
		r.closed = true
		close(r.queue)
		if r.criticalQueue != nil {
			close(r.criticalQueue)
		}
	}
	r.sendMu.Unlock()
	<-r.done
	if r.writeErrors.Load() > 0 {
		return errors.New("recorder output incomplete; inspect write_errors")
	}
	return nil
}
