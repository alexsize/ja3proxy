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

	"github.com/lylemi/ja3proxy/internal/ja3proxy/capture/tlshello"
)

const (
	ObservationSchemaVersion = "tls-observation/2"
	CaptureVersion           = 1
	TLSEngineUTLSVersion     = "v1.8.2"
	InitialAnalysisRevision  = 1
)

var (
	ErrObservationNotFound = errors.New("observation not retained")
	ErrRawUnavailable      = errors.New("raw ClientHello is not retained")
	ErrReparseMalformed    = errors.New("stored raw ClientHello is malformed")
	ErrRecorderClosed      = errors.New("recorder is closed")
)

type Meta struct {
	ConnectionID   string               `json:"connection_id"`
	CapturePoint   string               `json:"capture_point"`
	Direction      string               `json:"direction"`
	ByteSource     string               `json:"byte_source"`
	Mode           string               `json:"mode"`
	Destination    string               `json:"destination"`
	Source         string               `json:"source"`
	Profile        string               `json:"profile,omitempty"`
	ProfileID      string               `json:"profile_id,omitempty"`
	ProfileVersion uint64               `json:"profile_version,omitempty"`
	ConfigVersion  uint64               `json:"config_version,omitempty"`
	Expected       *FingerprintExpected `json:"-"`
	Forwarded      *ForwardingExpected  `json:"-"`
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

type Verification struct {
	SchemaVersion          string              `json:"schema_version"`
	Status                 string              `json:"status"`
	Reason                 string              `json:"reason,omitempty"`
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
	CapturedAt          time.Time               `json:"captured_at"`
	PersistedAt         time.Time               `json:"processed_at"`
	Completeness        string                  `json:"completeness"`
	ErrorCode           string                  `json:"error_code,omitempty"`
	RecordVersion       uint16                  `json:"record_version"`
	RecordCount         int                     `json:"record_count"`
	DeclaredHelloLength int                     `json:"declared_hello_length,omitempty"`
	Hello               *tlshello.Hello         `json:"decoded,omitempty"`
	Fingerprints        *tlshello.Fingerprints  `json:"fingerprints,omitempty"`
	Verification        *Verification           `json:"verification,omitempty"`
	Forwarding          *ForwardingVerification `json:"forwarding,omitempty"`
	Raw                 []byte                  `json:"raw_client_hello,omitempty"`
	Records             []byte                  `json:"raw_records,omitempty"`
}

type Options struct {
	QueueSize    int
	RecentLimit  int
	MemoryBytes  int
	Raw          bool
	JSONLPath    string
	MaxFileBytes int64
}

type queued struct {
	meta    Meta
	capture tlshello.Capture
	at      time.Time
}

type Stats struct {
	Accepted          uint64 `json:"accepted"`
	Processed         uint64 `json:"processed"`
	Dropped           uint64 `json:"dropped"`
	WriteErrors       uint64 `json:"write_errors"`
	QueueDepth        int    `json:"queue_depth"`
	Recent            int    `json:"recent"`
	MemoryBytes       int    `json:"memory_bytes"`
	RecordingDegraded bool   `json:"recording_degraded"`
}

type Recorder struct {
	opts         Options
	queue        chan queued
	done         chan struct{}
	sendMu       sync.RWMutex
	closed       bool
	mu           sync.RWMutex
	recent       [][]byte
	memory       int
	file         *os.File
	fileMu       sync.Mutex
	fileBytes    int64
	exportFailed bool
	accepted     atomic.Uint64
	processed    atomic.Uint64
	dropped      atomic.Uint64
	writeErrors  atomic.Uint64
}

func New(opts Options) (*Recorder, error) {
	if opts.QueueSize == 0 {
		opts.QueueSize = 64
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
	if opts.QueueSize < 1 || opts.QueueSize > 1024 || opts.RecentLimit < 1 || opts.RecentLimit > 10000 || opts.MemoryBytes < 1024 || opts.MemoryBytes > 256<<20 || opts.MaxFileBytes < 1 {
		return nil, errors.New("invalid recorder limits")
	}
	r := &Recorder{opts: opts, queue: make(chan queued, opts.QueueSize), done: make(chan struct{})}
	if opts.JSONLPath != "" {
		// Never overwrite previous evidence. Raw output requires explicit opt-in.
		f, err := os.OpenFile(opts.JSONLPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			return nil, err
		}
		r.file = f
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
	r.sendMu.RLock()
	defer r.sendMu.RUnlock()
	if r.closed {
		r.dropped.Add(1)
		return false
	}
	select {
	case r.queue <- queued{meta, capture, time.Now().UTC()}:
		r.accepted.Add(1)
		return true
	default:
		r.dropped.Add(1)
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
	}()
	for q := range r.queue {
		c := q.capture
		engine, engineVersion := observationTLSEngine(q.meta)
		o := Observation{
			SchemaVersion: ObservationSchemaVersion, CaptureVersion: CaptureVersion,
			ParserVersion: tlshello.ParserVersion, JA3Version: tlshello.JA3Version,
			JA4Version: tlshello.JA4Version, TLSNormVersion: tlshello.NormalizationVersion,
			TLSEngine: engine, TLSEngineVersion: engineVersion,
			AnalysisRevision: InitialAnalysisRevision,
			ID:               NewID(), Meta: q.meta, CapturedAt: q.at, PersistedAt: time.Now().UTC(),
			Completeness: c.Status, ErrorCode: c.ErrorCode, RecordVersion: c.RecordVersion,
			RecordCount: c.RecordCount, DeclaredHelloLength: c.DeclaredHelloLength,
		}
		if c.Status == "complete" {
			h, err := tlshello.Parse(c.Raw)
			if err != nil {
				o.Completeness = "malformed"
				o.ErrorCode = "malformed_client_hello"
			} else {
				fp, err := tlshello.Calculate(h, c.Raw, c.Records)
				if err != nil {
					o.ErrorCode = "calculation_failed"
				} else {
					o.Hello = h
					o.Fingerprints = &fp
				}
			}
		}
		if q.meta.Expected != nil {
			o.Verification = VerifyExpected(*q.meta.Expected, o)
		}
		if q.meta.Forwarded != nil {
			o.Forwarding = VerifyForwarding(*q.meta.Forwarded, c)
		}
		if r.opts.Raw {
			o.Raw = c.Raw
			o.Records = c.Records
		}
		data, err := json.Marshal(o)
		if err != nil {
			r.dropped.Add(1)
			continue
		}
		r.writeJSONL(data)
		r.remember(data)
		r.processed.Add(1)
	}
}

func observationTLSEngine(meta Meta) (string, string) {
	if meta.CapturePoint == "PROXY_OUT" && meta.Mode == "MITM_REISSUE" {
		return "utls", TLSEngineUTLSVersion
	}
	return "external", "unknown"
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
	derived, err := ReparseObservation(*source)
	if err != nil {
		return Observation{}, err
	}
	data, err := json.Marshal(derived)
	if err != nil {
		return Observation{}, err
	}
	r.writeJSONL(data)
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
	return Stats{Accepted: r.accepted.Load(), Processed: r.processed.Load(), Dropped: dropped, WriteErrors: writes, QueueDepth: len(r.queue), Recent: recent, MemoryBytes: memory, RecordingDegraded: dropped > 0 || writes > 0}
}

func (r *Recorder) Export(w io.Writer) error {
	for _, o := range r.Snapshot() {
		if err := json.NewEncoder(w).Encode(o); err != nil {
			return err
		}
	}
	return nil
}

func (r *Recorder) Close() error {
	if r == nil {
		return nil
	}
	r.sendMu.Lock()
	if !r.closed {
		r.closed = true
		close(r.queue)
	}
	r.sendMu.Unlock()
	<-r.done
	if r.writeErrors.Load() > 0 {
		return errors.New("recorder output incomplete; inspect write_errors")
	}
	return nil
}
