package recorder

import (
	"encoding/json"
	"os"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const (
	defaultPerfConcurrency = 1000
	defaultPerfDuration    = 5 * time.Second
	perfLatencySampleEvery = 1024
	perfLatencySampleLimit = 100000
)

type recorderPerfResult struct {
	RecorderEnabled   bool    `json:"recorder_enabled"`
	Concurrency       int     `json:"concurrency"`
	DurationMS        int64   `json:"duration_ms"`
	Operations        uint64  `json:"operations"`
	Throughput        float64 `json:"throughput_ops_per_second"`
	P50NS             int64   `json:"p50_ns"`
	P95NS             int64   `json:"p95_ns"`
	P99NS             int64   `json:"p99_ns"`
	Accepted          uint64  `json:"accepted"`
	Processed         uint64  `json:"processed"`
	Dropped           uint64  `json:"dropped"`
	QueueDepth        int     `json:"queue_depth"`
	MemoryBytes       int     `json:"memory_bytes"`
	RecordingDegraded bool    `json:"recording_degraded"`
}

// TestRecorderLoadBaseline is an opt-in lower-level load baseline for the
// MVP-0 acceptance run. It intentionally does not claim to replace the full
// HTTP CONNECT/SOCKS5 workload, which must be run against the proxy binary.
func TestRecorderLoadBaseline(t *testing.T) {
	if os.Getenv("JA3PROXY_PERF") != "1" {
		t.Skip("set JA3PROXY_PERF=1 to run the opt-in recorder load baseline")
	}
	concurrency := perfIntEnv("JA3PROXY_PERF_CONCURRENCY", defaultPerfConcurrency)
	duration := perfDurationEnv("JA3PROXY_PERF_DURATION", defaultPerfDuration)
	if concurrency < 1 || duration <= 0 {
		t.Fatalf("invalid performance settings: concurrency=%d duration=%s", concurrency, duration)
	}

	results := []recorderPerfResult{
		runRecorderPerf(t, false, concurrency, duration),
		runRecorderPerf(t, true, concurrency, duration),
	}
	encoded, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	t.Log(string(encoded))
}

func runRecorderPerf(t *testing.T, recorderEnabled bool, concurrency int, duration time.Duration) recorderPerfResult {
	t.Helper()
	var recording *Recorder
	if recorderEnabled {
		var err error
		recording, err = New(Options{QueueSize: 1024, RecentLimit: 256, MemoryBytes: 32 << 20})
		if err != nil {
			t.Fatal(err)
		}
	}

	var operations atomic.Uint64
	var sampled atomic.Uint64
	var latencyMu sync.Mutex
	latencies := make([]int64, 0, perfLatencySampleLimit)
	deadline := time.Now().Add(duration)
	start := time.Now()
	var workers sync.WaitGroup
	workers.Add(concurrency)
	for i := 0; i < concurrency; i++ {
		go func() {
			defer workers.Done()
			windowStart := time.Now()
			for time.Now().Before(deadline) {
				capture := sample()
				if recorderEnabled {
					recording.TryCapture(Meta{ConnectionID: "perf"}, capture)
				}
				operation := operations.Add(1)
				if operation%perfLatencySampleEvery == 0 {
					n := sampled.Add(1)
					latency := time.Since(windowStart).Nanoseconds()
					windowStart = time.Now()
					latencyMu.Lock()
					if len(latencies) < perfLatencySampleLimit {
						latencies = append(latencies, latency)
					} else if int(n)%perfLatencySampleLimit == 0 {
						latencies[int(n/perfLatencySampleLimit)%perfLatencySampleLimit] = latency
					}
					latencyMu.Unlock()
				}
			}
		}()
	}
	workers.Wait()
	elapsed := time.Since(start)

	result := recorderPerfResult{
		RecorderEnabled: recorderEnabled,
		Concurrency:     concurrency,
		DurationMS:      elapsed.Milliseconds(),
		Operations:      operations.Load(),
		Throughput:      float64(operations.Load()) / elapsed.Seconds(),
	}
	latencyMu.Lock()
	sort.Slice(latencies, func(i, j int) bool { return latencies[i] < latencies[j] })
	result.P50NS = percentile(latencies, 0.50)
	result.P95NS = percentile(latencies, 0.95)
	result.P99NS = percentile(latencies, 0.99)
	latencyMu.Unlock()
	if recording != nil {
		stats := recording.Stats()
		result.Accepted = stats.Accepted
		result.Processed = stats.Processed
		result.Dropped = stats.Dropped
		result.QueueDepth = stats.QueueDepth
		result.MemoryBytes = stats.MemoryBytes
		result.RecordingDegraded = stats.RecordingDegraded
		if err := recording.Close(); err != nil {
			t.Fatal(err)
		}
	}
	return result
}

func percentile(values []int64, fraction float64) int64 {
	if len(values) == 0 {
		return 0
	}
	index := int(float64(len(values)-1) * fraction)
	return values[index]
}

func perfIntEnv(name string, fallback int) int {
	value, err := strconv.Atoi(os.Getenv(name))
	if err != nil || value == 0 {
		return fallback
	}
	return value
}

func perfDurationEnv(name string, fallback time.Duration) time.Duration {
	value, err := time.ParseDuration(os.Getenv(name))
	if err != nil || value == 0 {
		return fallback
	}
	return value
}
