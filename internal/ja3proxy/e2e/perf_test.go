package e2e

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"os"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/lylemi/ja3proxy/internal/ja3proxy/dialer"
	httpproxy "github.com/lylemi/ja3proxy/internal/ja3proxy/proxy"
	"github.com/lylemi/ja3proxy/internal/ja3proxy/recorder"
	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/proxy"
)

type proxyLoadResult struct {
	Downstream         string  `json:"downstream"`
	RecorderEnabled    bool    `json:"recorder_enabled"`
	Concurrency        int     `json:"concurrency"`
	RequestsPerConn    int     `json:"requests_per_connection"`
	Requests           int     `json:"requests"`
	Completed          int     `json:"completed"`
	Errors             int     `json:"errors"`
	DurationMS         int64   `json:"duration_ms"`
	Throughput         float64 `json:"throughput_requests_per_second"`
	P50NS              int64   `json:"p50_ns"`
	P95NS              int64   `json:"p95_ns"`
	P99NS              int64   `json:"p99_ns"`
	LatencySamples     int     `json:"latency_samples"`
	ZeroLatencySamples int     `json:"zero_latency_samples"`
	MinNS              int64   `json:"min_ns"`
	RecorderAccepted   uint64  `json:"recorder_accepted"`
	RecorderDropped    uint64  `json:"recorder_dropped"`
	RecorderProcessed  uint64  `json:"recorder_processed"`
	RecorderPersisted  int64   `json:"recorder_persisted_observations"`
}

// TestProxyLoadMatrix is an opt-in MVP-0 acceptance run. It exercises real
// HTTP CONNECT and SOCKS5 proxy handshakes against a local TLS target with the
// recorder disabled and enabled, and reports request latency percentiles.
func TestProxyLoadMatrix(t *testing.T) {
	if os.Getenv("JA3PROXY_E2E_PERF") != "1" {
		t.Skip("set JA3PROXY_E2E_PERF=1 to run the HTTP CONNECT/SOCKS5 load matrix")
	}
	concurrency := perfEnvInt("JA3PROXY_E2E_PERF_CONCURRENCY", 16)
	requests := perfEnvInt("JA3PROXY_E2E_PERF_REQUESTS", 100)
	if concurrency < 1 || requests < 1 {
		t.Fatalf("invalid performance settings: concurrency=%d requests=%d", concurrency, requests)
	}
	target := newLocalHTTPSTarget(t)
	results := make([]proxyLoadResult, 0, 4)
	for _, downstream := range []string{"http", "socks5"} {
		for _, recording := range []bool{false, true} {
			result := runProxyLoadCase(t, target, downstream, recording, concurrency, requests)
			results = append(results, result)
		}
	}
	data, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	t.Log(string(data))
}

func runProxyLoadCase(t *testing.T, target, downstream string, recording bool, concurrency, requests int) proxyLoadResult {
	t.Helper()
	handler := newTestTunnelHandler(t, utls.HelloGolang)
	var recorderInstance *recorder.Recorder
	upstream, err := dialer.NewUpstreamDialer("", 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	proxyServer := httpproxy.NewProxy(upstream.Dial, handler.Connect, upstream.Transport).WithTLSInspection(true)
	proxyAddress := serveMixedRecorderProxy(t, proxyServer)
	client := newLoadClient(t, downstream, proxyAddress)
	t.Cleanup(client.CloseIdleConnections)
	for warmup := 0; warmup < concurrency; warmup++ {
		response, err := client.Get(target)
		if err == nil {
			_, err = ioReadAndClose(response)
		}
		if err != nil {
			t.Fatalf("%s warm-up request %d/%d: %v", downstream, warmup+1, concurrency, err)
		}
	}
	if recording {
		recorderInstance, err = recorder.New(recorder.Options{QueueSize: 1024, CriticalQueueSize: 1024, RecentLimit: 256, MemoryBytes: 32 << 20})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = recorderInstance.Close() })
		handler.Recorder = recorderInstance
	}

	result := proxyLoadResult{Downstream: downstream, RecorderEnabled: recording, Concurrency: concurrency, RequestsPerConn: 1, Requests: concurrency * requests}
	latencies := make([]int64, 0, result.Requests)
	var latenciesMu sync.Mutex
	var completed, failed int
	var countersMu sync.Mutex
	start := time.Now()
	var workers sync.WaitGroup
	workers.Add(concurrency)
	for worker := 0; worker < concurrency; worker++ {
		go func() {
			defer workers.Done()
			for request := 0; request < requests; request++ {
				requestStart := time.Now()
				response, err := client.Get(target)
				if err == nil {
					_, err = ioReadAndClose(response)
				}
				if err != nil {
					countersMu.Lock()
					failed++
					countersMu.Unlock()
					continue
				}
				countersMu.Lock()
				completed++
				countersMu.Unlock()
				latenciesMu.Lock()
				latencies = append(latencies, time.Since(requestStart).Nanoseconds())
				latenciesMu.Unlock()
			}
		}()
	}
	workers.Wait()
	elapsed := time.Since(start)
	if recorderInstance != nil {
		if err := recorderInstance.Close(); err != nil {
			t.Fatalf("close recorder after draining load: %v", err)
		}
	}
	sort.Slice(latencies, func(i, j int) bool { return latencies[i] < latencies[j] })
	result.Completed, result.Errors = completed, failed
	result.DurationMS = elapsed.Milliseconds()
	result.Throughput = float64(completed) / elapsed.Seconds()
	result.LatencySamples = len(latencies)
	if len(latencies) > 0 {
		result.MinNS = latencies[0]
		for _, latency := range latencies {
			if latency == 0 {
				result.ZeroLatencySamples++
			}
		}
	}
	result.P50NS = loadPercentile(latencies, 0.50)
	result.P95NS = loadPercentile(latencies, 0.95)
	result.P99NS = loadPercentile(latencies, 0.99)
	if recorderInstance != nil {
		stats := recorderInstance.Stats()
		result.RecorderAccepted = stats.Accepted
		result.RecorderDropped = stats.Dropped
		result.RecorderProcessed = stats.Processed
	}
	if failed != 0 {
		t.Fatalf("%s recorder=%t: %d/%d requests failed", downstream, recording, failed, result.Requests)
	}
	return result
}

func newLoadClient(t *testing.T, downstream, address string) *http.Client {
	t.Helper()
	transport := &http.Transport{
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true}, // local test certificate
		ForceAttemptHTTP2:   false,
		TLSHandshakeTimeout: 3 * time.Second,
		DisableKeepAlives:   true,
		MaxIdleConns:        128,
		MaxIdleConnsPerHost: 128,
	}
	if downstream == "http" {
		proxyURL, err := url.Parse("http://" + address)
		if err != nil {
			t.Fatal(err)
		}
		transport.Proxy = http.ProxyURL(proxyURL)
	} else {
		proxyURL, err := url.Parse("socks5://" + address)
		if err != nil {
			t.Fatal(err)
		}
		dialerInstance, err := proxy.FromURL(proxyURL, proxy.Direct)
		if err != nil {
			t.Fatal(err)
		}
		transport.Dial = dialerInstance.Dial
	}
	return &http.Client{Transport: transport, Timeout: 10 * time.Second}
}

func ioReadAndClose(response *http.Response) (int64, error) {
	defer response.Body.Close()
	var total int64
	buffer := make([]byte, 1024)
	for {
		n, err := response.Body.Read(buffer)
		total += int64(n)
		if err != nil {
			if err == io.EOF {
				return total, nil
			}
			return total, err
		}
	}
}

func loadPercentile(values []int64, fraction float64) int64 {
	if len(values) == 0 || fraction < 0 || fraction > 1 {
		return 0
	}
	index := int(math.Ceil(float64(len(values))*fraction)) - 1
	if index < 0 {
		index = 0
	}
	return values[index]
}

func perfEnvInt(name string, fallback int) int {
	value := 0
	if _, err := fmt.Sscanf(os.Getenv(name), "%d", &value); err != nil || value == 0 {
		return fallback
	}
	return value
}
