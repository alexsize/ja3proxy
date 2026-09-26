package e2e

import (
	"database/sql"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/lylemi/ja3proxy/internal/ja3proxy/recorder"
	_ "modernc.org/sqlite"
)

// TestProxyBinaryLoadMatrix exercises the built CLI binary against a local TLS
// target. It is opt-in because it builds and starts several proxy processes.
func TestProxyBinaryLoadMatrix(t *testing.T) {
	if os.Getenv("JA3PROXY_E2E_BINARY_PERF") != "1" {
		t.Skip("set JA3PROXY_E2E_BINARY_PERF=1 to run the built-binary load matrix")
	}
	concurrency := perfEnvInt("JA3PROXY_E2E_PERF_CONCURRENCY", 16)
	requests := perfEnvInt("JA3PROXY_E2E_PERF_REQUESTS", 100)
	rounds := perfEnvInt("JA3PROXY_E2E_PERF_ROUNDS", 5)
	if concurrency < 1 || requests < 1 || rounds < 1 {
		t.Fatalf("invalid performance settings: concurrency=%d requests=%d rounds=%d", concurrency, requests, rounds)
	}
	root := repositoryRoot(t)
	goTool := goToolPath(t)
	binary := filepath.Join(t.TempDir(), "ja3proxy"+executableSuffix())
	build := exec.Command(goTool, "build", "-o", binary, "./cmd/ja3proxy")
	build.Dir = root
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build proxy binary: %v\n%s", err, output)
	}
	target := newLocalHTTPSTarget(t)
	results := make([]proxyLoadResult, 0, rounds*4)
	comparisons := make([]proxyLoadComparison, 0, rounds*2)
	for round := 0; round < rounds; round++ {
		for downstreamIndex, downstream := range []string{"http", "socks5"} {
			recorderFirst := (round+downstreamIndex)%2 == 1
			order := []bool{false, true}
			if recorderFirst {
				order = []bool{true, false}
			}
			var off, on proxyLoadResult
			for _, recording := range order {
				result := runBinaryProxyLoadCase(t, binary, target, downstream, recording, concurrency, requests)
				results = append(results, result)
				if recording {
					on = result
				} else {
					off = result
				}
			}
			comparisons = append(comparisons, proxyLoadComparison{
				Round: round + 1, Downstream: downstream,
				RecorderFirst:       recorderFirst,
				ThroughputChangePct: percentChange(off.Throughput, on.Throughput),
				P95ChangePct:        percentChange(float64(off.P95NS), float64(on.P95NS)),
			})
		}
	}
	summaries := summarizeProxyLoadComparisons(comparisons)
	report := struct {
		Rounds      int                   `json:"rounds"`
		Results     []proxyLoadResult     `json:"results"`
		Comparisons []proxyLoadComparison `json:"paired_comparisons"`
		Summaries   []proxyLoadSummary    `json:"summaries"`
	}{Rounds: rounds, Results: results, Comparisons: comparisons, Summaries: summaries}
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	t.Log(string(data))
}

type proxyLoadComparison struct {
	Round               int     `json:"round"`
	Downstream          string  `json:"downstream"`
	RecorderFirst       bool    `json:"recorder_on_ran_first"`
	ThroughputChangePct float64 `json:"throughput_on_vs_off_pct"`
	P95ChangePct        float64 `json:"p95_on_vs_off_pct"`
}

type proxyLoadSummary struct {
	Downstream                string  `json:"downstream"`
	Rounds                    int     `json:"rounds"`
	MedianThroughputChangePct float64 `json:"median_throughput_on_vs_off_pct"`
	MedianP95ChangePct        float64 `json:"median_p95_on_vs_off_pct"`
	PassUnderTenPercent       bool    `json:"pass_under_10_percent"`
}

func TestSummarizeProxyLoadComparisons(t *testing.T) {
	comparisons := []proxyLoadComparison{
		{Downstream: "http", ThroughputChangePct: 10, P95ChangePct: 8},
		{Downstream: "http", ThroughputChangePct: -4, P95ChangePct: 2},
		{Downstream: "socks5", ThroughputChangePct: 6, P95ChangePct: 12},
	}
	summaries := summarizeProxyLoadComparisons(comparisons)
	if len(summaries) != 2 {
		t.Fatalf("summaries = %+v, want both proxy protocols", summaries)
	}
	if summaries[0].Downstream != "http" || summaries[0].MedianThroughputChangePct != 3 || summaries[0].MedianP95ChangePct != 5 {
		t.Fatalf("HTTP summary = %+v", summaries[0])
	}
	if !summaries[0].PassUnderTenPercent {
		t.Fatalf("HTTP summary should pass both 10%% limits: %+v", summaries[0])
	}
	if summaries[1].Downstream != "socks5" || summaries[1].MedianThroughputChangePct != 6 || summaries[1].MedianP95ChangePct != 12 {
		t.Fatalf("SOCKS5 summary = %+v", summaries[1])
	}
	if summaries[1].PassUnderTenPercent {
		t.Fatalf("SOCKS5 summary should fail the p95 10%% limit: %+v", summaries[1])
	}
}

func percentChange(off, on float64) float64 {
	if off == 0 {
		return 0
	}
	return (on - off) / off * 100
}

func summarizeProxyLoadComparisons(comparisons []proxyLoadComparison) []proxyLoadSummary {
	summaries := make([]proxyLoadSummary, 0, 2)
	for _, downstream := range []string{"http", "socks5"} {
		throughputChanges := make([]float64, 0)
		p95Changes := make([]float64, 0)
		for _, comparison := range comparisons {
			if comparison.Downstream == downstream {
				throughputChanges = append(throughputChanges, comparison.ThroughputChangePct)
				p95Changes = append(p95Changes, comparison.P95ChangePct)
			}
		}
		if len(throughputChanges) == 0 {
			continue
		}
		sort.Float64s(throughputChanges)
		sort.Float64s(p95Changes)
		summaries = append(summaries, proxyLoadSummary{
			Downstream: downstream, Rounds: len(throughputChanges),
			MedianThroughputChangePct: medianFloat64(throughputChanges),
			MedianP95ChangePct:        medianFloat64(p95Changes),
			PassUnderTenPercent:       medianFloat64(throughputChanges) > -10 && medianFloat64(p95Changes) < 10,
		})
	}
	return summaries
}

func medianFloat64(sortedValues []float64) float64 {
	middle := len(sortedValues) / 2
	if len(sortedValues)%2 == 1 {
		return sortedValues[middle]
	}
	return (sortedValues[middle-1] + sortedValues[middle]) / 2
}

func runBinaryProxyLoadCase(t *testing.T, binary, target, downstream string, recording bool, concurrency, requests int) proxyLoadResult {
	t.Helper()
	workDir := t.TempDir()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	proxyAddress := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	panelAddress := ""
	statePath := filepath.Join(workDir, "state.db")
	args := []string{
		"--listen", proxyAddress,
		// Keep proxy behavior identical in recorder-on/off runs. Otherwise
		// --capture-tls enables inspection while the default MITM mode differs.
		"--tls-mode", "PASSTHROUGH",
		"--state-sqlite", statePath,
		"--ca-cert", filepath.Join(workDir, "ca.pem"),
		"--ca-key", filepath.Join(workDir, "ca-key.pem"),
	}
	if recording {
		panelListener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		panelAddress = panelListener.Addr().String()
		if err := panelListener.Close(); err != nil {
			t.Fatal(err)
		}
		args = append(args, "--capture-tls", "--web-panel", panelAddress)
	}
	command := exec.Command(binary, args...)
	command.Dir = workDir
	logFile, err := os.Create(filepath.Join(workDir, "proxy.log"))
	if err != nil {
		t.Fatal(err)
	}
	command.Stdout, command.Stderr = logFile, logFile
	if err := command.Start(); err != nil {
		_ = logFile.Close()
		t.Fatalf("start built proxy: %v", err)
	}
	defer func() {
		_ = command.Process.Kill()
		_ = command.Wait()
		_ = logFile.Close()
	}()
	waitForProxy(t, proxyAddress, filepath.Join(workDir, "proxy.log"))
	client := newLoadClient(t, downstream, proxyAddress)
	t.Cleanup(client.CloseIdleConnections)
	for warmup := 0; warmup < concurrency; warmup++ {
		response, err := client.Get(target)
		if err == nil {
			_, err = ioReadAndClose(response)
		}
		if err != nil {
			t.Fatalf("built %s proxy warm-up %d/%d: %v", downstream, warmup+1, concurrency, err)
		}
	}
	var baseline recorder.Stats
	var baselineRows int64
	if recording {
		baseline = waitForRecorderQueue(t, "http://"+panelAddress+"/api/v1/status")
		baselineRows = countPersistedObservations(t, statePath)
	}

	result := proxyLoadResult{Downstream: downstream, RecorderEnabled: recording, Concurrency: concurrency, RequestsPerConn: 1, Requests: concurrency * requests}
	latencies := make([]int64, 0, result.Requests)
	var latenciesMu sync.Mutex
	var countersMu sync.Mutex
	var completed, failed int
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
	if recording {
		stats := waitForRecorderQueue(t, "http://"+panelAddress+"/api/v1/status")
		result.RecorderAccepted = stats.Accepted - baseline.Accepted
		result.RecorderDropped = stats.Dropped - baseline.Dropped
		result.RecorderProcessed = stats.Processed - baseline.Processed
		result.RecorderPersisted = countPersistedObservations(t, statePath) - baselineRows
		if stats.WriteErrors > baseline.WriteErrors {
			t.Fatalf("built recorder reported %d SQLite write errors", stats.WriteErrors-baseline.WriteErrors)
		}
		if result.RecorderDropped != 0 {
			t.Fatalf("built recorder dropped %d events under the acceptance load", result.RecorderDropped)
		}
		if result.RecorderPersisted != int64(result.RecorderProcessed) {
			t.Fatalf("built recorder processed %d events but SQLite persisted %d", result.RecorderProcessed, result.RecorderPersisted)
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
	if failed != 0 {
		t.Fatalf("built %s recorder=%t: %d/%d requests failed", downstream, recording, failed, result.Requests)
	}
	return result
}

func waitForProxy(t *testing.T, address, logPath string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		connection, err := net.DialTimeout("tcp", address, 100*time.Millisecond)
		if err == nil {
			_ = connection.Close()
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	log, _ := os.ReadFile(logPath)
	t.Fatalf("built proxy did not listen on %s within 10s:\n%s", address, log)
}

func waitForRecorderQueue(t *testing.T, statusURL string) recorder.Stats {
	t.Helper()
	client := &http.Client{Timeout: time.Second}
	deadline := time.Now().Add(15 * time.Second)
	var lastAccepted, lastProcessed, lastDropped uint64
	stableSince := time.Time{}
	for time.Now().Before(deadline) {
		response, err := client.Get(statusURL)
		if err == nil {
			var payload struct {
				Enabled bool           `json:"enabled"`
				Stats   recorder.Stats `json:"stats"`
			}
			err = json.NewDecoder(response.Body).Decode(&payload)
			_ = response.Body.Close()
			if err == nil && payload.Enabled && payload.Stats.QueueDepth == 0 {
				stats := payload.Stats
				if stats.Accepted == lastAccepted && stats.Processed == lastProcessed && stats.Dropped == lastDropped {
					if stableSince.IsZero() {
						stableSince = time.Now()
					} else if time.Since(stableSince) >= 300*time.Millisecond {
						return stats
					}
				} else {
					lastAccepted, lastProcessed, lastDropped = stats.Accepted, stats.Processed, stats.Dropped
					stableSince = time.Time{}
				}
			} else {
				stableSince = time.Time{}
			}
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("recorder status did not become stable and drained at %s", statusURL)
	return recorder.Stats{}
}

func countPersistedObservations(t *testing.T, databasePath string) int64 {
	t.Helper()
	database, err := sql.Open("sqlite", databasePath)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	var count int64
	if err := database.QueryRow(`SELECT COUNT(*) FROM observations`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count
}

func repositoryRoot(t *testing.T) string {
	t.Helper()
	_, source, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate binary performance test source")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(source), "..", "..", ".."))
}

func goToolPath(t *testing.T) string {
	t.Helper()
	if path, err := exec.LookPath("go"); err == nil {
		return path
	}
	path := filepath.Join(runtime.GOROOT(), "bin", "go"+executableSuffix())
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("locate Go tool in PATH or GOROOT: %v", err)
	}
	return path
}

func executableSuffix() string {
	if runtime.GOOS == "windows" {
		return ".exe"
	}
	return ""
}
