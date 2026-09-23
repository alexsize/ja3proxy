package webpanel

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/lylemi/ja3proxy/internal/ja3proxy/device"
	"github.com/lylemi/ja3proxy/internal/ja3proxy/fingerprint"
	"github.com/lylemi/ja3proxy/internal/ja3proxy/recorder"
)

func (panel Server) registerRecorderRoutes(mux *http.ServeMux) {
	mux.Handle("GET /metrics", recorderLocalOnly(http.HandlerFunc(panel.RecorderMetrics)))
	mux.Handle("GET /health/live", recorderLocalOnly(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{"status": "live"})
	})))
	mux.Handle("GET /health/ready", recorderLocalOnly(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"status": "ready", "recording_degraded": panel.Recorder.Stats().RecordingDegraded})
	})))
	routes := map[string]http.HandlerFunc{
		"GET /api/v1/status":                     panel.recorderStatus,
		"GET /api/v1/devices":                    panel.devices,
		"GET /api/v1/devices/{id}":               panel.getDevice,
		"POST /api/v1/devices":                   panel.createDevice,
		"PUT /api/v1/devices/{id}":               panel.updateDevice,
		"DELETE /api/v1/devices/{id}":            panel.deleteDevice,
		"GET /api/v1/device-assignments":         panel.assignments,
		"GET /api/v1/device-assignments/{id}":    panel.getAssignment,
		"POST /api/v1/device-assignments":        panel.createAssignment,
		"PUT /api/v1/device-assignments/{id}":    panel.updateAssignment,
		"DELETE /api/v1/device-assignments/{id}": panel.deleteAssignment,
		"GET /api/v1/applications":               panel.applications,
		"GET /api/v1/applications/{id}":          panel.getApplication,
		"POST /api/v1/applications":              panel.createApplication,
		"PUT /api/v1/applications/{id}":          panel.updateApplication,
		"DELETE /api/v1/applications/{id}":       panel.deleteApplication,
		"GET /api/v1/observations":               panel.observations,
		"GET /api/v1/observations/{id}":          panel.observation,
		"POST /api/v1/observations/{id}/reparse": panel.reparseObservation,
		"GET /api/v1/fingerprints/diff":          panel.fingerprintDiff,
		"GET /api/v1/fingerprints/timeline":      panel.fingerprintTimeline,
		"GET /api/v1/export/observations":        panel.exportObservations,
		"POST /api/v1/routes/test":               panel.routeTest,
		"GET /api/v1/tls/presets":                func(w http.ResponseWriter, r *http.Request) { json.NewEncoder(w).Encode(fingerprint.Presets()) },
	}
	for pattern, h := range routes {
		mux.Handle(pattern, recorderLocalOnly(h))
	}
}

func (panel Server) devices(w http.ResponseWriter, r *http.Request) {
	if panel.Devices == nil {
		json.NewEncoder(w).Encode(struct {
			SchemaVersion string          `json:"schema_version"`
			ConfigVersion uint64          `json:"config_version"`
			Items         []device.Device `json:"items"`
		}{SchemaVersion: device.SchemaVersion, Items: []device.Device{}})
		return
	}
	snapshot := panel.Devices.Snapshot()
	json.NewEncoder(w).Encode(struct {
		SchemaVersion string          `json:"schema_version"`
		ConfigVersion uint64          `json:"config_version"`
		Items         []device.Device `json:"items"`
	}{snapshot.SchemaVersion, snapshot.ConfigVersion, snapshot.Devices})
}

// The first recorder release is a local management surface. Validate Host as
// well as peer IP so DNS rebinding cannot expose local observations to a site.
func recorderLocalOnly(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/") || strings.HasPrefix(r.URL.Path, "/health/") {
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
		}
		w.Header().Set("Cache-Control", "no-store")
		peer, _, err := net.SplitHostPort(r.RemoteAddr)
		host := r.Host
		if h, _, e := net.SplitHostPort(host); e == nil {
			host = h
		}
		host = strings.Trim(host, "[]")
		ip := net.ParseIP(host)
		if err != nil || !net.ParseIP(peer).IsLoopback() || (host != "localhost" && (ip == nil || !ip.IsLoopback())) {
			writeAPIError(w, 403, "recorder API is loopback-only")
			return
		}
		if origin := r.Header.Get("Origin"); origin != "" {
			u, e := url.Parse(origin)
			if e != nil || u.Host != r.Host || (u.Scheme != "http" && u.Scheme != "https") {
				writeAPIError(w, 403, "cross-origin access denied")
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func (panel Server) recorderStatus(w http.ResponseWriter, r *http.Request) {
	json.NewEncoder(w).Encode(struct {
		Enabled bool           `json:"enabled"`
		Stats   recorder.Stats `json:"stats"`
	}{panel.Recorder != nil, panel.Recorder.Stats()})
}

func (panel Server) observations(w http.ResponseWriter, r *http.Request) {
	filter, ok := parseObservationFilter(w, r)
	if !ok {
		return
	}
	limit := 50
	if value := r.URL.Query().Get("limit"); value != "" {
		n, err := strconv.Atoi(value)
		if err != nil || n < 1 || n > 100 {
			writeAPIError(w, 400, "limit must be 1..100")
			return
		}
		limit = n
	}
	query := strings.ToLower(r.URL.Query().Get("q"))
	cursor := r.URL.Query().Get("cursor")
	after := cursor == ""
	items := []recorder.Observation{}
	next := ""
	for _, o := range panel.Recorder.Snapshot() {
		if !after {
			if o.ID == cursor {
				after = true
			}
			continue
		}
		if !filter.matches(o) {
			continue
		}
		search := o.Destination + " " + o.Source + " " + o.ConnectionID + " " + o.IdentitySource + " " + o.IdentityValue + " " + o.Confidence + " " + o.ResolvedDeviceID + " " + o.Application + " " + o.ApplicationVersion
		if o.Fingerprints != nil {
			search += " " + o.Fingerprints.JA3 + " " + o.Fingerprints.JA3Hash + " " + o.Fingerprints.JA4
		}
		if query != "" && !strings.Contains(strings.ToLower(search), query) {
			continue
		}
		if len(items) == limit {
			next = items[len(items)-1].ID
			break
		}
		o.Raw = nil
		o.Records = nil
		o.Hello = nil
		if o.Fingerprints != nil {
			o.Fingerprints.Normalized = nil
		}
		items = append(items, o)
	}
	if !after {
		writeAPIError(w, 409, "cursor expired; refresh the bounded observation window")
		return
	}
	json.NewEncoder(w).Encode(struct {
		Items      []recorder.Observation `json:"items"`
		NextCursor string                 `json:"next_cursor,omitempty"`
	}{items, next})
}

func (panel Server) observation(w http.ResponseWriter, r *http.Request) {
	for _, o := range panel.Recorder.Snapshot() {
		if o.ID == r.PathValue("id") {
			json.NewEncoder(w).Encode(o)
			return
		}
	}
	writeAPIError(w, 404, "observation not retained")
}

func (panel Server) reparseObservation(w http.ResponseWriter, r *http.Request) {
	if panel.Recorder == nil {
		writeAPIError(w, 503, "recorder is disabled")
		return
	}
	o, err := panel.Recorder.Reparse(r.PathValue("id"))
	if err != nil {
		switch {
		case errors.Is(err, recorder.ErrObservationNotFound):
			writeAPIError(w, 404, err.Error())
		case errors.Is(err, recorder.ErrRawUnavailable), errors.Is(err, recorder.ErrReparseMalformed):
			writeAPIError(w, 422, err.Error())
		default:
			writeAPIError(w, 503, err.Error())
		}
		return
	}
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(o)
}

func (panel Server) fingerprintDiff(w http.ResponseWriter, r *http.Request) {
	a, b := r.URL.Query().Get("a"), r.URL.Query().Get("b")
	var left, right *recorder.Observation
	for _, o := range panel.Recorder.Snapshot() {
		if o.ID == a {
			v := o
			left = &v
		}
		if o.ID == b {
			v := o
			right = &v
		}
	}
	if left == nil || right == nil {
		writeAPIError(w, 404, "both observations must be retained")
		return
	}
	json.NewEncoder(w).Encode(recorder.Compare(*left, *right))
}
func (panel Server) exportObservations(w http.ResponseWriter, r *http.Request) {
	if panel.Recorder == nil {
		writeAPIError(w, http.StatusServiceUnavailable, "recorder is disabled")
		return
	}
	filter, ok := parseObservationFilter(w, r)
	if !ok {
		return
	}
	format := strings.ToLower(r.URL.Query().Get("format"))
	if format == "" || format == "jsonl" {
		w.Header().Set("Content-Type", "application/x-ndjson")
		w.Header().Set("Content-Disposition", `attachment; filename="observations.jsonl"`)
		for _, observation := range panel.Recorder.Snapshot() {
			if filter.matches(observation) {
				if err := json.NewEncoder(w).Encode(observation); err != nil {
					return
				}
			}
		}
		return
	}
	if format != "csv" {
		writeAPIError(w, http.StatusBadRequest, "format must be jsonl or csv")
		return
	}
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="fingerprints.csv"`)
	writeFingerprintCSV(w, filteredObservations(panel.Recorder.Snapshot(), filter))
}

// RecorderMetrics avoids device/host/fingerprint labels with unbounded cardinality.
func (panel Server) RecorderMetrics(w http.ResponseWriter, r *http.Request) {
	s := panel.Recorder.Stats()
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	fmt.Fprintf(w, "recorder_accepted_total %d\nrecorder_processed_total %d\nrecorder_dropped_total %d\nrecorder_write_errors_total %d\nrecorder_queue_depth %d\n", s.Accepted, s.Processed, s.Dropped, s.WriteErrors, s.QueueDepth)
}
