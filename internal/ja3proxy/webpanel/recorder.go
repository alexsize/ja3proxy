package webpanel

import (
	"encoding/csv"
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
		"POST /api/v1/reparse/sqlite":            panel.reparseSQLite,
		"GET /api/v1/fingerprints/diff":          panel.fingerprintDiff,
		"GET /api/v1/fingerprint-families":       panel.fingerprintFamilies,
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
	if panel.Recorder == nil {
		writeAPIError(w, http.StatusServiceUnavailable, "recorder is disabled")
		return
	}
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
	if storage := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("storage"))); storage != "" && storage != "memory" {
		if storage != "sqlite" {
			writeAPIError(w, http.StatusBadRequest, "storage must be memory or sqlite")
			return
		}
		page, err := panel.Recorder.QueryStored(storedObservationQuery(filter, r, limit))
		if err != nil {
			writeStoredQueryError(w, err)
			return
		}
		for i := range page.Items {
			page.Items[i] = compactObservation(page.Items[i])
		}
		_ = json.NewEncoder(w).Encode(struct {
			Items      []recorder.Observation `json:"items"`
			NextCursor string                 `json:"next_cursor,omitempty"`
		}{page.Items, page.NextCursor})
		return
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
		if query != "" && !strings.Contains(observationSearchText(o), query) {
			continue
		}
		if len(items) == limit {
			next = items[len(items)-1].ID
			break
		}
		items = append(items, compactObservation(o))
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
	if panel.Recorder == nil {
		writeAPIError(w, http.StatusServiceUnavailable, "recorder is disabled")
		return
	}
	storage := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("storage")))
	if storage != "" && storage != "memory" && storage != "sqlite" {
		writeAPIError(w, http.StatusBadRequest, "storage must be memory or sqlite")
		return
	}
	if storage == "sqlite" {
		o, err := panel.Recorder.Stored(r.PathValue("id"))
		if err == nil {
			_ = json.NewEncoder(w).Encode(o)
			return
		}
		if !errors.Is(err, recorder.ErrObservationNotFound) {
			writeStoredQueryError(w, err)
			return
		}
		writeAPIError(w, 404, "observation not retained")
		return
	}
	for _, o := range panel.Recorder.Snapshot() {
		if o.ID == r.PathValue("id") {
			json.NewEncoder(w).Encode(o)
			return
		}
	}
	writeAPIError(w, 404, "observation not retained")
}

func compactObservation(observation recorder.Observation) recorder.Observation {
	observation.RawClientHelloAvailable = observation.RawClientHelloAvailable || len(observation.Raw) > 0
	observation.Raw = nil
	observation.Records = nil
	observation.Hello = nil
	observation.RawServerHello = nil
	observation.ServerRecords = nil
	observation.ServerHello = nil
	if observation.Fingerprints != nil {
		observation.Fingerprints.Normalized = nil
	}
	return observation
}

func observationSearchText(observation recorder.Observation) string {
	encoded, err := json.Marshal(compactObservation(observation))
	if err != nil {
		return ""
	}
	return strings.ToLower(string(encoded))
}

func writeStoredQueryError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, recorder.ErrHistoricalUnavailable):
		writeAPIError(w, http.StatusServiceUnavailable, "historical SQLite storage is not enabled")
	case errors.Is(err, recorder.ErrHistoricalCursor):
		writeAPIError(w, http.StatusConflict, "historical cursor expired; refresh the SQLite window")
	default:
		writeAPIError(w, http.StatusServiceUnavailable, err.Error())
	}
}

func (panel Server) reparseObservation(w http.ResponseWriter, r *http.Request) {
	if panel.Recorder == nil {
		writeAPIError(w, 503, "recorder is disabled")
		return
	}
	storage := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("storage")))
	if storage != "" && storage != "memory" && storage != "sqlite" {
		writeAPIError(w, http.StatusBadRequest, "storage must be memory or sqlite")
		return
	}
	var o recorder.Observation
	var err error
	if storage == "sqlite" {
		o, err = panel.Recorder.ReparseStored(r.PathValue("id"))
	} else {
		o, err = panel.Recorder.Reparse(r.PathValue("id"))
	}
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

func (panel Server) reparseSQLite(w http.ResponseWriter, r *http.Request) {
	if panel.Recorder == nil {
		writeAPIError(w, http.StatusServiceUnavailable, "recorder is disabled")
		return
	}
	filter, ok := parseObservationFilter(w, r)
	if !ok {
		return
	}
	limit := 100
	if value := strings.TrimSpace(r.URL.Query().Get("limit")); value != "" {
		n, err := strconv.Atoi(value)
		if err != nil || n < 1 || n > 100 {
			writeAPIError(w, http.StatusBadRequest, "limit must be 1..100")
			return
		}
		limit = n
	}
	result, err := panel.Recorder.ReparseStoredPage(storedObservationQuery(filter, r, limit))
	if err != nil {
		writeStoredQueryError(w, err)
		return
	}
	_ = json.NewEncoder(w).Encode(result)
}

func (panel Server) fingerprintDiff(w http.ResponseWriter, r *http.Request) {
	if panel.Recorder == nil {
		writeAPIError(w, http.StatusServiceUnavailable, "recorder is disabled")
		return
	}
	a, b := r.URL.Query().Get("a"), r.URL.Query().Get("b")
	var left, right *recorder.Observation
	storage := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("storage")))
	if storage != "" && storage != "memory" && storage != "sqlite" {
		writeAPIError(w, http.StatusBadRequest, "storage must be memory or sqlite")
		return
	}
	if storage == "sqlite" {
		for _, target := range []struct {
			id        string
			observation **recorder.Observation
		}{{a, &left}, {b, &right}} {
			observation, err := panel.Recorder.Stored(target.id)
			if err != nil {
				if errors.Is(err, recorder.ErrObservationNotFound) {
					continue
				}
				writeStoredQueryError(w, err)
				return
			}
			copy := observation
			*target.observation = &copy
		}
	} else {
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
	if storage := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("storage"))); storage != "" && storage != "memory" {
		if storage != "sqlite" {
			writeAPIError(w, http.StatusBadRequest, "storage must be memory or sqlite")
			return
		}
		if format != "" && format != "jsonl" && format != "csv" {
			writeAPIError(w, http.StatusBadRequest, "format must be jsonl or csv")
			return
		}
		panel.exportStoredObservations(w, r, filter, format)
		return
	}
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

func (panel Server) exportStoredObservations(w http.ResponseWriter, r *http.Request, filter observationFilter, format string) {
	query := storedObservationQuery(filter, r, 100)
	if format == "" || format == "jsonl" {
		w.Header().Set("Content-Type", "application/x-ndjson")
		w.Header().Set("Content-Disposition", `attachment; filename="observations.sqlite.jsonl"`)
		encoder := json.NewEncoder(w)
		for {
			stored, err := panel.Recorder.QueryStored(query)
			if err != nil {
				writeStoredQueryError(w, err)
				return
			}
			for _, observation := range stored.Items {
				if err := encoder.Encode(observation); err != nil {
					return
				}
			}
			if stored.NextCursor == "" {
				return
			}
			query.Cursor = stored.NextCursor
		}
	}

	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="fingerprints.sqlite.csv"`)
	writer := csv.NewWriter(w)
	writeFingerprintCSVHeader(writer)
	for {
		stored, err := panel.Recorder.QueryStored(query)
		if err != nil {
			writeStoredQueryError(w, err)
			return
		}
		writeFingerprintCSVRows(writer, stored.Items)
		if stored.NextCursor == "" {
			writer.Flush()
			return
		}
		query.Cursor = stored.NextCursor
	}
}

// RecorderMetrics avoids device/host/fingerprint labels with unbounded cardinality.
func (panel Server) RecorderMetrics(w http.ResponseWriter, r *http.Request) {
	s := panel.Recorder.Stats()
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	fmt.Fprintf(w, "recorder_accepted_total %d\nrecorder_processed_total %d\nrecorder_dropped_total %d\nrecorder_write_errors_total %d\nrecorder_queue_depth %d\nrecorder_critical_queue_depth %d\nrecorder_critical_spill_accepted_total %d\nrecorder_spool_bytes %d\nrecorder_spool_events %d\nrecorder_spool_quarantined_total %d\nrecorder_spool_quota_failures_total %d\n", s.Accepted, s.Processed, s.Dropped, s.WriteErrors, s.QueueDepth, s.CriticalQueueDepth, s.CriticalSpillAccepted, s.SpoolBytes, s.SpoolEvents, s.SpoolQuarantined, s.SpoolQuotaFailures)
	for _, class := range []string{recorder.DeliveryClassCritical, recorder.DeliveryClassImportant, recorder.DeliveryClassOptional} {
		fmt.Fprintf(w, "recorder_dropped_by_class_total{class=\"%s\"} %d\n", class, s.DroppedByClass[class])
		fmt.Fprintf(w, "recorder_lost_by_class_total{class=\"%s\"} %d\n", class, s.LostByClass[class])
	}
}
