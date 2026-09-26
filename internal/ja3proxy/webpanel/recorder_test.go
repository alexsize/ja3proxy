package webpanel

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	http2capture "github.com/lylemi/ja3proxy/internal/ja3proxy/capture/http2"
	"github.com/lylemi/ja3proxy/internal/ja3proxy/capture/tlshello"
	"github.com/lylemi/ja3proxy/internal/ja3proxy/recorder"
	"github.com/lylemi/ja3proxy/internal/ja3proxy/tlsprofile"
)

func requestRecorder(h http.Handler, path string) *httptest.ResponseRecorder {
	return requestRecorderMethod(h, "GET", path)
}

func requestRecorderMethod(h http.Handler, method, path string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, "http://127.0.0.1"+path, nil)
	r.RemoteAddr = "127.0.0.1:10000"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func reparseCapture() tlshello.Capture {
	raw := []byte{1, 0, 0, 43, 3, 3}
	raw = append(raw, make([]byte, 32)...)
	raw = append(raw, 0, 0, 2, 0x13, 1, 1, 0, 0, 0)
	return tlshello.Capture{Status: "complete", Raw: raw, Records: append([]byte{22, 3, 1, 0, 47}, raw...), RecordVersion: 0x0301, RecordCount: 1}
}

func TestRecorderAPI(t *testing.T) {
	r, err := recorder.New(recorder.Options{})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		meta := recorder.Meta{Destination: "test.example", ConnectionID: recorder.NewID()}
		if i == 0 {
			meta.IdentitySource = "proxy_username"
			meta.IdentityValue = "iphone017"
			meta.Confidence = "exact"
			meta.ResolvedDeviceID = "iphone-017"
			meta.Application = "Example"
			meta.ApplicationID = "example"
			meta.ApplicationVersion = "1.2.0"
		}
		r.TryCapture(meta, tlshello.Capture{Status: "timeout", ErrorCode: "capture_timeout"})
	}
	r.Close()
	h := Server{Recorder: r}.Handler()
	w := requestRecorder(h, "/api/v1/observations?limit=2")
	if w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	var page struct {
		Items []recorder.Observation `json:"items"`
		Next  string                 `json:"next_cursor"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &page); err != nil || len(page.Items) != 2 || page.Next == "" {
		t.Fatal(w.Body.String())
	}
	if page.Items[0].SchemaVersion != recorder.ObservationSchemaVersion ||
		page.Items[0].ParserVersion != tlshello.ParserVersion || page.Items[0].TLSEngine == "" {
		t.Fatalf("API omitted observation version envelope: %+v", page.Items[0])
	}
	w = requestRecorder(h, "/api/v1/observations?limit=2&cursor="+page.Next)
	if w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	json.Unmarshal(w.Body.Bytes(), &page)
	if len(page.Items) != 1 {
		t.Fatal("pagination")
	}
	filtered := requestRecorder(h, "/api/v1/observations?q=iphone017")
	var filteredPage struct {
		Items []recorder.Observation `json:"items"`
	}
	if filtered.Code != 200 || json.Unmarshal(filtered.Body.Bytes(), &filteredPage) != nil || len(filteredPage.Items) != 1 || filteredPage.Items[0].IdentityValue != "iphone017" {
		t.Fatalf("identity search = %s", filtered.Body.String())
	}
	filtered = requestRecorder(h, "/api/v1/observations?application=Example&application_version=1.2.0")
	if filtered.Code != 200 || json.Unmarshal(filtered.Body.Bytes(), &filteredPage) != nil || len(filteredPage.Items) != 1 || filteredPage.Items[0].ApplicationID != "example" {
		t.Fatalf("application filter = %s", filtered.Body.String())
	}
	export := requestRecorder(h, "/api/v1/export/observations?format=jsonl&device_id=iphone-017")
	if export.Code != 200 || !strings.Contains(export.Body.String(), "application_version") || !strings.Contains(export.Body.String(), "1.2.0") {
		t.Fatalf("filtered JSONL export = %d %s", export.Code, export.Body.String())
	}
	csvExport := requestRecorder(h, "/api/v1/export/observations?format=csv&device_id=iphone-017")
	if csvExport.Code != 200 || !strings.Contains(csvExport.Body.String(), "observation_id,captured_at,device_id") {
		t.Fatalf("CSV export = %d %s", csvExport.Code, csvExport.Body.String())
	}
	for _, path := range []string{"/api/v1/status", "/api/v1/devices", "/api/v1/tls/presets", "/api/v1/fingerprint-families", "/api/v1/observations/" + page.Items[0].ID, "/api/v1/export/observations", "/recorder.html", "/recorder.js", "/profiles.html", "/profiles.js", "/profiles.css", "/replay-lab.html", "/replay-lab.js", "/tokens.html", "/tokens.js"} {
		if w := requestRecorder(h, path); w.Code != 200 {
			t.Fatalf("%s: %d", path, w.Code)
		}
	}
	for _, path := range []string{"/api/v1/observations?limit=0", "/api/v1/observations?limit=101"} {
		if requestRecorder(h, path).Code != 400 {
			t.Fatal(path)
		}
	}
	if requestRecorder(h, "/api/v1/observations?cursor=expired").Code != 409 {
		t.Fatal("stale cursor")
	}
	if requestRecorder(h, "/api/v1/observations/missing").Code != 404 {
		t.Fatal("missing observation")
	}
	w = requestRecorder(h, "/api/v1/fingerprints/diff?a="+page.Items[0].ID+"&b="+page.Items[0].ID)
	if !strings.Contains(w.Body.String(), "UNKNOWN") {
		t.Fatal("timeout considered match")
	}
}

func TestFingerprintFamiliesOnlyGroupStronglyIdentifiedInboundClientVariants(t *testing.T) {
	makeObservation := func(id, device, app, point, direction, ja4, tlsState string) recorder.Observation {
		observation := recorder.Observation{
			ID:           id,
			Meta:         recorder.Meta{ConnectionID: "conn-" + id, ResolvedDeviceID: device, ApplicationID: app, Application: app, CapturePoint: point, Direction: direction},
			Fingerprints: &tlshello.Fingerprints{JA3: "771,4865,,,", JA3Hash: "same-ja3", JA4: ja4},
		}
		if tlsState != "" {
			observation.NegotiatedState = &recorder.NegotiatedState{HandshakeComplete: true}
			if tlsState == "RESUMED" {
				observation.NegotiatedState.SessionResumption = true
			}
		}
		return observation
	}
	observations := []recorder.Observation{
		makeObservation("full", "device-1", "app-1", "CLIENT_IN", "inbound", "t13d...", "FULL"),
		makeObservation("resumed", "device-1", "app-1", "CLIENT_IN", "inbound", "t13d...", "RESUMED"),
		makeObservation("other-device", "device-2", "app-1", "CLIENT_IN", "inbound", "t13d...", "FULL"),
		makeObservation("outbound", "device-1", "app-1", "PROXY_OUT", "outbound", "proxy-ja4", "FULL"),
		makeObservation("unresolved", "", "app-1", "CLIENT_IN", "inbound", "t13d...", "FULL"),
		{ID: "http-full", Meta: recorder.Meta{ConnectionID: "conn-full", CapturePoint: "CLIENT_IN", Direction: "inbound"}, HTTP2: &http2capture.Fingerprint{Hash: "h2-fingerprint"}},
	}
	families := buildFingerprintFamilies(observations)
	if len(families) != 2 {
		t.Fatalf("families = %+v, want separate groups for two resolved devices", families)
	}
	var family fingerprintFamily
	for _, candidate := range families {
		if candidate.DeviceID == "device-1" {
			family = candidate
		}
	}
	if family.DeviceID != "device-1" || family.ObservationCount != 3 || len(family.Variants) != 2 {
		t.Fatalf("family = %+v", family)
	}
	states := map[string]bool{}
	for _, variant := range family.Variants {
		states[variant.TLSState] = true
		if variant.TLSState == "FULL" && (len(variant.HTTPFingerprints) != 1 || len(variant.ObservationIDs) != 2) {
			t.Fatalf("HTTP fingerprint not associated with same observation: %+v", variant)
		}
	}
	if !states["FULL"] || !states["RESUMED"] {
		t.Fatalf("initial/resumed variants = %+v", family.Variants)
	}
}

func TestFingerprintFamiliesReadDurableHistoryBeyondMemoryWindow(t *testing.T) {
	path := filepath.Join(t.TempDir(), "recorder.db")
	r, err := recorder.New(recorder.Options{SQLitePath: path, RecentLimit: 2})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	for i := 0; i < 103; i++ {
		meta := recorder.Meta{
			ConnectionID: recorder.NewID(), ResolvedDeviceID: "device-history",
			ApplicationID: "app-history", Application: "History app",
			CapturePoint: "CLIENT_IN", Direction: "inbound",
		}
		if !r.TryCapture(meta, reparseCapture()) {
			t.Fatal("enqueue historical observation")
		}
	}
	deadline := time.Now().Add(5 * time.Second)
	for r.Stats().Processed < 103 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if r.Stats().Processed != 103 {
		t.Fatalf("processed %d observations, want 103", r.Stats().Processed)
	}
	response := requestRecorder(Server{Recorder: r}.Handler(), "/api/v1/fingerprint-families")
	if response.Code != http.StatusOK {
		t.Fatalf("API status=%d body=%s", response.Code, response.Body.String())
	}
	var result struct {
		Scope string              `json:"scope"`
		Items []fingerprintFamily `json:"items"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.Scope != "sqlite_history_plus_recent" || len(result.Items) != 1 || result.Items[0].ObservationCount != 103 {
		t.Fatalf("durable families = %+v, scope=%q", result.Items, result.Scope)
	}
}

func TestManagedProfileFamiliesRequireMatchingExplicitID(t *testing.T) {
	profiles := []tlsprofile.Template{
		{ID: "p1", Name: "Chrome initial", FamilyID: "mobile.chrome", Version: 2, Expected: &tlsprofile.Expected{JA3: "ja3-a", JA4: "ja4-a"}},
		{ID: "p2", Name: "Chrome resumed", FamilyID: "mobile.chrome", Version: 1, Expected: &tlsprofile.Expected{JA3: "ja3-b", JA4: "ja4-b"}},
		{ID: "p3", Name: "Unlinked", Expected: &tlsprofile.Expected{JA4: "ja4-c"}},
		{ID: "p4", Name: "Singleton", FamilyID: "alone"},
	}
	families := buildManagedProfileFamilies(profiles)
	if len(families) != 1 || families[0].FamilyID != "mobile.chrome" || len(families[0].Profiles) != 2 {
		t.Fatalf("managed profile families = %+v", families)
	}
	if families[0].Profiles[0].ProfileID != "p1" || families[0].Profiles[0].JA4 != "ja4-a" {
		t.Fatalf("profile variants not sorted or fingerprint omitted: %+v", families[0].Profiles)
	}
}

func TestRecorderReparseAPI(t *testing.T) {
	r, err := recorder.New(recorder.Options{Raw: true})
	if err != nil {
		t.Fatal(err)
	}
	if !r.TryCapture(recorder.Meta{ConnectionID: "reparse", CapturePoint: "CLIENT_IN", Direction: "inbound"}, reparseCapture()) {
		t.Fatal("enqueue")
	}
	var source recorder.Observation
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		items := r.Snapshot()
		if len(items) == 1 {
			source = items[0]
			break
		}
		time.Sleep(time.Millisecond)
	}
	if source.ID == "" {
		t.Fatal("source observation was not processed")
	}
	w := requestRecorderMethod(recorderServer(r), "POST", "/api/v1/observations/"+source.ID+"/reparse")
	if w.Code != http.StatusCreated {
		t.Fatal(w.Body.String())
	}
	var derived recorder.Observation
	if err := json.Unmarshal(w.Body.Bytes(), &derived); err != nil {
		t.Fatal(err)
	}
	if derived.AnalysisParentID != source.ID || derived.AnalysisRevision != 2 {
		t.Fatalf("invalid revision: %+v", derived)
	}
	if len(r.Snapshot()) != 2 {
		t.Fatal("source and derived observations were not both retained")
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}

	withoutRaw, err := recorder.New(recorder.Options{})
	if err != nil {
		t.Fatal(err)
	}
	withoutRaw.TryCapture(recorder.Meta{ConnectionID: "no-raw"}, reparseCapture())
	deadline = time.Now().Add(time.Second)
	var noRawID string
	for time.Now().Before(deadline) {
		items := withoutRaw.Snapshot()
		if len(items) == 1 {
			noRawID = items[0].ID
			break
		}
		time.Sleep(time.Millisecond)
	}
	w = requestRecorderMethod(recorderServer(withoutRaw), "POST", "/api/v1/observations/"+noRawID+"/reparse")
	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}
	if err := withoutRaw.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestHistoricalSQLiteRecorderAPI(t *testing.T) {
	path := filepath.Join(t.TempDir(), "history.db")
	r, err := recorder.New(recorder.Options{Raw: true, SQLitePath: path, SQLiteRetention: 10, RecentLimit: 1})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if !r.TryCapture(recorder.Meta{ConnectionID: "history-" + string(rune('0'+i)), ApplicationID: "example"}, reparseCapture()) {
			t.Fatal("enqueue")
		}
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	r, err = recorder.New(recorder.Options{Raw: true, SQLitePath: path, SQLiteRetention: 10, RecentLimit: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	h := recorderServer(r)
	w := requestRecorder(h, "/api/v1/observations?storage=sqlite&limit=2&q=history-")
	if w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	var page struct {
		Items []recorder.Observation `json:"items"`
		Next  string                 `json:"next_cursor"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &page); err != nil || len(page.Items) != 2 || page.Next == "" || !page.Items[0].RawClientHelloAvailable {
		t.Fatalf("historical page = %s", w.Body.String())
	}
	w = requestRecorder(h, "/api/v1/observations?storage=sqlite&limit=2&cursor="+page.Next+"&q=history-")
	if w.Code != 200 || !strings.Contains(w.Body.String(), "history-") {
		t.Fatalf("historical next page = %d %s", w.Code, w.Body.String())
	}
	w = requestRecorder(h, "/api/v1/observations/"+page.Items[0].ID+"?storage=sqlite")
	if w.Code != 200 || !strings.Contains(w.Body.String(), page.Items[0].ID) {
		t.Fatalf("historical detail = %d %s", w.Code, w.Body.String())
	}
	w = requestRecorder(h, "/api/v1/fingerprints/diff?storage=sqlite&a="+page.Items[0].ID+"&b="+page.Items[0].ID)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"status":"MATCH"`) || !strings.Contains(w.Body.String(), `"family":"tls_client_hello"`) {
		t.Fatalf("historical compare = %d %s", w.Code, w.Body.String())
	}
	w = requestRecorderMethod(h, "POST", "/api/v1/observations/"+page.Items[0].ID+"/reparse?storage=sqlite")
	if w.Code != http.StatusCreated || !strings.Contains(w.Body.String(), `"analysis_revision":2`) {
		t.Fatalf("historical single reparse = %d %s", w.Code, w.Body.String())
	}
	w = requestRecorder(h, "/api/v1/observations?storage=sqlite&limit=10&analysis_revision=2&q=history-")
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), page.Items[0].ID) {
		t.Fatalf("historical reparse revision search = %d %s", w.Code, w.Body.String())
	}
	w = requestRecorderMethod(h, "POST", "/api/v1/reparse/sqlite?limit=2&q=history-")
	if w.Code != 200 {
		t.Fatalf("historical reparse = %d %s", w.Code, w.Body.String())
	}
	var reparsePage recorder.ReparsePageResult
	if err := json.Unmarshal(w.Body.Bytes(), &reparsePage); err != nil || reparsePage.Scanned != 2 || reparsePage.Reparsed != 2 || reparsePage.NextCursor == "" {
		t.Fatalf("historical reparse page = %s", w.Body.String())
	}
	w = requestRecorderMethod(h, "POST", "/api/v1/reparse/sqlite?limit=2&cursor="+reparsePage.NextCursor+"&q=history-")
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"reparsed":1`) || strings.Contains(w.Body.String(), `"next_cursor"`) {
		t.Fatalf("historical reparse final page = %d %s", w.Code, w.Body.String())
	}
	w = requestRecorder(h, "/api/v1/export/observations?storage=sqlite&format=jsonl&q=history-&analysis_revision=1")
	if w.Code != 200 || strings.Count(w.Body.String(), "history-") != 3 {
		t.Fatalf("historical JSONL export = %d %s", w.Code, w.Body.String())
	}
	w = requestRecorder(h, "/api/v1/export/observations?storage=sqlite&format=csv&application_id=example")
	if w.Code != 200 || !strings.Contains(w.Body.String(), "observation_id,captured_at") {
		t.Fatalf("historical CSV export = %d %s", w.Code, w.Body.String())
	}
	backup := requestRecorder(h, "/api/v1/export/telemetry")
	if backup.Code != 200 || backup.Header().Get("Content-Type") != "application/vnd.sqlite3" || len(backup.Body.Bytes()) == 0 {
		t.Fatalf("telemetry backup = %d %s", backup.Code, backup.Body.String())
	}
	backupPath := filepath.Join(t.TempDir(), "telemetry-backup.db")
	if err := os.WriteFile(backupPath, backup.Body.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", backupPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM observations`).Scan(&count); err != nil || count != 7 {
		t.Fatalf("telemetry backup observations = %d, err=%v", count, err)
	}
	targetPath := filepath.Join(t.TempDir(), "restored.db")
	target, err := recorder.New(recorder.Options{Raw: true, SQLitePath: targetPath, SQLiteRetention: 10})
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	restoreRequest := httptest.NewRequest("POST", "http://127.0.0.1/api/v1/import/telemetry", bytes.NewReader(backup.Body.Bytes()))
	restoreRequest.RemoteAddr = "127.0.0.1:10000"
	restoreRequest.Header.Set("Content-Type", "application/vnd.sqlite3")
	restoreResponse := httptest.NewRecorder()
	Server{Recorder: target}.Handler().ServeHTTP(restoreResponse, restoreRequest)
	if restoreResponse.Code != http.StatusOK || !strings.Contains(restoreResponse.Body.String(), `"imported":7`) {
		t.Fatalf("telemetry restore = %d %s", restoreResponse.Code, restoreResponse.Body.String())
	}
	restoreRequest = httptest.NewRequest("POST", "http://127.0.0.1/api/v1/import/telemetry", bytes.NewReader(backup.Body.Bytes()))
	restoreRequest.RemoteAddr = "127.0.0.1:10000"
	restoreRequest.Header.Set("Content-Type", "application/vnd.sqlite3")
	restoreResponse = httptest.NewRecorder()
	Server{Recorder: target}.Handler().ServeHTTP(restoreResponse, restoreRequest)
	if restoreResponse.Code != http.StatusOK || !strings.Contains(restoreResponse.Body.String(), `"imported":0`) {
		t.Fatalf("idempotent telemetry restore = %d %s", restoreResponse.Code, restoreResponse.Body.String())
	}
}

func recorderServer(r *recorder.Recorder) http.Handler {
	return Server{Recorder: r}.Handler()
}

func TestRecorderRejectsRemoteAndRebinding(t *testing.T) {
	h := Server{}.Handler()
	for _, tt := range []struct{ host, peer, origin string }{{"evil.example", "127.0.0.1:20", ""}, {"127.0.0.1", "192.0.2.1:20", ""}, {"127.0.0.1", "127.0.0.1:20", "https://evil.example"}} {
		r := httptest.NewRequest("GET", "http://"+tt.host+"/api/v1/observations", nil)
		r.RemoteAddr = tt.peer
		r.Header.Set("Origin", tt.origin)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != 403 {
			t.Fatalf("%+v accepted", tt)
		}
	}
}
