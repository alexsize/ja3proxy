package webpanel

import (
	"encoding/csv"
	"encoding/json"
	"net/http"
	"sort"
	"strconv"
	"time"

	"github.com/lylemi/ja3proxy/internal/ja3proxy/recorder"
)

type fingerprintTimelinePoint struct {
	ObservationID      string    `json:"observation_id"`
	CapturedAt         time.Time `json:"captured_at"`
	ConnectionID       string    `json:"connection_id"`
	DeviceID           string    `json:"device_id,omitempty"`
	Application        string    `json:"application,omitempty"`
	ApplicationID      string    `json:"application_id,omitempty"`
	ApplicationVersion string    `json:"application_version,omitempty"`
	JA3                string    `json:"ja3"`
	JA3Hash            string    `json:"ja3_hash"`
	JA4                string    `json:"ja4"`
	ProfileID          string    `json:"profile_id,omitempty"`
	ProfileVersion     uint64    `json:"profile_version,omitempty"`
	Changed            bool      `json:"changed"`
}

func (panel Server) fingerprintTimeline(w http.ResponseWriter, r *http.Request) {
	if panel.Recorder == nil {
		writeAPIError(w, http.StatusServiceUnavailable, "recorder is disabled")
		return
	}
	filter, ok := parseObservationFilter(w, r)
	if !ok {
		return
	}
	points := buildFingerprintTimeline(filteredObservations(panel.Recorder.Snapshot(), filter))
	_ = json.NewEncoder(w).Encode(struct {
		Items []fingerprintTimelinePoint `json:"items"`
	}{points})
}

func buildFingerprintTimeline(observations []recorder.Observation) []fingerprintTimelinePoint {
	points := make([]fingerprintTimelinePoint, 0, len(observations))
	for _, observation := range observations {
		if observation.Fingerprints == nil {
			continue
		}
		fingerprints := observation.Fingerprints
		points = append(points, fingerprintTimelinePoint{
			ObservationID: observation.ID, CapturedAt: observation.CapturedAt, ConnectionID: observation.ConnectionID,
			DeviceID: observation.ResolvedDeviceID, Application: observation.Application, ApplicationID: observation.ApplicationID,
			ApplicationVersion: observation.ApplicationVersion, JA3: fingerprints.JA3, JA3Hash: fingerprints.JA3Hash,
			JA4: fingerprints.JA4, ProfileID: observation.ProfileID, ProfileVersion: observation.ProfileVersion,
		})
	}
	sort.SliceStable(points, func(i, j int) bool { return points[i].CapturedAt.Before(points[j].CapturedAt) })
	previous := make(map[string]fingerprintTimelinePoint)
	for i := range points {
		key := points[i].DeviceID + "\x00" + points[i].ApplicationID + "\x00" + points[i].Application
		last, found := previous[key]
		points[i].Changed = !found || points[i].JA3 != last.JA3 || points[i].JA4 != last.JA4 || points[i].JA3Hash != last.JA3Hash
		previous[key] = points[i]
	}
	return points
}

func writeFingerprintCSV(w http.ResponseWriter, observations []recorder.Observation) {
	writer := csv.NewWriter(w)
	_ = writer.Write([]string{"observation_id", "captured_at", "device_id", "application", "application_id", "application_version", "destination", "ja3", "ja3_hash", "ja4", "profile_id", "profile_version", "verification_status"})
	for _, observation := range observations {
		if observation.Fingerprints == nil {
			continue
		}
		verification := ""
		if observation.Verification != nil {
			verification = observation.Verification.Status
		}
		_ = writer.Write([]string{
			observation.ID, observation.CapturedAt.UTC().Format(time.RFC3339Nano), observation.ResolvedDeviceID,
			observation.Application, observation.ApplicationID, observation.ApplicationVersion, observation.Destination,
			observation.Fingerprints.JA3, observation.Fingerprints.JA3Hash, observation.Fingerprints.JA4,
			observation.ProfileID, strconv.FormatUint(observation.ProfileVersion, 10), verification,
		})
	}
	writer.Flush()
}
