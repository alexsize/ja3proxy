package webpanel

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/lylemi/ja3proxy/internal/ja3proxy/recorder"
)

type observationFilter struct {
	DeviceID           string
	Application        string
	ApplicationID      string
	ApplicationVersion string
	AnalysisRevision   int
	From               *time.Time
	To                 *time.Time
}

func parseObservationFilter(w http.ResponseWriter, r *http.Request) (observationFilter, bool) {
	filter := observationFilter{
		DeviceID:           strings.TrimSpace(r.URL.Query().Get("device_id")),
		Application:        strings.TrimSpace(r.URL.Query().Get("application")),
		ApplicationID:      strings.TrimSpace(r.URL.Query().Get("application_id")),
		ApplicationVersion: strings.TrimSpace(r.URL.Query().Get("application_version")),
	}
	if value := strings.TrimSpace(r.URL.Query().Get("analysis_revision")); value != "" {
		revision, err := strconv.Atoi(value)
		if err != nil || revision < 1 {
			writeAPIError(w, http.StatusBadRequest, "analysis_revision must be a positive integer")
			return observationFilter{}, false
		}
		filter.AnalysisRevision = revision
	}
	for name, destination := range map[string]**time.Time{"from": &filter.From, "to": &filter.To} {
		value := strings.TrimSpace(r.URL.Query().Get(name))
		if value == "" {
			continue
		}
		parsed, err := time.Parse(time.RFC3339, value)
		if err != nil {
			writeAPIError(w, http.StatusBadRequest, name+" must be RFC3339")
			return observationFilter{}, false
		}
		*destination = &parsed
	}
	if filter.From != nil && filter.To != nil && filter.To.Before(*filter.From) {
		writeAPIError(w, http.StatusBadRequest, "to must not be before from")
		return observationFilter{}, false
	}
	return filter, true
}

func (filter observationFilter) matches(observation recorder.Observation) bool {
	if filter.AnalysisRevision > 0 && observation.AnalysisRevision != filter.AnalysisRevision {
		return false
	}
	if filter.DeviceID != "" && observation.ResolvedDeviceID != filter.DeviceID {
		return false
	}
	if filter.Application != "" && !strings.EqualFold(observation.Application, filter.Application) {
		return false
	}
	if filter.ApplicationID != "" && observation.ApplicationID != filter.ApplicationID {
		return false
	}
	if filter.ApplicationVersion != "" && observation.ApplicationVersion != filter.ApplicationVersion {
		return false
	}
	if filter.From != nil && observation.CapturedAt.Before(*filter.From) {
		return false
	}
	if filter.To != nil && !observation.CapturedAt.Before(*filter.To) {
		return false
	}
	return true
}

func storedObservationQuery(filter observationFilter, request *http.Request, limit int) recorder.StoredQuery {
	return recorder.StoredQuery{
		Limit:              limit,
		Cursor:             strings.TrimSpace(request.URL.Query().Get("cursor")),
		Search:             strings.TrimSpace(request.URL.Query().Get("q")),
		DeviceID:           filter.DeviceID,
		Application:        filter.Application,
		ApplicationID:      filter.ApplicationID,
		ApplicationVersion: filter.ApplicationVersion,
		AnalysisRevision:   filter.AnalysisRevision,
		From:               filter.From,
		To:                 filter.To,
	}
}

func filteredObservations(observations []recorder.Observation, filter observationFilter) []recorder.Observation {
	filtered := make([]recorder.Observation, 0, len(observations))
	for _, observation := range observations {
		if filter.matches(observation) {
			filtered = append(filtered, observation)
		}
	}
	return filtered
}
