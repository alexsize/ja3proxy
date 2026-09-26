package webpanel

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"

	"github.com/lylemi/ja3proxy/internal/ja3proxy/fingerprint"
	"github.com/lylemi/ja3proxy/internal/ja3proxy/tlsprofile"
)

type templateMutation struct {
	ExpectedVersion uint64              `json:"expected_version"`
	Template        tlsprofile.Template `json:"template"`
}

func (panel Server) registerProfileRoutes(mux *http.ServeMux) {
	routes := map[string]http.HandlerFunc{
		"POST /api/v1/replay-lab/run":                panel.runReplayLab,
		"GET /api/v1/tls/profiles":                   panel.listTLSProfiles,
		"GET /api/v1/tls/profiles/{id}":              panel.getTLSProfile,
		"GET /api/v1/tls/profiles/{id}/versions":     panel.getTLSProfileVersions,
		"POST /api/v1/tls/profiles/from-preset":      panel.profileFromPreset,
		"POST /api/v1/tls/profiles/preview":          panel.previewTLSProfile,
		"POST /api/v1/tls/profiles/from-observation": panel.profileFromObservation,
		"POST /api/v1/tls/profiles":                  panel.createTLSProfile,
		"PUT /api/v1/tls/profiles/{id}":              panel.updateTLSProfile,
		"DELETE /api/v1/tls/profiles/{id}":           panel.deleteTLSProfile,
		"POST /api/v1/tls/profiles/{id}/rollback":    panel.rollbackTLSProfile,
		"PUT /api/v1/tls/profiles/active":            panel.activateTLSProfile,
	}
	for pattern, handler := range routes {
		mux.Handle(pattern, recorderLocalOnly(handler))
	}
}

func (panel Server) getTLSProfileVersions(w http.ResponseWriter, r *http.Request) {
	history := panel.Profiles.History(r.PathValue("id"))
	if len(history) == 0 {
		writeAPIError(w, http.StatusNotFound, "история TLS-профиля не найдена")
		return
	}
	json.NewEncoder(w).Encode(history)
}

func (panel Server) listTLSProfiles(w http.ResponseWriter, _ *http.Request) {
	json.NewEncoder(w).Encode(panel.Profiles.Snapshot())
}

func (panel Server) getTLSProfile(w http.ResponseWriter, r *http.Request) {
	profile, ok := panel.Profiles.Get(r.PathValue("id"))
	if !ok {
		writeAPIError(w, http.StatusNotFound, "TLS-профиль не найден")
		return
	}
	json.NewEncoder(w).Encode(profile)
}

func (panel Server) profileFromPreset(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Name         string                     `json:"name"`
		FamilyID     string                     `json:"family_id"`
		BasePreset   fingerprint.TLSFingerprint `json:"base_preset"`
		HostPatterns []string                   `json:"host_patterns"`
	}
	if !decodeProfileRequest(w, r, &request) {
		return
	}
	template, err := tlsprofile.TemplateFromPreset(request.Name, request.BasePreset.Client, request.BasePreset.Version)
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, err.Error())
		return
	}
	template.HostPatterns = request.HostPatterns
	template.FamilyID = request.FamilyID
	template, err = tlsprofile.Preview(template)
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, err.Error())
		return
	}
	json.NewEncoder(w).Encode(template)
}

func (panel Server) previewTLSProfile(w http.ResponseWriter, r *http.Request) {
	var template tlsprofile.Template
	if !decodeProfileRequest(w, r, &template) {
		return
	}
	preview, err := tlsprofile.Preview(template)
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, err.Error())
		return
	}
	json.NewEncoder(w).Encode(preview)
}

func (panel Server) createTLSProfile(w http.ResponseWriter, r *http.Request) {
	var request templateMutation
	if !decodeProfileRequest(w, r, &request) {
		return
	}
	created, library, err := panel.Profiles.Create(request.Template, request.ExpectedVersion)
	if writeProfileMutationError(w, err) {
		return
	}
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]any{"template": created, "library": library})
}

func (panel Server) updateTLSProfile(w http.ResponseWriter, r *http.Request) {
	var request templateMutation
	if !decodeProfileRequest(w, r, &request) {
		return
	}
	updated, library, err := panel.Profiles.Update(r.PathValue("id"), request.Template, request.ExpectedVersion)
	if writeProfileMutationError(w, err) {
		return
	}
	json.NewEncoder(w).Encode(map[string]any{"template": updated, "library": library})
}

func (panel Server) deleteTLSProfile(w http.ResponseWriter, r *http.Request) {
	var request struct {
		ExpectedVersion uint64 `json:"expected_version"`
	}
	if !decodeProfileRequest(w, r, &request) {
		return
	}
	library, err := panel.Profiles.Delete(r.PathValue("id"), request.ExpectedVersion)
	if writeProfileMutationError(w, err) {
		return
	}
	json.NewEncoder(w).Encode(library)
}

func (panel Server) rollbackTLSProfile(w http.ResponseWriter, r *http.Request) {
	var request struct {
		ExpectedVersion uint64 `json:"expected_version"`
		TargetVersion   uint64 `json:"target_version"`
	}
	if !decodeProfileRequest(w, r, &request) {
		return
	}
	rolledBack, library, err := panel.Profiles.Rollback(r.PathValue("id"), request.TargetVersion, request.ExpectedVersion)
	if writeProfileMutationError(w, err) {
		return
	}
	json.NewEncoder(w).Encode(map[string]any{"template": rolledBack, "library": library})
}

func (panel Server) activateTLSProfile(w http.ResponseWriter, r *http.Request) {
	var request struct {
		ExpectedVersion uint64   `json:"expected_version"`
		ID              string   `json:"id"`
		IDs             []string `json:"ids"`
	}
	if !decodeProfileRequest(w, r, &request) {
		return
	}
	var library tlsprofile.Library
	var err error
	if len(request.IDs) > 0 {
		library, err = panel.Profiles.ActivateMany(request.IDs, request.ExpectedVersion)
	} else {
		library, err = panel.Profiles.Activate(request.ID, request.ExpectedVersion)
	}
	if writeProfileMutationError(w, err) {
		return
	}
	json.NewEncoder(w).Encode(library)
}

func (panel Server) profileFromObservation(w http.ResponseWriter, r *http.Request) {
	var request struct {
		ExpectedVersion uint64                     `json:"expected_version"`
		ObservationID   string                     `json:"observation_id"`
		Name            string                     `json:"name"`
		FamilyID        string                     `json:"family_id"`
		BasePreset      fingerprint.TLSFingerprint `json:"base_preset"`
		HostPatterns    []string                   `json:"host_patterns"`
		Save            bool                       `json:"save"`
	}
	if !decodeProfileRequest(w, r, &request) {
		return
	}
	if panel.Recorder == nil {
		writeAPIError(w, http.StatusServiceUnavailable, "recorder выключен; наблюдения недоступны")
		return
	}
	var found bool
	var template tlsprofile.Template
	for _, observation := range panel.Recorder.Snapshot() {
		if observation.ID != request.ObservationID || observation.Hello == nil || observation.Fingerprints == nil {
			continue
		}
		fields, err := tlsprofile.FieldsFromHello(observation.Hello)
		if err != nil {
			writeAPIError(w, http.StatusBadRequest, err.Error())
			return
		}
		template = tlsprofile.Template{
			Name: request.Name, FamilyID: request.FamilyID, ProfileType: tlsprofile.ProfileTypeObserved, Enabled: true, HostPatterns: request.HostPatterns,
			BasePreset: request.BasePreset, Fields: fields, Policy: tlsprofile.DefaultMatchPolicy(), SourceObservationID: observation.ID,
			Source: &tlsprofile.ObservedSource{
				ObservationID: observation.ID, ServerName: observation.Hello.ServerName,
				JA3: observation.Fingerprints.JA3, JA3Hash: observation.Fingerprints.JA3Hash, JA4: observation.Fingerprints.JA4,
				NormalizedSHA256: observation.Fingerprints.NormalizedSHA256, Normalized: append([]byte(nil), observation.Fingerprints.Normalized...),
				NormalizationVersion: observation.Fingerprints.NormalizationVersion,
			},
		}
		found = true
		break
	}
	if !found {
		writeAPIError(w, http.StatusNotFound, "наблюдение отсутствует в окне памяти или не содержит полного ClientHello")
		return
	}
	if !request.Save {
		preview, err := tlsprofile.Preview(template)
		if err != nil {
			writeAPIError(w, http.StatusBadRequest, err.Error())
			return
		}
		json.NewEncoder(w).Encode(preview)
		return
	}
	created, library, err := panel.Profiles.Create(template, request.ExpectedVersion)
	if writeProfileMutationError(w, err) {
		return
	}
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]any{"template": created, "library": library})
}

func decodeProfileRequest(w http.ResponseWriter, r *http.Request, destination any) bool {
	if contentType := r.Header.Get("Content-Type"); contentType != "application/json" && contentType != "application/json; charset=utf-8" {
		writeAPIError(w, http.StatusUnsupportedMediaType, "Content-Type должен быть application/json")
		return false
	}
	r.Body = http.MaxBytesReader(w, r.Body, 128<<10)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		writeAPIError(w, http.StatusBadRequest, "некорректный JSON: "+err.Error())
		return false
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		writeAPIError(w, http.StatusBadRequest, "запрос должен содержать один JSON-объект")
		return false
	}
	return true
}

func writeProfileMutationError(w http.ResponseWriter, err error) bool {
	if err == nil {
		return false
	}
	switch {
	case errors.Is(err, tlsprofile.ErrVersionConflict):
		writeAPIError(w, http.StatusConflict, "конфигурация изменилась; обновите список и повторите действие")
	case errors.Is(err, os.ErrNotExist):
		writeAPIError(w, http.StatusNotFound, "TLS-профиль не найден")
	default:
		writeAPIError(w, http.StatusBadRequest, err.Error())
	}
	return true
}
