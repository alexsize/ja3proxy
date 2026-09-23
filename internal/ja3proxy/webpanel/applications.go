package webpanel

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/lylemi/ja3proxy/internal/ja3proxy/device"
)

type applicationMutation struct {
	ExpectedVersion uint64             `json:"expected_version"`
	Application     device.Application `json:"application"`
}

func (panel Server) applications(w http.ResponseWriter, _ *http.Request) {
	if panel.Devices == nil {
		writeAPIError(w, http.StatusServiceUnavailable, "реестр устройств недоступен")
		return
	}
	snapshot := panel.Devices.Snapshot()
	items := snapshot.Applications
	if items == nil {
		items = []device.Application{}
	}
	_ = json.NewEncoder(w).Encode(struct {
		SchemaVersion string               `json:"schema_version"`
		ConfigVersion uint64               `json:"config_version"`
		Items         []device.Application `json:"items"`
	}{snapshot.SchemaVersion, snapshot.ConfigVersion, items})
}

func (panel Server) getApplication(w http.ResponseWriter, r *http.Request) {
	if panel.Devices == nil {
		writeAPIError(w, http.StatusServiceUnavailable, "реестр устройств недоступен")
		return
	}
	application, ok := panel.Devices.GetApplication(r.PathValue("id"))
	if !ok {
		writeAPIError(w, http.StatusNotFound, "приложение не найдено")
		return
	}
	_ = json.NewEncoder(w).Encode(application)
}

func (panel Server) createApplication(w http.ResponseWriter, r *http.Request) {
	if panel.Devices == nil {
		writeAPIError(w, http.StatusServiceUnavailable, "реестр устройств недоступен")
		return
	}
	var request applicationMutation
	if !decodeProfileRequest(w, r, &request) {
		return
	}
	created, registry, err := panel.Devices.CreateApplication(request.Application, request.ExpectedVersion)
	if writeApplicationMutationError(w, err) {
		return
	}
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(map[string]any{"application": created, "registry": registry})
}

func (panel Server) updateApplication(w http.ResponseWriter, r *http.Request) {
	if panel.Devices == nil {
		writeAPIError(w, http.StatusServiceUnavailable, "реестр устройств недоступен")
		return
	}
	var request applicationMutation
	if !decodeProfileRequest(w, r, &request) {
		return
	}
	updated, registry, err := panel.Devices.UpdateApplication(r.PathValue("id"), request.Application, request.ExpectedVersion)
	if writeApplicationMutationError(w, err) {
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"application": updated, "registry": registry})
}

func (panel Server) deleteApplication(w http.ResponseWriter, r *http.Request) {
	if panel.Devices == nil {
		writeAPIError(w, http.StatusServiceUnavailable, "реестр устройств недоступен")
		return
	}
	var request struct {
		ExpectedVersion uint64 `json:"expected_version"`
	}
	if !decodeProfileRequest(w, r, &request) {
		return
	}
	registry, err := panel.Devices.DeleteApplication(r.PathValue("id"), request.ExpectedVersion)
	if writeApplicationMutationError(w, err) {
		return
	}
	_ = json.NewEncoder(w).Encode(registry)
}

func writeApplicationMutationError(w http.ResponseWriter, err error) bool {
	if err == nil {
		return false
	}
	switch {
	case errors.Is(err, device.ErrVersionConflict):
		writeAPIError(w, http.StatusConflict, "реестр устройств изменился; обновите список и повторите действие")
	case errors.Is(err, device.ErrApplicationNotFound):
		writeAPIError(w, http.StatusNotFound, "приложение не найдено")
	case errors.Is(err, device.ErrApplicationHasAssignments):
		writeAPIError(w, http.StatusConflict, "сначала удалите привязки приложения")
	case errors.Is(err, device.ErrPersistence):
		writeAPIError(w, http.StatusServiceUnavailable, "не удалось сохранить реестр устройств")
	default:
		writeAPIError(w, http.StatusBadRequest, err.Error())
	}
	return true
}
