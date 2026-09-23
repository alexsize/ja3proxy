package webpanel

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/lylemi/ja3proxy/internal/ja3proxy/device"
)

type assignmentMutation struct {
	ExpectedVersion uint64                       `json:"expected_version"`
	Assignment      device.ApplicationAssignment `json:"assignment"`
}

func (panel Server) assignments(w http.ResponseWriter, _ *http.Request) {
	if panel.Devices == nil {
		writeAPIError(w, http.StatusServiceUnavailable, "реестр устройств недоступен")
		return
	}
	snapshot := panel.Devices.Snapshot()
	items := snapshot.Assignments
	if items == nil {
		items = []device.ApplicationAssignment{}
	}
	_ = json.NewEncoder(w).Encode(struct {
		SchemaVersion string                         `json:"schema_version"`
		ConfigVersion uint64                         `json:"config_version"`
		Items         []device.ApplicationAssignment `json:"items"`
	}{snapshot.SchemaVersion, snapshot.ConfigVersion, items})
}

func (panel Server) getAssignment(w http.ResponseWriter, r *http.Request) {
	if panel.Devices == nil {
		writeAPIError(w, http.StatusServiceUnavailable, "реестр устройств недоступен")
		return
	}
	assignment, ok := panel.Devices.GetAssignment(r.PathValue("id"))
	if !ok {
		writeAPIError(w, http.StatusNotFound, "временная привязка не найдена")
		return
	}
	_ = json.NewEncoder(w).Encode(assignment)
}

func (panel Server) createAssignment(w http.ResponseWriter, r *http.Request) {
	if panel.Devices == nil {
		writeAPIError(w, http.StatusServiceUnavailable, "реестр устройств недоступен")
		return
	}
	var request assignmentMutation
	if !decodeProfileRequest(w, r, &request) {
		return
	}
	created, registry, err := panel.Devices.CreateAssignment(request.Assignment, request.ExpectedVersion)
	if writeAssignmentMutationError(w, err) {
		return
	}
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(map[string]any{"assignment": created, "registry": registry})
}

func (panel Server) updateAssignment(w http.ResponseWriter, r *http.Request) {
	if panel.Devices == nil {
		writeAPIError(w, http.StatusServiceUnavailable, "реестр устройств недоступен")
		return
	}
	var request assignmentMutation
	if !decodeProfileRequest(w, r, &request) {
		return
	}
	updated, registry, err := panel.Devices.UpdateAssignment(r.PathValue("id"), request.Assignment, request.ExpectedVersion)
	if writeAssignmentMutationError(w, err) {
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"assignment": updated, "registry": registry})
}

func (panel Server) deleteAssignment(w http.ResponseWriter, r *http.Request) {
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
	registry, err := panel.Devices.DeleteAssignment(r.PathValue("id"), request.ExpectedVersion)
	if writeAssignmentMutationError(w, err) {
		return
	}
	_ = json.NewEncoder(w).Encode(registry)
}

func writeAssignmentMutationError(w http.ResponseWriter, err error) bool {
	if err == nil {
		return false
	}
	switch {
	case errors.Is(err, device.ErrVersionConflict):
		writeAPIError(w, http.StatusConflict, "реестр устройств изменился; обновите список и повторите действие")
	case errors.Is(err, device.ErrAssignmentNotFound):
		writeAPIError(w, http.StatusNotFound, "временная привязка не найдена")
	case errors.Is(err, device.ErrPersistence):
		writeAPIError(w, http.StatusServiceUnavailable, "не удалось сохранить реестр устройств")
	default:
		writeAPIError(w, http.StatusBadRequest, err.Error())
	}
	return true
}
