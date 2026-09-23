package webpanel

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/lylemi/ja3proxy/internal/ja3proxy/device"
)

type deviceMutation struct {
	ExpectedVersion uint64        `json:"expected_version"`
	Device          device.Device `json:"device"`
}

func (panel Server) getDevice(w http.ResponseWriter, r *http.Request) {
	if panel.Devices == nil {
		writeAPIError(w, http.StatusServiceUnavailable, "реестр устройств недоступен")
		return
	}
	item, ok := panel.Devices.Get(r.PathValue("id"))
	if !ok {
		writeAPIError(w, http.StatusNotFound, "устройство не найдено")
		return
	}
	_ = json.NewEncoder(w).Encode(item)
}

func (panel Server) createDevice(w http.ResponseWriter, r *http.Request) {
	if panel.Devices == nil {
		writeAPIError(w, http.StatusServiceUnavailable, "реестр устройств недоступен")
		return
	}
	var request deviceMutation
	if !decodeProfileRequest(w, r, &request) {
		return
	}
	created, registry, err := panel.Devices.Create(request.Device, request.ExpectedVersion)
	if writeDeviceMutationError(w, err) {
		return
	}
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(map[string]any{"device": created, "registry": registry})
}

func (panel Server) updateDevice(w http.ResponseWriter, r *http.Request) {
	if panel.Devices == nil {
		writeAPIError(w, http.StatusServiceUnavailable, "реестр устройств недоступен")
		return
	}
	var request deviceMutation
	if !decodeProfileRequest(w, r, &request) {
		return
	}
	updated, registry, err := panel.Devices.Update(r.PathValue("id"), request.Device, request.ExpectedVersion)
	if writeDeviceMutationError(w, err) {
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"device": updated, "registry": registry})
}

func (panel Server) deleteDevice(w http.ResponseWriter, r *http.Request) {
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
	registry, err := panel.Devices.Delete(r.PathValue("id"), request.ExpectedVersion)
	if writeDeviceMutationError(w, err) {
		return
	}
	_ = json.NewEncoder(w).Encode(registry)
}

func writeDeviceMutationError(w http.ResponseWriter, err error) bool {
	if err == nil {
		return false
	}
	switch {
	case errors.Is(err, device.ErrVersionConflict):
		writeAPIError(w, http.StatusConflict, "реестр устройств изменился; обновите список и повторите действие")
	case errors.Is(err, device.ErrDeviceNotFound):
		writeAPIError(w, http.StatusNotFound, "устройство не найдено")
	case errors.Is(err, device.ErrDeviceHasAssignments):
		writeAPIError(w, http.StatusConflict, "сначала удалите временные привязки устройства")
	case errors.Is(err, device.ErrPersistence):
		writeAPIError(w, http.StatusServiceUnavailable, "не удалось сохранить реестр устройств")
	default:
		writeAPIError(w, http.StatusBadRequest, err.Error())
	}
	return true
}
