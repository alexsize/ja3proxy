package webpanel

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
)

func (panel Server) handleTokenList(w http.ResponseWriter, r *http.Request) {
	if !panel.requireTokenAdmin(w, r) {
		return
	}
	if panel.TokenRegistry == nil {
		writeAPIError(w, http.StatusServiceUnavailable, "реестр токенов SQLite недоступен")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(map[string]any{"tokens": panel.TokenRegistry.List()})
}

func (panel Server) handleTokenIssue(w http.ResponseWriter, r *http.Request) {
	if !panel.requireTokenAdmin(w, r) {
		return
	}
	if !panel.requireTokenAudit(w) {
		return
	}
	if panel.TokenRegistry == nil {
		writeAPIError(w, http.StatusServiceUnavailable, "реестр токенов SQLite недоступен")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 8<<10)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	var input TokenIssue
	if err := decoder.Decode(&input); err != nil {
		writeAPIError(w, http.StatusBadRequest, "некорректный запрос выпуска токена")
		return
	}
	if err := requireJSONEnd(decoder); err != nil {
		writeAPIError(w, http.StatusBadRequest, "ожидался один JSON-объект")
		return
	}
	issued, err := panel.TokenRegistry.Issue(input)
	if err != nil {
		status := http.StatusBadRequest
		if strings.Contains(err.Error(), "already exists") {
			status = http.StatusConflict
		}
		writeAPIError(w, status, err.Error())
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(issued)
}

func (panel Server) handleTokenRotate(w http.ResponseWriter, r *http.Request) {
	if !panel.requireTokenAdmin(w, r) {
		return
	}
	if !panel.requireTokenAudit(w) {
		return
	}
	if panel.TokenRegistry == nil {
		writeAPIError(w, http.StatusServiceUnavailable, "реестр токенов SQLite недоступен")
		return
	}
	issued, err := panel.TokenRegistry.Rotate(r.PathValue("id"))
	if err != nil {
		status := http.StatusNotFound
		if !errors.Is(err, errTokenNotFound) {
			status = http.StatusConflict
		}
		writeAPIError(w, status, err.Error())
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(issued)
}

func (panel Server) handleTokenUpdate(w http.ResponseWriter, r *http.Request) {
	if !panel.requireTokenAdmin(w, r) {
		return
	}
	if !panel.requireTokenAudit(w) {
		return
	}
	if panel.TokenRegistry == nil {
		writeAPIError(w, http.StatusServiceUnavailable, "реестр токенов SQLite недоступен")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 8<<10)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	var input TokenUpdate
	if err := decoder.Decode(&input); err != nil {
		writeAPIError(w, http.StatusBadRequest, "некорректное обновление роли токена")
		return
	}
	if err := requireJSONEnd(decoder); err != nil {
		writeAPIError(w, http.StatusBadRequest, "ожидался один JSON-объект")
		return
	}
	entry, err := panel.TokenRegistry.Update(r.PathValue("id"), input)
	if err != nil {
		status := http.StatusBadRequest
		if errors.Is(err, errTokenNotFound) {
			status = http.StatusNotFound
		} else if strings.Contains(err.Error(), "last active admin") {
			status = http.StatusConflict
		}
		writeAPIError(w, status, err.Error())
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(entry)
}

func (panel Server) handleTokenRevoke(w http.ResponseWriter, r *http.Request) {
	if !panel.requireTokenAdmin(w, r) {
		return
	}
	if !panel.requireTokenAudit(w) {
		return
	}
	if panel.TokenRegistry == nil {
		writeAPIError(w, http.StatusServiceUnavailable, "реестр токенов SQLite недоступен")
		return
	}
	entry, err := panel.TokenRegistry.Revoke(r.PathValue("id"))
	if err != nil {
		status := http.StatusConflict
		if errors.Is(err, errTokenNotFound) {
			status = http.StatusNotFound
		}
		writeAPIError(w, status, err.Error())
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(entry)
}

func (panel Server) requireTokenAudit(w http.ResponseWriter) bool {
	if panel.Audit != nil {
		return true
	}
	writeAPIError(w, http.StatusServiceUnavailable, "аудит недоступен; управление токенами отклонено")
	return false
}

func (panel Server) requireTokenAdmin(w http.ResponseWriter, r *http.Request) bool {
	if loopbackPanelAddress(panel.Address) {
		return true
	}
	principal, ok := r.Context().Value(authPrincipalKey{}).(AuthToken)
	if !ok || principal.Role != "admin" {
		writeAPIError(w, http.StatusForbidden, "требуется роль admin")
		return false
	}
	return true
}

func requireJSONEnd(decoder *json.Decoder) error {
	var extra any
	err := decoder.Decode(&extra)
	if errors.Is(err, io.EOF) {
		return nil
	}
	if err != nil {
		return err
	}
	return errors.New("extra JSON value")
}
