package webpanel

import (
	"encoding/json"
	"encoding/pem"
	"net/http"
)

func (panel Server) handleCACertificate(w http.ResponseWriter, r *http.Request) {
	if panel.CACertificate == nil {
		writeAPIError(w, http.StatusServiceUnavailable, "CA недоступен")
		return
	}
	certificate := panel.CACertificate()
	if certificate == nil || len(certificate.Raw) == 0 {
		writeAPIError(w, http.StatusServiceUnavailable, "CA не загружен")
		return
	}
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Header().Set("Content-Disposition", `attachment; filename="ja3proxy-ca.pem"`)
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Raw}))
}

func (panel Server) handleCAReload(w http.ResponseWriter, r *http.Request) {
	if !panel.requireTokenAdmin(w, r) {
		return
	}
	if panel.Audit == nil {
		writeAPIError(w, http.StatusServiceUnavailable, "аудит недоступен; смена CA отклонена")
		return
	}
	if panel.ReloadCA == nil {
		writeAPIError(w, http.StatusNotImplemented, "повторная загрузка CA недоступна")
		return
	}
	if r.ContentLength > 0 {
		writeAPIError(w, http.StatusBadRequest, "запрос не должен содержать тело")
		return
	}
	status, err := panel.ReloadCA()
	if err != nil {
		writeAPIError(w, http.StatusConflict, "не удалось загрузить CA; прежний CA оставлен активным")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(struct {
		Runtime RuntimeStatus `json:"runtime"`
	}{Runtime: status})
}

func (panel Server) handleCARotate(w http.ResponseWriter, r *http.Request) {
	if !panel.requireTokenAdmin(w, r) {
		return
	}
	if panel.Audit == nil {
		writeAPIError(w, http.StatusServiceUnavailable, "аудит недоступен; ротация CA отклонена")
		return
	}
	if panel.RotateCA == nil {
		writeAPIError(w, http.StatusNotImplemented, "ротация CA недоступна")
		return
	}
	if r.ContentLength > 0 {
		writeAPIError(w, http.StatusBadRequest, "запрос не должен содержать тело")
		return
	}
	status, err := panel.RotateCA()
	if err != nil {
		writeAPIError(w, http.StatusConflict, "не удалось выполнить ротацию CA; активный CA не изменён")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(struct {
		Runtime                 RuntimeStatus `json:"runtime"`
		ClientTrustInstallation bool          `json:"client_trust_installation_required"`
	}{Runtime: status, ClientTrustInstallation: true})
}
