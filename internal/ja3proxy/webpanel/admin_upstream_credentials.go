package webpanel

import "net/http"

func (panel Server) handleUpstreamCredentialsReload(w http.ResponseWriter, r *http.Request) {
	if !panel.requireTokenAdmin(w, r) {
		return
	}
	if panel.Audit == nil {
		writeAPIError(w, http.StatusServiceUnavailable, "аудит недоступен; обновление upstream credentials отклонено")
		return
	}
	if panel.ReloadUpstreamCredentials == nil {
		writeAPIError(w, http.StatusNotImplemented, "обновление upstream credentials недоступно")
		return
	}
	if r.ContentLength > 0 {
		writeAPIError(w, http.StatusBadRequest, "запрос не должен содержать тело")
		return
	}
	if _, err := panel.ReloadUpstreamCredentials(); err != nil {
		writeAPIError(w, http.StatusConflict, "не удалось применить upstream credential-файлы; прежние подключения не затронуты")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusNoContent)
}
