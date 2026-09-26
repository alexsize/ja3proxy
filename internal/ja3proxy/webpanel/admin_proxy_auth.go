package webpanel

import "net/http"

func (panel Server) handleProxyAuthReload(w http.ResponseWriter, r *http.Request) {
	if !panel.requireTokenAdmin(w, r) {
		return
	}
	if panel.Audit == nil {
		writeAPIError(w, http.StatusServiceUnavailable, "аудит недоступен; обновление proxy-аутентификации отклонено")
		return
	}
	if panel.ReloadProxyAuth == nil {
		writeAPIError(w, http.StatusNotImplemented, "обновление proxy-аутентификации недоступно")
		return
	}
	if r.ContentLength > 0 {
		writeAPIError(w, http.StatusBadRequest, "запрос не должен содержать тело")
		return
	}
	if _, err := panel.ReloadProxyAuth(); err != nil {
		writeAPIError(w, http.StatusConflict, "не удалось применить proxy credential-файлы; прежние учётные данные сохранены")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusNoContent)
}
