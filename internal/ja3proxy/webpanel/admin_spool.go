package webpanel

import (
	"errors"
	"net/http"

	"github.com/lylemi/ja3proxy/internal/ja3proxy/recorder"
)

func (panel Server) handleSpoolKeyReload(w http.ResponseWriter, r *http.Request) {
	if !panel.requireTokenAdmin(w, r) {
		return
	}
	if panel.Audit == nil {
		writeAPIError(w, http.StatusServiceUnavailable, "аудит недоступен; смена ключа отклонена")
		return
	}
	if r.ContentLength > 0 {
		writeAPIError(w, http.StatusBadRequest, "запрос не должен содержать тело")
		return
	}
	err := panel.Recorder.ReloadSpoolKey()
	switch {
	case errors.Is(err, recorder.ErrSpoolUnavailable):
		writeAPIError(w, http.StatusServiceUnavailable, "зашифрованный spool не включён или recorder остановлен")
	case errors.Is(err, recorder.ErrSpoolPending):
		writeAPIError(w, http.StatusConflict, "spool содержит ожидающие записи; сохранён прежний ключ. Верните прежний файл ключа до перезапуска")
	case err != nil:
		writeAPIError(w, http.StatusConflict, "ключ не применён; проверьте файл ключа и доступность spool. Прежний ключ сохранён")
	default:
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusNoContent)
	}
}
