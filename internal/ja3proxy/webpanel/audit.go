package webpanel

import (
	"encoding/json"
	"net"
	"net/http"
	"strconv"
	"strings"

	"github.com/lylemi/ja3proxy/internal/ja3proxy/audit"
	"github.com/lylemi/ja3proxy/internal/ja3proxy/logutil"
)

type auditResponseWriter struct {
	http.ResponseWriter
	status int
}

func (w *auditResponseWriter) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}

func (w *auditResponseWriter) WriteHeader(status int) {
	if w.status != http.StatusOK {
		return
	}
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}

func (w *auditResponseWriter) Write(data []byte) (int, error) {
	if w.status == http.StatusOK {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(data)
}

func (panel Server) auditRequests(next http.Handler) http.Handler {
	if panel.Audit == nil {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !shouldAuditRequest(r) {
			next.ServeHTTP(w, r)
			return
		}
		event := audit.Event{
			Actor:    auditActor(r),
			Action:   strings.ToLower(r.Method),
			Object:   r.URL.Path,
			SourceIP: auditSourceIP(r),
			Result:   "requested",
		}
		if err := panel.Audit.Append(event); err != nil {
			writeAPIError(w, http.StatusServiceUnavailable, "журнал аудита недоступен; операция отклонена")
			return
		}
		response := &auditResponseWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(response, r)
		result := "success"
		if response.status < 200 || response.status >= 400 {
			result = "rejected"
		}
		event.Result = result
		if err := panel.Audit.Append(event); err != nil {
			// The requested event was already durably recorded before the
			// operation. Keep the response status intact and surface the
			// persistence failure to the process log for operational repair.
			logutil.Warn("webpanel", "failed appending audit result", "error", err, "path", r.URL.Path)
		}
	})
}

func shouldAuditRequest(r *http.Request) bool {
	if r == nil || r.URL == nil || r.URL.Path == "/api/v1/audit" {
		return false
	}
	if r.URL.Path == "/api/config" {
		return true
	}
	if strings.HasPrefix(r.URL.Path, "/api/v1/export/") && r.Method == http.MethodGet {
		return true
	}
	return strings.HasPrefix(r.URL.Path, "/api/v1/") && (r.Method == http.MethodPost || r.Method == http.MethodPut || r.Method == http.MethodPatch || r.Method == http.MethodDelete)
}

func auditActor(r *http.Request) string {
	if actor := authenticatedActor(r); actor != "" {
		return actor
	}
	if value := strings.TrimSpace(r.Header.Get("X-Operator")); value != "" {
		return value
	}
	return "anonymous"
}

func auditSourceIP(r *http.Request) string {
	peer, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		return peer
	}
	return strings.TrimSpace(r.RemoteAddr)
}

func (panel Server) auditEvents(w http.ResponseWriter, r *http.Request) {
	if panel.Audit == nil {
		writeAPIError(w, http.StatusServiceUnavailable, "журнал аудита недоступен")
		return
	}
	limit := 50
	if value := strings.TrimSpace(r.URL.Query().Get("limit")); value != "" {
		parsed, err := strconv.Atoi(value)
		if err != nil || parsed < 1 || parsed > 100 {
			writeAPIError(w, http.StatusBadRequest, "limit must be 1..100")
			return
		}
		limit = parsed
	}
	page, err := panel.Audit.Query(limit, strings.TrimSpace(r.URL.Query().Get("cursor")))
	if err != nil {
		if err == audit.ErrCursorNotFound {
			writeAPIError(w, http.StatusConflict, "курсор аудита больше недоступен")
			return
		}
		writeAPIError(w, http.StatusServiceUnavailable, err.Error())
		return
	}
	_ = json.NewEncoder(w).Encode(page)
}
