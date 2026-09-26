package webpanel

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/lylemi/ja3proxy/internal/ja3proxy/device"
	"github.com/lylemi/ja3proxy/internal/ja3proxy/recorder"
	"github.com/lylemi/ja3proxy/internal/ja3proxy/routing"
	"github.com/lylemi/ja3proxy/internal/ja3proxy/tlsprofile"
	"github.com/lylemi/ja3proxy/internal/ja3proxy/upstreamtls"
)

const configBackupSchemaVersion = "ja3proxy-config-backup/1"

// ConfigBackup contains restorable control-plane state without telemetry or
// plaintext upstream credentials.
type ConfigBackup struct {
	SchemaVersion            string                        `json:"schema_version"`
	ExportedAt               time.Time                     `json:"exported_at"`
	Runtime                  RuntimeStatus                 `json:"runtime"`
	Devices                  device.Registry               `json:"devices"`
	Profiles                 tlsprofile.Library            `json:"tls_profiles"`
	Routes                   routing.Config                `json:"routes"`
	RouteConfigVersion       uint64                        `json:"route_config_version"`
	UpstreamTLS              upstreamtls.UpstreamTLSConfig `json:"upstream_tls"`
	UpstreamTLSConfigVersion uint64                        `json:"upstream_tls_config_version"`
}

func (panel Server) exportConfig(w http.ResponseWriter, r *http.Request) {
	format := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("format")))
	if format == "" {
		format = "json"
	}
	if format != "json" && format != "zip" {
		writeAPIError(w, http.StatusBadRequest, "format must be json or zip")
		return
	}

	payload, err := json.MarshalIndent(panel.configBackup(), "", "  ")
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "не удалось подготовить резервную копию конфигурации")
		return
	}
	if format == "json" {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="ja3proxy-config-backup.json"`)
		_, _ = w.Write(append(payload, '\n'))
		return
	}

	var archive bytes.Buffer
	writer := zip.NewWriter(&archive)
	file, err := writer.Create("config.json")
	if err == nil {
		_, err = file.Write(append(payload, '\n'))
	}
	if err == nil {
		err = writer.Close()
	} else {
		_ = writer.Close()
	}
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "не удалось подготовить ZIP-резервную копию")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", `attachment; filename="ja3proxy-config-backup.zip"`)
	_, _ = w.Write(archive.Bytes())
}

// exportTelemetry returns a consistent standalone SQLite snapshot. It is
// intentionally separate from the control-plane JSON backup because telemetry
// can contain raw TLS evidence and is protected by the export/raw scopes.
func (panel Server) exportTelemetry(w http.ResponseWriter, r *http.Request) {
	if panel.Recorder == nil {
		writeAPIError(w, http.StatusServiceUnavailable, "recorder is disabled")
		return
	}
	temporary, err := os.CreateTemp("", "ja3proxy-telemetry-*.sqlite")
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "не удалось подготовить SQLite backup")
		return
	}
	path := temporary.Name()
	if err := temporary.Close(); err != nil {
		_ = os.Remove(path)
		writeAPIError(w, http.StatusInternalServerError, "не удалось подготовить SQLite backup")
		return
	}
	_ = os.Remove(path)
	defer os.Remove(path)
	if err := panel.Recorder.BackupSQLite(path); err != nil {
		if errors.Is(err, recorder.ErrHistoricalUnavailable) {
			writeAPIError(w, http.StatusServiceUnavailable, "durable SQLite storage is not enabled")
			return
		}
		writeAPIError(w, http.StatusServiceUnavailable, err.Error())
		return
	}
	file, err := os.Open(path)
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "не удалось открыть SQLite backup")
		return
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "не удалось определить размер SQLite backup")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/vnd.sqlite3")
	w.Header().Set("Content-Disposition", `attachment; filename="ja3proxy-telemetry.sqlite"`)
	w.Header().Set("Content-Length", strconv.FormatInt(info.Size(), 10))
	_, _ = io.Copy(w, file)
}

// importTelemetry merges a validated standalone SQLite snapshot into the
// active recorder. It deliberately never replaces the live database file.
func (panel Server) importTelemetry(w http.ResponseWriter, r *http.Request) {
	if panel.Recorder == nil {
		writeAPIError(w, http.StatusServiceUnavailable, "recorder is disabled")
		return
	}
	contentType := strings.ToLower(strings.TrimSpace(strings.Split(r.Header.Get("Content-Type"), ";")[0]))
	if contentType != "application/vnd.sqlite3" && contentType != "application/octet-stream" {
		writeAPIError(w, http.StatusUnsupportedMediaType, "Content-Type must be application/vnd.sqlite3 or application/octet-stream")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 2<<30)
	temporary, err := os.CreateTemp("", "ja3proxy-telemetry-restore-*.sqlite")
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "не удалось подготовить SQLite restore")
		return
	}
	path := temporary.Name()
	defer os.Remove(path)
	if _, err := io.Copy(temporary, r.Body); err != nil {
		_ = temporary.Close()
		writeAPIError(w, http.StatusBadRequest, "не удалось сохранить SQLite backup")
		return
	}
	if err := temporary.Close(); err != nil {
		writeAPIError(w, http.StatusBadRequest, "не удалось закрыть SQLite backup")
		return
	}
	imported, err := panel.Recorder.RestoreSQLiteBackup(path)
	if err != nil {
		if errors.Is(err, recorder.ErrHistoricalUnavailable) {
			writeAPIError(w, http.StatusServiceUnavailable, "durable SQLite storage is not enabled")
			return
		}
		writeAPIError(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(map[string]int{"imported": imported})
}

type configImportValidation struct {
	Valid      bool     `json:"valid"`
	Schema     string   `json:"schema_version"`
	Components []string `json:"components"`
	Errors     []string `json:"errors,omitempty"`
}

type configImportResult struct {
	Applied       []string          `json:"applied"`
	Skipped       []string          `json:"skipped,omitempty"`
	Warnings      []string          `json:"warnings,omitempty"`
	ConfigVersion map[string]uint64 `json:"config_versions,omitempty"`
}

func (panel Server) validateConfigImport(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 16<<20)
	data, err := io.ReadAll(r.Body)
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, "не удалось прочитать резервную копию")
		return
	}
	backup, err := decodeConfigBackup(data)
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, err.Error())
		return
	}
	result := validateConfigBackup(backup)
	status := http.StatusOK
	if !result.Valid {
		status = http.StatusUnprocessableEntity
	}
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(result)
}

func (panel Server) importConfig(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 16<<20)
	data, err := io.ReadAll(r.Body)
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, "не удалось прочитать резервную копию")
		return
	}
	backup, err := decodeConfigBackup(data)
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, err.Error())
		return
	}
	validation := validateConfigBackup(backup)
	if !validation.Valid {
		w.WriteHeader(http.StatusUnprocessableEntity)
		_ = json.NewEncoder(w).Encode(validation)
		return
	}

	expected, err := requiredRestoreVersions(r)
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, err.Error())
		return
	}
	result := configImportResult{Applied: []string{}, Skipped: []string{}, Warnings: []string{}, ConfigVersion: map[string]uint64{}}
	if panel.Devices != nil {
		if err := ensureDeviceVersion(panel.Devices.Snapshot().ConfigVersion, expected["devices"]); err != nil {
			writeRestoreConflict(w, err)
			return
		}
	}
	if panel.Profiles != nil {
		if err := ensureVersion(panel.Profiles.Snapshot().ConfigVersion, expected["tls_profiles"], "TLS profiles"); err != nil {
			writeRestoreConflict(w, err)
			return
		}
	}
	if panel.Routes != nil {
		_, version, _ := panel.Routes.Snapshot()
		if err := ensureVersion(version, expected["routes"], "routes"); err != nil {
			writeRestoreConflict(w, err)
			return
		}
	}
	if panel.UpstreamTLS != nil {
		_, version, _ := panel.UpstreamTLS.Snapshot()
		if err := ensureVersion(version, expected["upstream_tls"], "upstream TLS"); err != nil {
			writeRestoreConflict(w, err)
			return
		}
	}

	if panel.Devices != nil {
		registry, err := panel.Devices.Replace(backup.Devices, expected["devices"])
		if err != nil {
			writeRestoreError(w, err)
			return
		}
		result.Applied = append(result.Applied, "devices")
		result.ConfigVersion["devices"] = registry.ConfigVersion
	} else {
		result.Skipped = append(result.Skipped, "devices")
	}
	if panel.Profiles != nil {
		library, err := panel.Profiles.Replace(backup.Profiles, expected["tls_profiles"])
		if err != nil {
			writeRestoreError(w, err)
			return
		}
		result.Applied = append(result.Applied, "tls_profiles")
		result.ConfigVersion["tls_profiles"] = library.ConfigVersion
	} else {
		result.Skipped = append(result.Skipped, "tls_profiles")
	}
	if panel.Routes != nil {
		if err := panel.Routes.ReplaceValidated(backup.Routes, expected["routes"]); err != nil {
			writeRestoreError(w, err)
			return
		}
		result.Applied = append(result.Applied, "routes")
		_, version, _ := panel.Routes.Snapshot()
		result.ConfigVersion["routes"] = version
	} else {
		result.Skipped = append(result.Skipped, "routes")
	}
	if panel.UpstreamTLS != nil {
		if err := panel.UpstreamTLS.ReplaceValidated(backup.UpstreamTLS, expected["upstream_tls"]); err != nil {
			writeRestoreError(w, err)
			return
		}
		result.Applied = append(result.Applied, "upstream_tls")
		_, version, _ := panel.UpstreamTLS.Snapshot()
		result.ConfigVersion["upstream_tls"] = version
	} else {
		result.Skipped = append(result.Skipped, "upstream_tls")
	}
	result.Warnings = append(result.Warnings, "runtime settings are not restored because credentials are intentionally absent from backup")
	_ = json.NewEncoder(w).Encode(result)
}

func requiredRestoreVersions(r *http.Request) (map[string]uint64, error) {
	versions := make(map[string]uint64, 4)
	for _, name := range []string{"devices", "tls_profiles", "routes", "upstream_tls"} {
		value := strings.TrimSpace(r.URL.Query().Get("expected_" + name + "_version"))
		if value == "" {
			return nil, fmt.Errorf("expected_%s_version is required for restore", name)
		}
		version, err := strconv.ParseUint(value, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("expected_%s_version must be a non-negative integer", name)
		}
		versions[name] = version
	}
	return versions, nil
}

func ensureDeviceVersion(actual, expected uint64) error {
	return ensureVersion(actual, expected, "devices")
}

func ensureVersion(actual, expected uint64, name string) error {
	if actual != expected {
		return fmt.Errorf("%s config version conflict: current=%d expected=%d", name, actual, expected)
	}
	return nil
}

func writeRestoreConflict(w http.ResponseWriter, err error) {
	writeAPIError(w, http.StatusConflict, err.Error())
}

func writeRestoreError(w http.ResponseWriter, err error) {
	if errors.Is(err, device.ErrVersionConflict) || errors.Is(err, tlsprofile.ErrVersionConflict) || errors.Is(err, routing.ErrVersionConflict) || errors.Is(err, upstreamtls.ErrVersionConflict) {
		writeRestoreConflict(w, err)
		return
	}
	writeAPIError(w, http.StatusServiceUnavailable, err.Error())
}

func decodeConfigBackup(data []byte) (ConfigBackup, error) {
	if len(data) == 0 {
		return ConfigBackup{}, fmt.Errorf("резервная копия пуста")
	}
	if bytes.HasPrefix(data, []byte("PK\x03\x04")) {
		archive, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
		if err != nil {
			return ConfigBackup{}, fmt.Errorf("некорректный ZIP backup: %w", err)
		}
		var configData []byte
		for _, file := range archive.File {
			if file.Name != "config.json" {
				continue
			}
			reader, err := file.Open()
			if err != nil {
				return ConfigBackup{}, fmt.Errorf("открытие config.json: %w", err)
			}
			configData, err = io.ReadAll(io.LimitReader(reader, 16<<20+1))
			_ = reader.Close()
			if err != nil {
				return ConfigBackup{}, fmt.Errorf("чтение config.json: %w", err)
			}
			if len(configData) > 16<<20 {
				return ConfigBackup{}, fmt.Errorf("config.json превышает 16 МиБ")
			}
			break
		}
		if len(configData) == 0 {
			return ConfigBackup{}, fmt.Errorf("ZIP не содержит config.json")
		}
		data = configData
	}
	var backup ConfigBackup
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&backup); err != nil {
		return ConfigBackup{}, fmt.Errorf("некорректный JSON backup: %w", err)
	}
	return backup, nil
}

func validateConfigBackup(backup ConfigBackup) configImportValidation {
	result := configImportValidation{
		Valid:      true,
		Schema:     backup.SchemaVersion,
		Components: []string{"runtime", "devices", "tls_profiles", "routes", "upstream_tls"},
	}
	addError := func(err error) {
		if err != nil {
			result.Valid = false
			result.Errors = append(result.Errors, err.Error())
		}
	}
	if backup.SchemaVersion != configBackupSchemaVersion {
		addError(fmt.Errorf("неподдерживаемая schema_version %q", backup.SchemaVersion))
	}
	addError(device.ValidateRegistry(backup.Devices))
	if backup.Profiles.SchemaVersion != tlsprofile.SchemaVersion {
		addError(fmt.Errorf("неподдерживаемая схема TLS-профилей %q", backup.Profiles.SchemaVersion))
	}
	if len(backup.Profiles.Templates) > 100 {
		addError(fmt.Errorf("backup содержит больше 100 TLS-профилей"))
	}
	seenProfiles := make(map[string]struct{}, len(backup.Profiles.Templates))
	for _, template := range backup.Profiles.Templates {
		if _, exists := seenProfiles[template.ID]; exists {
			addError(fmt.Errorf("дублирующийся TLS-профиль %q", template.ID))
			continue
		}
		seenProfiles[template.ID] = struct{}{}
		if _, err := tlsprofile.Preview(template); err != nil {
			addError(fmt.Errorf("TLS-профиль %q: %w", template.ID, err))
		}
	}
	addError(routing.Validate(backup.Routes))
	if backup.UpstreamTLS.Default != (upstreamtls.UpstreamTLSProfile{}) || len(backup.UpstreamTLS.Routes) > 0 {
		addError(upstreamtls.Validate(backup.UpstreamTLS))
	}
	return result
}

func (panel Server) configBackup() ConfigBackup {
	runtime := RuntimeStatus{}
	if panel.Runtime != nil {
		runtime = panel.Runtime()
	}
	runtime.Upstream = redactBackupURL(runtime.Upstream)

	routes := routing.Config{Rules: []routing.Rule{}}
	var routeVersion uint64
	if panel.Routes != nil {
		var ok bool
		routes, routeVersion, ok = panel.Routes.Snapshot()
		if !ok {
			routes = routing.Config{Rules: []routing.Rule{}}
		}
	}
	redactRouteURLs(&routes)

	upstreamTLS := upstreamtls.UpstreamTLSConfig{Routes: []upstreamtls.UpstreamTLSRoute{}}
	var upstreamTLSVersion uint64
	if panel.UpstreamTLS != nil {
		var ok bool
		upstreamTLS, upstreamTLSVersion, ok = panel.UpstreamTLS.Snapshot()
		if !ok {
			upstreamTLS = upstreamtls.UpstreamTLSConfig{Routes: []upstreamtls.UpstreamTLSRoute{}}
		}
	}

	return ConfigBackup{
		SchemaVersion:            configBackupSchemaVersion,
		ExportedAt:               time.Now().UTC(),
		Runtime:                  runtime,
		Devices:                  panel.Devices.Snapshot(),
		Profiles:                 panel.Profiles.Snapshot(),
		Routes:                   routes,
		RouteConfigVersion:       routeVersion,
		UpstreamTLS:              upstreamTLS,
		UpstreamTLSConfigVersion: upstreamTLSVersion,
	}
}

func redactRouteURLs(config *routing.Config) {
	if config == nil {
		return
	}
	config.Default.Upstream = redactBackupURL(config.Default.Upstream)
	for index := range config.Rules {
		config.Rules[index].Action.Upstream = redactBackupURL(config.Rules[index].Action.Upstream)
	}
}

func redactBackupURL(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "[REDACTED]"
	}
	if u.User != nil {
		// Usernames can identify accounts and remain credentials even if the
		// password is omitted, so exports contain no URL userinfo at all.
		u.User = nil
	}
	query := u.Query()
	for key := range query {
		lower := strings.ToLower(key)
		if strings.Contains(lower, "pass") || strings.Contains(lower, "token") || strings.Contains(lower, "secret") || strings.Contains(lower, "auth") || strings.Contains(lower, "key") {
			query.Del(key)
		}
	}
	u.RawQuery = query.Encode()
	return u.String()
}
