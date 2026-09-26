package webpanel

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/lylemi/ja3proxy/internal/ja3proxy/capture/tlshello"
	"github.com/lylemi/ja3proxy/internal/ja3proxy/recorder"
	"github.com/lylemi/ja3proxy/internal/ja3proxy/tlsprofile"
	utls "github.com/refraction-networking/utls"
)

type replayLabRequest struct {
	ProfileID      string               `json:"profile_id,omitempty"`
	ProfileType    string               `json:"profile_type,omitempty"`
	Template       *tlsprofile.Template `json:"template,omitempty"`
	PresetClient   string               `json:"preset_client,omitempty"`
	PresetVersion  string               `json:"preset_version,omitempty"`
	RandomizedALPN string               `json:"randomized_alpn,omitempty"`
	ObservationID  string               `json:"observation_id,omitempty"`
	TargetHost     string               `json:"target_host"`
	TargetPort     int                  `json:"target_port"`
	ServerName     string               `json:"server_name,omitempty"`
	TimeoutMillis  int                  `json:"timeout_ms,omitempty"`
}

type replayLabFingerprint struct {
	JA3                  string `json:"ja3"`
	JA3Hash              string `json:"ja3_hash"`
	JA4                  string `json:"ja4"`
	NormalizedSHA256     string `json:"normalized_sha256"`
	NormalizationVersion string `json:"normalization_version"`
}

type replayLabCompiled struct {
	Status        string                   `json:"status"`
	Fingerprint   *replayLabFingerprint    `json:"fingerprint,omitempty"`
	Replayability tlsprofile.Replayability `json:"replayability"`
}

type replayLabPolicyVerification struct {
	Status                string            `json:"status"`
	Reason                string            `json:"reason,omitempty"`
	MismatchedMustMatch   []string          `json:"mismatched_must_match,omitempty"`
	MismatchedShouldMatch []string          `json:"mismatched_should_match,omitempty"`
	ViolatedConstraints   []string          `json:"violated_constraints,omitempty"`
	Changes               []recorder.Change `json:"changes"`
}

type replayLabServerResponse struct {
	HandshakeComplete bool                         `json:"handshake_complete"`
	TLSVersion        uint16                       `json:"tls_version,omitempty"`
	CipherSuite       uint16                       `json:"cipher_suite,omitempty"`
	NegotiatedALPN    string                       `json:"negotiated_alpn,omitempty"`
	SessionReused     bool                         `json:"session_reused"`
	ServerHello       *tlshello.ServerHello        `json:"server_hello,omitempty"`
	Fingerprints      *tlshello.ServerFingerprints `json:"fingerprints,omitempty"`
}

type replayLabResult struct {
	Status             string                         `json:"status"`
	Profile            string                         `json:"profile"`
	ProfileType        string                         `json:"profile_type"`
	Target             string                         `json:"target"`
	ObservationID      string                         `json:"observation_id,omitempty"`
	Expected           *replayLabFingerprint          `json:"expected,omitempty"`
	Compiled           replayLabCompiled              `json:"compiled"`
	Actual             *replayLabFingerprint          `json:"actual,omitempty"`
	ServerResponse     replayLabServerResponse        `json:"server_response"`
	Diff               map[string]recorder.Comparison `json:"diff"`
	Error              string                         `json:"error,omitempty"`
	DurationMillis     int64                          `json:"duration_ms"`
	EngineVersion      string                         `json:"current_engine_version"`
	Compatibility      string                         `json:"compatibility_status,omitempty"`
	PolicyVerification *replayLabPolicyVerification   `json:"policy_verification,omitempty"`
}

func (panel Server) runReplayLab(w http.ResponseWriter, r *http.Request) {
	var request replayLabRequest
	if !decodeProfileRequest(w, r, &request) {
		return
	}
	targetHost := strings.Trim(strings.TrimSpace(request.TargetHost), "[]")
	if targetHost == "" || len(targetHost) > 253 || strings.ContainsAny(targetHost, "\r\n\x00 /\\") {
		writeAPIError(w, 400, "target_host обязателен и должен содержать только имя хоста или IP-адрес")
		return
	}
	if request.TargetPort == 0 {
		request.TargetPort = 443
	}
	if request.TargetPort < 1 || request.TargetPort > 65535 {
		writeAPIError(w, 400, "target_port должен быть в диапазоне 1..65535")
		return
	}
	timeout := 10 * time.Second
	if request.TimeoutMillis != 0 {
		if request.TimeoutMillis < 100 || request.TimeoutMillis > 60000 {
			writeAPIError(w, 400, "timeout_ms должен быть в диапазоне 100..60000")
			return
		}
		timeout = time.Duration(request.TimeoutMillis) * time.Millisecond
	}

	template, err := panel.replayLabTemplate(request)
	if err != nil {
		writeAPIError(w, 400, err.Error())
		return
	}
	serverName := strings.TrimSpace(request.ServerName)
	if serverName == "" {
		serverName = targetHost
	}
	materialized, err := tlsprofile.Materialize(template, serverName)
	if err != nil {
		writeAPIError(w, 400, "профиль не компилируется: "+err.Error())
		return
	}
	if materialized.Replayability.Status == "UNSUPPORTED" {
		writeAPIError(w, 400, "профиль нельзя воспроизвести: "+strings.Join(materialized.Replayability.Unsupported, "; "))
		return
	}

	var expected *recorder.Observation
	if request.ObservationID != "" {
		if panel.Recorder == nil {
			writeAPIError(w, 503, "регистратор выключен; исходное наблюдение недоступно")
			return
		}
		for _, observation := range panel.Recorder.Snapshot() {
			if observation.ID == request.ObservationID && observation.Fingerprints != nil {
				copy := observation
				expected = &copy
				break
			}
		}
		if expected == nil {
			if stored, storedErr := panel.Recorder.Stored(request.ObservationID); storedErr == nil && stored.Fingerprints != nil {
				expected = &stored
			}
		}
		if expected == nil {
			writeAPIError(w, 404, "исходное наблюдение не найдено в окне памяти или не содержит fingerprint")
			return
		}
	}

	result := replayLabResult{
		Status: "READY", Profile: template.Name, ProfileType: template.ProfileType,
		Target:        net.JoinHostPort(targetHost, fmt.Sprint(request.TargetPort)),
		ObservationID: request.ObservationID, Diff: map[string]recorder.Comparison{},
		Compiled:      replayLabCompiled{Status: "COMPILED", Replayability: materialized.Replayability},
		EngineVersion: recorder.TLSEngineUTLSVersion,
	}
	var compiledFingerprint *tlshello.Fingerprints
	if materialized.RandomizedID != nil {
		result.Compiled.Status = "NON_DETERMINISTIC"
	} else {
		compiledFingerprint, err = replayLabCompiledFingerprint(materialized)
		if err != nil {
			writeAPIError(w, 500, "не удалось рассчитать compiled fingerprint: "+err.Error())
			return
		}
		result.Compiled.Fingerprint = replayLabFingerprintFrom(compiledFingerprint)
	}
	if expected != nil {
		result.Expected = replayLabFingerprintFrom(expected.Fingerprints)
	}

	ctx, cancel := context.WithTimeout(r.Context(), timeout)
	defer cancel()
	started := time.Now()
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", result.Target)
	if err != nil {
		result.Status = "CONNECT_FAILED"
		result.Error = err.Error()
		result.DurationMillis = time.Since(started).Milliseconds()
		jsonResponse(w, result)
		return
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	var clientCapture, serverCapture tlshello.Capture
	serverConn := tlshello.WrapServerHello(conn, true, tlshello.DefaultLimits(), func(capture tlshello.Capture) { serverCapture = capture })
	clientConn := tlshello.Wrap(serverConn, false, tlshello.DefaultLimits(), func(capture tlshello.Capture) { clientCapture = capture })
	protocols := append([]string(nil), template.Fields.ALPN...)
	if materialized.RandomizedID != nil && len(protocols) == 0 && template.RandomizedALPN != tlsprofile.RandomizedALPNDisabled {
		protocols = []string{"h2", "http/1.1"}
	}
	config := &utls.Config{
		ServerName: serverName, InsecureSkipVerify: true, NextProtos: protocols,
	}
	var tlsConn *utls.UConn
	if materialized.RandomizedID != nil {
		config.CurvePreferences = []utls.CurveID{utls.X25519, utls.CurveP256, utls.CurveP384, utls.CurveP521}
		tlsConn = utls.UClient(clientConn, config, *materialized.RandomizedID)
	} else {
		tlsConn = utls.UClient(clientConn, config, utls.HelloCustom)
		if err := tlsConn.ApplyPreset(materialized.Spec); err != nil {
			result.Status = "COMPILE_FAILED"
			result.Error = err.Error()
			result.DurationMillis = time.Since(started).Milliseconds()
			jsonResponse(w, result)
			return
		}
	}
	if handshakeErr := tlsConn.HandshakeContext(ctx); handshakeErr != nil {
		result.Status = "HANDSHAKE_FAILED"
		result.Error = handshakeErr.Error()
	} else {
		state := tlsConn.ConnectionState()
		result.ServerResponse.HandshakeComplete = true
		result.ServerResponse.TLSVersion = state.Version
		result.ServerResponse.CipherSuite = state.CipherSuite
		result.ServerResponse.NegotiatedALPN = state.NegotiatedProtocol
		result.ServerResponse.SessionReused = state.DidResume
	}
	result.DurationMillis = time.Since(started).Milliseconds()
	actualReady := false
	if clientCapture.Status == "complete" {
		if hello, parseErr := tlshello.Parse(clientCapture.Raw); parseErr == nil {
			if actual, fingerprintErr := tlshello.Calculate(hello, clientCapture.Raw, clientCapture.Records); fingerprintErr == nil {
				result.Actual = replayLabFingerprintFrom(&actual)
				actualReady = true
				actualObservation := recorder.Observation{Completeness: "complete", Fingerprints: &actual}
				if expected != nil {
					result.Diff["captured_vs_actual"] = recorder.Compare(*expected, actualObservation)
				}
				if compiledFingerprint != nil {
					compiledObservation := recorder.Observation{Completeness: "complete", Fingerprints: compiledFingerprint}
					result.Diff["compiled_vs_actual"] = recorder.Compare(compiledObservation, actualObservation)
				}
			}
		}
	}
	if result.ServerResponse.HandshakeComplete {
		if actualReady {
			result.Status = "OK"
		} else {
			result.Status = "CAPTURE_FAILED"
			result.Error = fmt.Sprintf("не удалось зафиксировать outbound ClientHello: %s/%s", clientCapture.Status, clientCapture.ErrorCode)
		}
	}
	compatibility := tlsprofile.CompatibilityIncompatible
	if result.Status == "OK" {
		compatibility, result.PolicyVerification = replayCompatibilityStatus(template, materialized, clientCapture)
	}
	if request.ProfileID != "" && panel.Profiles != nil && (result.Status == "OK" || result.Status == "HANDSHAKE_FAILED") {
		updated, _, saveErr := panel.Profiles.RecordCompatibility(template.ID, template.Version, compatibility)
		if saveErr != nil {
			message := "результат проверки не сохранён: " + saveErr.Error()
			if result.Error != "" {
				result.Error += "; "
			}
			result.Error += message
		} else {
			result.Compatibility = tlsprofile.EngineCompatibility(updated)
		}
	}
	if serverCapture.Status == "complete" {
		if hello, parseErr := tlshello.ParseServerHello(serverCapture.Raw); parseErr == nil {
			result.ServerResponse.ServerHello = &hello
			if serverFingerprints, fingerprintErr := tlshello.CalculateServerFingerprints(&hello); fingerprintErr == nil {
				result.ServerResponse.Fingerprints = &serverFingerprints
			}
		}
	}
	jsonResponse(w, result)
}

func replayCompatibilityStatus(template tlsprofile.Template, materialized tlsprofile.Materialized, capture tlshello.Capture) (string, *replayLabPolicyVerification) {
	if capture.Status != "complete" || materialized.RandomizedID != nil {
		if capture.Status == "complete" {
			return tlsprofile.CompatibilityValid, nil
		}
		return tlsprofile.CompatibilityIncompatible, nil
	}
	hello, err := tlshello.Parse(capture.Raw)
	if err != nil {
		return tlsprofile.CompatibilityIncompatible, nil
	}
	actual, err := tlshello.Calculate(hello, capture.Raw, capture.Records)
	if err != nil {
		return tlsprofile.CompatibilityIncompatible, nil
	}
	expected := recorder.FingerprintExpected{
		ProfileSchemaVersion: tlsprofile.SchemaVersion,
		JA3:                  materialized.Expected.JA3, JA3Hash: materialized.Expected.JA3Hash,
		JA4: materialized.Expected.JA4, NormalizedSHA256: materialized.Expected.NormalizedSHA256,
		Normalized: materialized.Expected.Normalized, NormalizationVersion: materialized.Expected.NormalizationVersion,
		MaterializerVersion: materialized.Expected.MaterializerVersion,
		MustMatch:           append([]string(nil), template.Policy.MustMatch...),
		ShouldMatch:         append([]string(nil), template.Policy.ShouldMatch...),
		IgnoredDynamic:      append([]string(nil), template.Policy.IgnoredDynamic...),
	}
	for _, constraint := range template.Policy.Constraints {
		expected.Constraints = append(expected.Constraints, recorder.FingerprintConstraint{
			Path: constraint.Path, Operator: constraint.Operator,
			Value: constraint.Value, Values: constraint.Values,
		})
	}
	verification := recorder.VerifyExpected(expected, recorder.Observation{Completeness: "complete", Fingerprints: &actual})
	policyVerification := &replayLabPolicyVerification{
		Status: verification.Status, Reason: verification.Reason,
		MismatchedMustMatch:   append([]string(nil), verification.MismatchedMustMatch...),
		MismatchedShouldMatch: append([]string(nil), verification.MismatchedShouldMatch...),
		ViolatedConstraints:   append([]string(nil), verification.ViolatedConstraints...),
		Changes:               append([]recorder.Change{}, verification.Changes...),
	}
	switch verification.Status {
	case "MATCH":
		return tlsprofile.CompatibilityValid, policyVerification
	case "PARTIAL_MATCH":
		return tlsprofile.CompatibilityValidWithDifferences, policyVerification
	default:
		return tlsprofile.CompatibilityIncompatible, policyVerification
	}
}

func (panel Server) replayLabTemplate(request replayLabRequest) (tlsprofile.Template, error) {
	if request.ProfileType != "" && request.ProfileType != tlsprofile.ProfileTypePreset && request.ProfileType != tlsprofile.ProfileTypeRandomized {
		return tlsprofile.Template{}, fmt.Errorf("profile_type должен быть PRESET или RANDOMIZED")
	}
	selectors := 0
	if request.ProfileID != "" {
		selectors++
	}
	if request.Template != nil {
		selectors++
	}
	if request.ProfileType != "" {
		selectors++
	}
	if selectors != 1 {
		return tlsprofile.Template{}, fmt.Errorf("укажите ровно один источник: profile_id, template, PRESET или RANDOMIZED")
	}
	if request.ProfileID != "" {
		if request.ProfileType != "" || request.Template != nil {
			return tlsprofile.Template{}, fmt.Errorf("укажите только один источник профиля")
		}
		if panel.Profiles == nil {
			return tlsprofile.Template{}, fmt.Errorf("библиотека TLS-профилей недоступна")
		}
		template, ok := panel.Profiles.Get(request.ProfileID)
		if !ok {
			return tlsprofile.Template{}, fmt.Errorf("TLS-профиль не найден")
		}
		if template.ProfileType == "" {
			template.ProfileType = tlsprofile.ProfileTypeCustom
		}
		return template, nil
	}
	if request.Template != nil {
		if request.ProfileType != "" {
			return tlsprofile.Template{}, fmt.Errorf("укажите только один источник профиля")
		}
		return tlsprofile.Preview(*request.Template)
	}
	switch request.ProfileType {
	case tlsprofile.ProfileTypePreset:
		if request.PresetClient == "" || request.PresetVersion == "" {
			return tlsprofile.Template{}, fmt.Errorf("preset_client и preset_version обязательны")
		}
		return tlsprofile.TemplateFromPreset(request.PresetClient+" "+request.PresetVersion, request.PresetClient, request.PresetVersion)
	case tlsprofile.ProfileTypeRandomized:
		return tlsprofile.TemplateFromRandomized("RANDOMIZED", request.RandomizedALPN)
	default:
		return tlsprofile.Template{}, fmt.Errorf("profile_type должен быть PRESET или RANDOMIZED")
	}
}

func replayLabCompiledFingerprint(materialized tlsprofile.Materialized) (*tlshello.Fingerprints, error) {
	if materialized.Hello == nil || len(materialized.Raw) == 0 {
		return nil, fmt.Errorf("materialized ClientHello отсутствует")
	}
	record := make([]byte, 5+len(materialized.Raw))
	record[0] = 22
	binary.BigEndian.PutUint16(record[1:3], materialized.Hello.LegacyVersion)
	binary.BigEndian.PutUint16(record[3:5], uint16(len(materialized.Raw)))
	copy(record[5:], materialized.Raw)
	fingerprints, err := tlshello.Calculate(materialized.Hello, materialized.Raw, record)
	return &fingerprints, err
}

func replayLabFingerprintFrom(value *tlshello.Fingerprints) *replayLabFingerprint {
	if value == nil {
		return nil
	}
	return &replayLabFingerprint{
		JA3: value.JA3, JA3Hash: value.JA3Hash, JA4: value.JA4,
		NormalizedSHA256: value.NormalizedSHA256, NormalizationVersion: value.NormalizationVersion,
	}
}

func jsonResponse(w http.ResponseWriter, value any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(value)
}
