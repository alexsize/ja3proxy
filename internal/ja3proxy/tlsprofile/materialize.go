package tlsprofile

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"slices"
	"time"

	"github.com/lylemi/ja3proxy/internal/ja3proxy/capture/tlshello"
	"github.com/lylemi/ja3proxy/internal/ja3proxy/fingerprint"
	"github.com/lylemi/ja3proxy/internal/ja3proxy/recorder"
	utls "github.com/refraction-networking/utls"
)

type Materialized struct {
	Spec             *utls.ClientHelloSpec
	RandomizedID     *utls.ClientHelloID
	Raw              []byte
	Hello            *tlshello.Hello
	Expected         Expected
	Replayability    Replayability
	RuntimeMutations []recorder.RuntimeMutation
}

func TemplateFromPreset(name string, presetClient string, presetVersion string) (Template, error) {
	template := Template{
		SchemaVersion: SchemaVersion,
		ProfileType:   ProfileTypePreset,
		Name:          name,
		Enabled:       true,
		BasePreset:    fingerprint.TLSFingerprint{Client: presetClient, Version: presetVersion},
		Policy:        DefaultMatchPolicy(),
	}
	materialized, err := materializeBase(template.BasePreset.Client, template.BasePreset.Version, "preview.invalid")
	if err != nil {
		return Template{}, err
	}
	fields, err := FieldsFromHello(materialized.Hello)
	if err != nil {
		return Template{}, err
	}
	// uTLS may emit an empty ALPS extension in a preset, while the template
	// materializer omits it when there are no ALPS protocols. Store the fields
	// that the template can actually reproduce, including extension order.
	if len(fields.ALPS) == 0 {
		fields.ExtensionOrder = slices.DeleteFunc(fields.ExtensionOrder, func(id uint16) bool {
			return id == 17513 || id == 17613
		})
	}
	template.Fields = fields
	return Preview(template)
}

// TemplateFromRandomized creates a uTLS profile generated anew for each connection.
func TemplateFromRandomized(name, alpnMode string) (Template, error) {
	if alpnMode == "" {
		alpnMode = RandomizedALPNAuto
	}
	return Preview(Template{
		SchemaVersion:  SchemaVersion,
		ProfileType:    ProfileTypeRandomized,
		RandomizedALPN: alpnMode,
		Name:           name,
		Enabled:        true,
	})
}

func Preview(template Template) (Template, error) {
	if template.ProfileType == "" {
		template.ProfileType = ProfileTypeCustom
	}
	if template.ProfileMode == "" {
		template.ProfileMode = ProfileModeAdaptive
	}
	if template.ProfileType == ProfileTypeRandomized && template.RandomizedALPN == "" {
		template.RandomizedALPN = RandomizedALPNAuto
	}
	if template.ProfileType == ProfileTypeRandomized {
		template.BasePreset = fingerprint.TLSFingerprint{}
		template.Fields = StaticFields{}
		template.Policy = MatchPolicy{}
		template.SourceObservationID = ""
		template.Source = nil
		template.Expected = nil
	}
	if template.Policy.MustMatch == nil {
		template.Policy = DefaultMatchPolicy()
	}
	if template.Fields.ALPNPolicy == "" {
		template.Fields.ALPNPolicy = ALPNPolicyIntersection
	}
	if err := validateTemplate(template); err != nil {
		return Template{}, err
	}
	serverName := "preview.invalid"
	if template.Source != nil && template.Source.ServerName != "" {
		serverName = template.Source.ServerName
	}
	materialized, err := Materialize(template, serverName)
	if err != nil {
		template.Replayability = Replayability{Status: "UNSUPPORTED", Unsupported: []string{err.Error()}}
		template.Expected = nil
		return template, nil
	}
	if materialized.RandomizedID != nil {
		template.Expected = nil
		template.Replayability = Replayability{
			Status:   "NON_DETERMINISTIC",
			Warnings: []string{"ClientHello генерируется заново для каждого соединения; фактические JA3/JA4 доступны только в записи исходящего ClientHello"},
		}
		return template, nil
	}
	template.Replayability = assessObservedSource(template, materialized.Expected)
	template.Expected = &materialized.Expected
	return template, nil
}

func Materialize(template Template, serverName string) (Materialized, error) {
	if err := validateTemplate(template); err != nil {
		return Materialized{}, err
	}
	if template.ProfileType == ProfileTypeRandomized {
		var helloID utls.ClientHelloID
		switch template.RandomizedALPN {
		case "", RandomizedALPNAuto:
			helloID = utls.HelloRandomized
		case RandomizedALPNRequired:
			helloID = utls.HelloRandomizedALPN
		case RandomizedALPNDisabled:
			helloID = utls.HelloRandomizedNoALPN
		default:
			return Materialized{}, fmt.Errorf("неподдерживаемый randomized_alpn %q", template.RandomizedALPN)
		}
		// Keep uTLS from drawing the hybrid ML-KEM group that this dependency
		// version cannot use as its first local key exchange.
		weights := utls.DefaultWeights
		weights.CurveIDs_Append_X25519 = 0
		helloID.Weights = &weights
		return Materialized{RandomizedID: &helloID, Replayability: Replayability{
			Status:   "NON_DETERMINISTIC",
			Warnings: []string{"фактический отпечаток зависит от генерации ClientHello при подключении"},
		}}, nil
	}
	effective := template
	alpn, err := effectiveALPN(template, nil)
	if err != nil {
		return Materialized{}, err
	}
	alps, err := effectiveALPS(template, nil, alpn)
	if err != nil {
		return Materialized{}, err
	}
	effective.Fields.ALPN = alpn
	effective.Fields.ALPS = alps
	base, err := buildTemplateSpec(effective, serverName)
	if err != nil {
		return Materialized{}, err
	}

	uconn := utls.UClient(&net.TCPConn{}, &utls.Config{ServerName: serverName, InsecureSkipVerify: true}, utls.HelloCustom)
	if err := uconn.ApplyPreset(&base); err != nil {
		return Materialized{}, fmt.Errorf("применение ClientHelloSpec: %w", err)
	}
	if err := uconn.BuildHandshakeState(); err != nil {
		return Materialized{}, fmt.Errorf("сборка ClientHello: %w", err)
	}
	raw := append([]byte(nil), uconn.HandshakeState.Hello.Raw...)
	hello, err := tlshello.Parse(raw)
	if err != nil {
		return Materialized{}, fmt.Errorf("разбор materialized ClientHello: %w", err)
	}
	mutations, err := auditMaterializedFields(effective, hello)
	if err != nil {
		return Materialized{}, err
	}
	record := make([]byte, 5+len(raw))
	record[0] = 22
	binary.BigEndian.PutUint16(record[1:3], hello.LegacyVersion)
	binary.BigEndian.PutUint16(record[3:5], uint16(len(raw)))
	copy(record[5:], raw)
	fp, err := tlshello.Calculate(hello, raw, record)
	if err != nil {
		return Materialized{}, err
	}
	expected := Expected{
		JA3:                  fp.JA3,
		JA3Hash:              fp.JA3Hash,
		JA4:                  fp.JA4,
		NormalizedSHA256:     fp.NormalizedSHA256,
		Normalized:           append(json.RawMessage(nil), fp.Normalized...),
		NormalizationVersion: fp.NormalizationVersion,
		MaterializerVersion:  MaterializerVersion,
		CalculatedAt:         time.Now().UTC(),
	}
	if err := validatePolicyPaths(expected.Normalized, template.Policy); err != nil {
		return Materialized{}, err
	}
	replaySpec, err := buildTemplateSpec(effective, serverName)
	if err != nil {
		return Materialized{}, err
	}
	warnings := []string{"random, session ID, GREASE и key shares создаются uTLS динамически"}
	return Materialized{Spec: &replaySpec, Raw: raw, Hello: hello, Expected: expected, Replayability: Replayability{Status: "REPLAYABLE_WITH_DYNAMIC_FIELDS", Warnings: warnings}, RuntimeMutations: mutations}, nil
}

func buildTemplateSpec(template Template, serverName string) (utls.ClientHelloSpec, error) {
	base, err := utls.UTLSIdToSpec(utls.ClientHelloID{Client: template.BasePreset.Client, Version: template.BasePreset.Version})
	if err != nil {
		return utls.ClientHelloSpec{}, fmt.Errorf("пресет нельзя преобразовать в ClientHelloSpec: %w", err)
	}
	base.CipherSuites = append([]uint16(nil), template.Fields.CipherSuites...)
	for i, value := range base.CipherSuites {
		if value == GREASEPlaceholder {
			base.CipherSuites[i] = utls.GREASE_PLACEHOLDER
		}
	}

	byID := map[uint16][]utls.TLSExtension{}
	for _, extension := range base.Extensions {
		prepareExtension(extension, serverName)
		id, idErr := extensionID(extension)
		if idErr != nil {
			return utls.ClientHelloSpec{}, idErr
		}
		byID[id] = append(byID[id], extension)
	}

	ordered := make([]utls.TLSExtension, 0, len(template.Fields.ExtensionOrder))
	unsupported := []string{}
	for _, requestedID := range template.Fields.ExtensionOrder {
		id := normalizeGREASE(requestedID)
		queue := byID[id]
		if len(queue) == 0 {
			unsupported = append(unsupported, fmt.Sprintf("extension %d отсутствует в базовом пресете", requestedID))
			continue
		}
		extension := queue[0]
		byID[id] = queue[1:]
		if isALPSExtension(extension) && len(template.Fields.ALPS) == 0 {
			continue
		}
		applyEditableFields(extension, template.Fields)
		if padding, ok := extension.(*utls.UtlsPaddingExtension); ok && template.Fields.PaddingLength > 0 {
			// uTLS otherwise recalculates BoringSSL padding from random session
			// fields. A compiled profile must retain the observed padding
			// presence, length and position across preview and wire replay.
			padding.PaddingLen = template.Fields.PaddingLength
			padding.WillPad = true
			padding.GetPaddingLen = nil
		}
		ordered = append(ordered, extension)
	}
	if len(unsupported) > 0 {
		return utls.ClientHelloSpec{}, errors.New(unsupported[0])
	}
	base.Extensions = ordered
	return base, nil
}

func isALPSExtension(extension utls.TLSExtension) bool {
	switch extension.(type) {
	case *utls.ApplicationSettingsExtension, *utls.ApplicationSettingsExtensionNew:
		return true
	default:
		return false
	}
}

func materializeBase(client, version, serverName string) (Materialized, error) {
	base, err := utls.UTLSIdToSpec(utls.ClientHelloID{Client: client, Version: version})
	if err != nil {
		return Materialized{}, err
	}
	uconn := utls.UClient(&net.TCPConn{}, &utls.Config{ServerName: serverName, InsecureSkipVerify: true}, utls.HelloCustom)
	if err := uconn.ApplyPreset(&base); err != nil {
		return Materialized{}, err
	}
	if err := uconn.BuildHandshakeState(); err != nil {
		return Materialized{}, err
	}
	raw := append([]byte(nil), uconn.HandshakeState.Hello.Raw...)
	hello, err := tlshello.Parse(raw)
	return Materialized{Spec: &base, Raw: raw, Hello: hello}, err
}

func prepareExtension(extension utls.TLSExtension, serverName string) {
	if sni, ok := extension.(*utls.SNIExtension); ok {
		sni.ServerName = serverName
	}
}

func applyEditableFields(extension utls.TLSExtension, fields StaticFields) {
	switch ext := extension.(type) {
	case *utls.ALPNExtension:
		ext.AlpnProtocols = append([]string(nil), fields.ALPN...)
	case *utls.ApplicationSettingsExtension:
		ext.SupportedProtocols = append([]string(nil), fields.ALPS...)
	case *utls.ApplicationSettingsExtensionNew:
		ext.SupportedProtocols = append([]string(nil), fields.ALPS...)
	case *utls.SupportedVersionsExtension:
		ext.Versions = append([]uint16(nil), fields.SupportedVersions...)
		for i, value := range ext.Versions {
			if value == GREASEPlaceholder {
				ext.Versions[i] = utls.GREASE_PLACEHOLDER
			}
		}
	case *utls.SupportedCurvesExtension:
		ext.Curves = make([]utls.CurveID, len(fields.SupportedGroups))
		for i, value := range fields.SupportedGroups {
			if value == GREASEPlaceholder {
				value = utls.GREASE_PLACEHOLDER
			}
			ext.Curves[i] = utls.CurveID(value)
		}
	case *utls.SignatureAlgorithmsExtension:
		ext.SupportedSignatureAlgorithms = make([]utls.SignatureScheme, len(fields.SignatureAlgorithms))
		for i, value := range fields.SignatureAlgorithms {
			ext.SupportedSignatureAlgorithms[i] = utls.SignatureScheme(value)
		}
	}
}

func extensionID(extension utls.TLSExtension) (uint16, error) {
	switch extension.(type) {
	case *utls.SNIExtension:
		return 0, nil
	case *utls.UtlsPaddingExtension:
		return 21, nil
	case *utls.UtlsGREASEExtension:
		return GREASEPlaceholder, nil
	}
	if generic, ok := extension.(*utls.GenericExtension); ok {
		return normalizeGREASE(generic.Id), nil
	}
	length := extension.Len()
	if length < 4 || length > tlshello.MaxHelloSize {
		return 0, fmt.Errorf("extension %T нельзя сериализовать для профиля", extension)
	}
	buffer := make([]byte, length)
	n, err := extension.Read(buffer)
	if (err != nil && !errors.Is(err, io.EOF)) || n < 4 {
		return 0, fmt.Errorf("extension %T нельзя сериализовать для профиля: %v", extension, err)
	}
	return normalizeGREASE(binary.BigEndian.Uint16(buffer[:2])), nil
}

func extensionIDs(spec *utls.ClientHelloSpec) ([]uint16, error) {
	ids := make([]uint16, 0, len(spec.Extensions))
	for _, extension := range spec.Extensions {
		prepareExtension(extension, "preview.invalid")
		id, err := extensionID(extension)
		if err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, nil
}

func sameMultisetSubset(requested, available []uint16) bool {
	remaining := append([]uint16(nil), available...)
	for _, id := range requested {
		index := slices.Index(remaining, id)
		if index < 0 {
			return false
		}
		remaining = append(remaining[:index], remaining[index+1:]...)
	}
	return true
}
