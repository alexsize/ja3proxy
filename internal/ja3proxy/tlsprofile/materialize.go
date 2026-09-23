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
	utls "github.com/refraction-networking/utls"
)

type Materialized struct {
	Spec          *utls.ClientHelloSpec
	Raw           []byte
	Hello         *tlshello.Hello
	Expected      Expected
	Replayability Replayability
}

func TemplateFromPreset(name string, presetClient string, presetVersion string) (Template, error) {
	template := Template{
		SchemaVersion: SchemaVersion,
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
	template.Fields = fields
	return Preview(template)
}

func Preview(template Template) (Template, error) {
	if template.Policy.MustMatch == nil {
		template.Policy = DefaultMatchPolicy()
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
	template.Replayability = assessObservedSource(template, materialized.Expected)
	template.Expected = &materialized.Expected
	return template, nil
}

func Materialize(template Template, serverName string) (Materialized, error) {
	if err := validateTemplate(template); err != nil {
		return Materialized{}, err
	}
	base, err := buildTemplateSpec(template, serverName)
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
	replaySpec, err := buildTemplateSpec(template, serverName)
	if err != nil {
		return Materialized{}, err
	}
	warnings := []string{"random, session ID, GREASE и key shares создаются uTLS динамически"}
	return Materialized{Spec: &replaySpec, Raw: raw, Hello: hello, Expected: expected, Replayability: Replayability{Status: "REPLAYABLE_WITH_DYNAMIC_FIELDS", Warnings: warnings}}, nil
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
		applyEditableFields(extension, template.Fields)
		ordered = append(ordered, extension)
	}
	if len(unsupported) > 0 {
		return utls.ClientHelloSpec{}, errors.New(unsupported[0])
	}
	base.Extensions = ordered
	return base, nil
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
