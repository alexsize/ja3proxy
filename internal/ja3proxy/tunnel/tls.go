package tunnel

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/lylemi/ja3proxy/internal/ja3proxy/capture/tlshello"
	"github.com/lylemi/ja3proxy/internal/ja3proxy/certstore"
	"github.com/lylemi/ja3proxy/internal/ja3proxy/device"
	"github.com/lylemi/ja3proxy/internal/ja3proxy/fingerprint"
	"github.com/lylemi/ja3proxy/internal/ja3proxy/flowid"
	"github.com/lylemi/ja3proxy/internal/ja3proxy/logutil"
	"github.com/lylemi/ja3proxy/internal/ja3proxy/netutil"
	"github.com/lylemi/ja3proxy/internal/ja3proxy/pipe"
	"github.com/lylemi/ja3proxy/internal/ja3proxy/recorder"
	"github.com/lylemi/ja3proxy/internal/ja3proxy/tlsprofile"
	"github.com/lylemi/ja3proxy/internal/ja3proxy/upstreamtls"
	utls "github.com/refraction-networking/utls"
)

type TunnelHandler struct {
	Recorder            *recorder.Recorder
	Devices             *device.Store
	TLSProfiles         *tlsprofile.Store
	Mode                string
	CaptureTimeout      time.Duration
	Debug               bool
	CA                  *certstore.CertificateAuthority
	SessionKey          *certstore.SessionKeyHelper
	TLSFingerprints     *fingerprint.TLSFingerprintStore
	UpstreamTLSProfiles *upstreamtls.UpstreamTLSProfileStore
	DefaultTLSClient    string
	DefaultTLSVersion   string
}

func (handler *TunnelHandler) configuredTLSFingerprint() fingerprint.TLSFingerprint {
	if handler != nil && handler.TLSFingerprints != nil {
		if fp, ok := handler.TLSFingerprints.Get(); ok {
			return fp
		}
	}
	if handler != nil {
		return fingerprint.TLSFingerprint{
			Client:  handler.DefaultTLSClient,
			Version: handler.DefaultTLSVersion,
		}
	}

	return fingerprint.TLSFingerprint{
		Client:  utls.HelloGolang.Client,
		Version: utls.HelloGolang.Version,
	}
}

func (handler *TunnelHandler) configuredUpstreamTLSProfile(host string) upstreamtls.UpstreamTLSProfile {
	if handler != nil && handler.UpstreamTLSProfiles != nil {
		if profile, ok := handler.UpstreamTLSProfiles.Get(host); ok {
			return profile
		}
	}
	return upstreamtls.ProfileFromFingerprint(handler.configuredTLSFingerprint())
}

type upstreamTLSConn struct {
	net.Conn
	negotiatedProtocol string
	runtimeMutations   []recorder.RuntimeMutation
}

func (conn *upstreamTLSConn) NegotiatedProtocol() string {
	if conn == nil {
		return ""
	}
	return conn.negotiatedProtocol
}

func (handler *TunnelHandler) wrapUpstreamTLS(conn net.Conn, routeHost string, serverName string, nextProtos []string) (*upstreamTLSConn, error) {
	profile := handler.configuredUpstreamTLSProfile(routeHost)
	return handler.wrapUpstreamTLSProfile(conn, serverName, nextProtos, profile)
}

func (handler *TunnelHandler) wrapUpstreamTLSProfile(conn net.Conn, serverName string, nextProtos []string, profile upstreamtls.UpstreamTLSProfile) (*upstreamTLSConn, error) {
	return handler.wrapUpstreamTLSSelection(conn, serverName, nextProtos, profile, nil)
}

func (handler *TunnelHandler) wrapUpstreamTLSSelection(conn net.Conn, serverName string, nextProtos []string, profile upstreamtls.UpstreamTLSProfile, template *tlsprofile.Template) (*upstreamTLSConn, error) {
	if template != nil {
		uTLSConn, err := handler.utlsWrapTemplate(conn, serverName, *template)
		if err != nil {
			return nil, err
		}
		return &upstreamTLSConn{Conn: uTLSConn, negotiatedProtocol: uTLSConn.ConnectionState().NegotiatedProtocol}, nil
	}
	switch upstreamtls.NormalizeProtocol(profile.Protocol) {
	case upstreamtls.ProtocolUTLS:
		uTLSConn, mutations, err := handler.utlsWrapAudited(conn, serverName, nextProtos, fingerprint.TLSFingerprint{
			Client:  profile.Client,
			Version: profile.Version,
		})
		if err != nil {
			return nil, err
		}
		return &upstreamTLSConn{
			Conn:               uTLSConn,
			negotiatedProtocol: uTLSConn.ConnectionState().NegotiatedProtocol,
			runtimeMutations:   mutations,
		}, nil
	default:
		return nil, fmt.Errorf("unsupported upstream TLS protocol %q", profile.Protocol)
	}
}

func (handler *TunnelHandler) utlsWrapTemplate(conn net.Conn, serverName string, template tlsprofile.Template) (*utls.UConn, error) {
	materialized, err := tlsprofile.Materialize(template, serverName)
	if err != nil {
		return nil, err
	}
	config := &utls.Config{ServerName: serverName, InsecureSkipVerify: true, NextProtos: append([]string(nil), template.Fields.ALPN...)}
	uTLSConn := utls.UClient(conn, config, utls.HelloCustom)
	if err := uTLSConn.ApplyPreset(materialized.Spec); err != nil {
		return nil, err
	}
	ctx := context.Background()
	if handler.Recorder != nil {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, handler.captureTimeout())
		defer cancel()
	}
	if err := uTLSConn.HandshakeContext(ctx); err != nil {
		return nil, err
	}
	return uTLSConn, nil
}

func (handler *TunnelHandler) customTLSWrap(conn net.Conn, sni string, nextProtos []string) (*utls.UConn, error) {
	return handler.utlsWrap(conn, sni, nextProtos, handler.configuredTLSFingerprint())
}

func (handler *TunnelHandler) utlsWrap(conn net.Conn, sni string, nextProtos []string, fp fingerprint.TLSFingerprint) (*utls.UConn, error) {
	uTLSConn, _, err := handler.utlsWrapAudited(conn, sni, nextProtos, fp)
	return uTLSConn, err
}

func (handler *TunnelHandler) utlsWrapAudited(conn net.Conn, sni string, nextProtos []string, fp fingerprint.TLSFingerprint) (*utls.UConn, []recorder.RuntimeMutation, error) {
	clientHelloID := utls.ClientHelloID{
		Client: fp.Client, Version: fp.Version, Seed: nil, Weights: nil,
	}

	tlsConfig := &utls.Config{
		ServerName:         sni,
		InsecureSkipVerify: true,
		NextProtos:         nextProtos,
	}
	uTLSConn := utls.UClient(
		conn,
		tlsConfig,
		clientHelloID,
	)

	if len(nextProtos) > 0 && clientHelloID.Client != utls.HelloGolang.Client {
		spec, err := utls.UTLSIdToSpec(clientHelloID)
		if err == nil {
			mutations := limitSpecALPN(&spec, nextProtos)
			uTLSConn = utls.UClient(conn, tlsConfig, utls.HelloCustom)
			if err := uTLSConn.ApplyPreset(&spec); err != nil {
				return nil, mutations, err
			}
			handshaken, handshakeErr := handler.handshakeUTLS(uTLSConn)
			return handshaken, mutations, handshakeErr
		}
	}
	handshaken, handshakeErr := handler.handshakeUTLS(uTLSConn)
	return handshaken, nil, handshakeErr
}

func (handler *TunnelHandler) handshakeUTLS(uTLSConn *utls.UConn) (*utls.UConn, error) {
	ctx := context.Background()
	if handler.Recorder != nil {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, handler.captureTimeout())
		defer cancel()
	}
	if err := uTLSConn.HandshakeContext(ctx); err != nil {
		return nil, err
	}
	return uTLSConn, nil
}

func limitSpecALPN(spec *utls.ClientHelloSpec, nextProtos []string) []recorder.RuntimeMutation {
	mutations := []recorder.RuntimeMutation{}
	extensions := make([]utls.TLSExtension, 0, len(spec.Extensions)+1)
	for _, extension := range spec.Extensions {
		switch ext := extension.(type) {
		case *utls.ALPNExtension:
			before := append([]string(nil), ext.AlpnProtocols...)
			ext.AlpnProtocols = nextProtos
			if !sameStrings(before, nextProtos) {
				mutations = append(mutations, recorder.RuntimeMutation{Type: "PROFILE_RUNTIME_MUTATION", Field: "ALPN", Before: before, After: append([]string(nil), nextProtos...), Reason: "downstream protocol compatibility"})
			}
			extensions = append(extensions, extension)
		case *utls.ApplicationSettingsExtension:
			before := append([]string(nil), ext.SupportedProtocols...)
			after := matchingProtocols(before, nextProtos)
			ext.SupportedProtocols = after
			if !sameStrings(before, after) {
				mutations = append(mutations, recorder.RuntimeMutation{Type: "PROFILE_RUNTIME_MUTATION", Field: "ALPS", Before: before, After: append([]string(nil), after...), Reason: "downstream protocol compatibility"})
			}
			if len(ext.SupportedProtocols) > 0 {
				extensions = append(extensions, extension)
			}
		default:
			extensions = append(extensions, extension)
		}
	}

	spec.Extensions = extensions
	return mutations
}

func sameStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func matchingProtocols(supported []string, allowed []string) []string {
	matches := make([]string, 0, len(supported))
	for _, protocol := range supported {
		for _, allowedProtocol := range allowed {
			if protocol == allowedProtocol {
				matches = append(matches, protocol)
				break
			}
		}
	}
	return matches
}

func upstreamALPN(clientProtocols []string) []string {
	if len(clientProtocols) == 0 {
		return []string{"http/1.1"}
	}
	return clientProtocols
}

func clientALPN(upstreamProtocol string) []string {
	if upstreamProtocol != "" {
		return []string{upstreamProtocol}
	}
	return []string{"http/1.1"}
}

func (handler *TunnelHandler) generateCertificate(sni string) (tls.Certificate, error) {
	if handler == nil || handler.CA == nil {
		return tls.Certificate{}, fmt.Errorf("CA certificate has not been loaded")
	}
	if handler.SessionKey == nil {
		return tls.Certificate{}, fmt.Errorf("session key has not been generated")
	}

	return handler.CA.GenerateCertificate(*handler.SessionKey, sni)
}

func (handler *TunnelHandler) Connect(sni string, destConn net.Conn, clientConn net.Conn) {
	defer destConn.Close()
	defer clientConn.Close()
	var destTLSConn *upstreamTLSConn
	var outMeta recorder.Meta
	logger := logutil.WithComponent("tls_tunnel", "sni", sni)
	// Resolve once. A runtime profile change cannot relabel a running handshake.
	profile := handler.configuredUpstreamTLSProfile(sni)
	var selectedTemplate *tlsprofile.Template
	var selectedConfigVersion uint64
	if handler.TLSProfiles != nil {
		if template, configVersion, ok := handler.TLSProfiles.ResolveWithVersion(sni); ok {
			selectedTemplate = &template
			selectedConfigVersion = configVersion
		}
	}
	if handler.Mode == "BLOCK" {
		return
	}
	if handler.Recorder != nil {
		mode := handler.Mode
		if mode == "" {
			mode = "MITM_REISSUE"
		}
		id := flowid.From(clientConn)
		if id == "" {
			// Direct TunnelHandler users do not pass through MixedProxyListener.
			id = recorder.NewID()
		}
		meta := recorder.Meta{ConnectionID: id, CapturePoint: "CLIENT_IN", Direction: "inbound", ByteSource: "client_socket_read", Mode: mode, Destination: sni, Source: netutil.RemoteAddr(clientConn)}
		meta = applyIdentityEvidenceWithRegistry(meta, clientConn, handler.Devices)
		outMeta = meta
		outMeta.CapturePoint = "PROXY_OUT"
		outMeta.Direction = "outbound"
		outMeta.ByteSource = "upstream_socket_successful_write"
		if mode == "MITM_REISSUE" {
			if selectedTemplate != nil {
				outMeta.Profile = selectedTemplate.Name
				outMeta.ProfileID = selectedTemplate.ID
				outMeta.ProfileVersion = selectedTemplate.Version
				outMeta.ConfigVersion = selectedConfigVersion
			} else {
				outMeta.Profile = profile.Client + "@" + profile.Version
			}
		}
		if mode == "PASSTHROUGH" || mode == "OBSERVE_ONLY" {
			var forwardingMu sync.Mutex
			var forwarded *recorder.ForwardingExpected
			in := tlshello.Wrap(clientConn, true, tlshello.DefaultLimits(), func(c tlshello.Capture) {
				forwardingMu.Lock()
				forwarded = recorder.ForwardingFromCapture(c)
				forwardingMu.Unlock()
				handler.Recorder.TryCapture(meta, c)
			})
			out := tlshello.Wrap(destConn, false, tlshello.DefaultLimits(), func(c tlshello.Capture) {
				forwardingMu.Lock()
				outboundMeta := outMeta
				if forwarded != nil {
					copyExpected := *forwarded
					outboundMeta.Forwarded = &copyExpected
				}
				forwardingMu.Unlock()
				handler.Recorder.TryCapture(outboundMeta, c)
			})
			defer in.Close()
			defer out.Close()
			pipe.Junction(out, in)
			return
		}
		replayed, capture, err := tlshello.Sniff(clientConn, handler.captureTimeout(), tlshello.DefaultLimits())
		clientConn = replayed
		if err != nil {
			handler.Recorder.TryCapture(meta, capture)
			return
		}
		_, parseErr := tlshello.Parse(capture.Raw)
		if capture.Status != "complete" || parseErr != nil {
			if capture.Status == "complete" {
				capture.Status = "malformed"
				capture.ErrorCode = "malformed_client_hello"
			}
			meta.Mode = "PASSTHROUGH"
			outMeta.Mode = "PASSTHROUGH"
			outMeta.Profile = ""
			outMeta.Forwarded = recorder.ForwardingFromCapture(capture)
			handler.Recorder.TryCapture(meta, capture)
			out := tlshello.Wrap(destConn, false, tlshello.DefaultLimits(), func(c tlshello.Capture) { handler.Recorder.TryCapture(outMeta, c) })
			defer out.Close()
			pipe.Junction(out, clientConn)
			return
		}
		handler.Recorder.TryCapture(meta, capture)
		out := tlshello.Wrap(destConn, false, tlshello.DefaultLimits(), func(c tlshello.Capture) { handler.Recorder.TryCapture(outMeta, c) })
		defer out.Close()
		destConn = out
	} else if handler.Mode == "PASSTHROUGH" || handler.Mode == "OBSERVE_ONLY" {
		pipe.Junction(destConn, clientConn)
		return
	}

	config := &tls.Config{
		InsecureSkipVerify: true,
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			serverName := sni
			if hello.ServerName != "" {
				serverName = hello.ServerName
			}
			connectionTemplate := selectedTemplate
			if selectedTemplate != nil {
				effective, constrainErr := tlsprofile.ConstrainALPN(*selectedTemplate, upstreamALPN(hello.SupportedProtos))
				if constrainErr != nil {
					return nil, fmt.Errorf("TLS profile ALPN/ALPS: %w", constrainErr)
				}
				connectionTemplate = &effective
				materialized, materializeErr := tlsprofile.Materialize(effective, serverName)
				if materializeErr != nil {
					return nil, fmt.Errorf("materialize TLS profile: %w", materializeErr)
				}
				outMeta.Expected = expectedForRecorder(materialized.Expected, effective.Policy)
			}

			tlsCert, err := handler.generateCertificate(serverName)
			if err != nil {
				return nil, fmt.Errorf("generate certificate: %w", err)
			}

			destTLSConn, err = handler.wrapUpstreamTLSSelection(destConn, serverName, upstreamALPN(hello.SupportedProtos), profile, connectionTemplate)
			if err != nil {
				return nil, err
			}
			outMeta.RuntimeMutations = append([]recorder.RuntimeMutation(nil), destTLSConn.runtimeMutations...)

			return &tls.Config{
				InsecureSkipVerify: true,
				Certificates:       []tls.Certificate{tlsCert},
				NextProtos:         clientALPN(destTLSConn.NegotiatedProtocol()),
			}, nil
		},
	}

	clientTLSConn := tls.Server(
		clientConn,
		config,
	)
	ctx := context.Background()
	if handler.Recorder != nil {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, handler.captureTimeout())
		defer cancel()
	}
	err := clientTLSConn.HandshakeContext(ctx)
	if err != nil {
		logger.Warn("client TLS handshake failed", "err", err)
		return
	}

	if destTLSConn == nil {
		logger.Error("upstream TLS connection was not established")
		return
	}

	if handler != nil && handler.Debug {
		pipe.DebugJunction(destTLSConn, clientTLSConn)
	} else {
		pipe.Junction(destTLSConn, clientTLSConn)
	}
}

func applyIdentityEvidence(meta recorder.Meta, clientConn net.Conn) recorder.Meta {
	return applyIdentityEvidenceWithRegistry(meta, clientConn, nil)
}

func applyIdentityEvidenceWithRegistry(meta recorder.Meta, clientConn net.Conn, devices *device.Store) recorder.Meta {
	if username := flowid.ProxyUsernameFrom(clientConn); username != "" {
		meta.IdentitySource = "proxy_username"
		meta.IdentityValue = username
		meta.Confidence = "exact"
		return resolveDevice(meta, username, "", devices)
	}
	ip := netutil.StripPort(meta.Source)
	if net.ParseIP(ip) == nil {
		return meta
	}
	meta.IdentitySource = "source_ip"
	meta.IdentityValue = ip
	meta.Confidence = "inferred"
	return resolveDevice(meta, "", ip, devices)
}

func resolveDevice(meta recorder.Meta, username, sourceIP string, devices *device.Store) recorder.Meta {
	if devices == nil {
		return meta
	}
	resolution := devices.ResolveAt(username, sourceIP, time.Now().UTC())
	if resolution.Ambiguous {
		meta.Confidence = "ambiguous"
		meta.ResolvedDeviceID = ""
		return meta
	}
	meta.ResolvedDeviceID = resolution.DeviceID
	if resolution.AssignmentAmbiguous {
		return meta
	}
	meta.Application = resolution.Application
	meta.ApplicationVersion = resolution.ApplicationVersion
	meta.ApplicationID = resolution.ApplicationID
	meta.ApplicationAssignmentID = resolution.AssignmentID
	return meta
}

func expectedForRecorder(expected tlsprofile.Expected, policy tlsprofile.MatchPolicy) *recorder.FingerprintExpected {
	constraints := make([]recorder.FingerprintConstraint, len(policy.Constraints))
	for i, constraint := range policy.Constraints {
		constraints[i] = recorder.FingerprintConstraint{
			Path: constraint.Path, Operator: constraint.Operator,
			Value: append([]byte(nil), constraint.Value...), Values: cloneRawMessages(constraint.Values),
		}
	}
	return &recorder.FingerprintExpected{
		ProfileSchemaVersion: tlsprofile.SchemaVersion,
		JA3:                  expected.JA3, JA3Hash: expected.JA3Hash, JA4: expected.JA4,
		NormalizedSHA256: expected.NormalizedSHA256, Normalized: append([]byte(nil), expected.Normalized...),
		NormalizationVersion: expected.NormalizationVersion, MaterializerVersion: expected.MaterializerVersion,
		MustMatch: append([]string(nil), policy.MustMatch...), ShouldMatch: append([]string(nil), policy.ShouldMatch...),
		IgnoredDynamic: append([]string(nil), policy.IgnoredDynamic...),
		Constraints:    constraints,
	}
}

func cloneRawMessages(values []json.RawMessage) []json.RawMessage {
	cloned := make([]json.RawMessage, len(values))
	for i, value := range values {
		cloned[i] = append(json.RawMessage(nil), value...)
	}
	return cloned
}

func (handler *TunnelHandler) captureTimeout() time.Duration {
	if handler.CaptureTimeout > 0 {
		return handler.CaptureTimeout
	}
	return 5 * time.Second
}
