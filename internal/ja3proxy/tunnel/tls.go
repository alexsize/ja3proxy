package tunnel

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"time"

	"github.com/lylemi/ja3proxy/internal/ja3proxy/capture/tlshello"
	"github.com/lylemi/ja3proxy/internal/ja3proxy/certstore"
	"github.com/lylemi/ja3proxy/internal/ja3proxy/fingerprint"
	"github.com/lylemi/ja3proxy/internal/ja3proxy/logutil"
	"github.com/lylemi/ja3proxy/internal/ja3proxy/netutil"
	"github.com/lylemi/ja3proxy/internal/ja3proxy/pipe"
	"github.com/lylemi/ja3proxy/internal/ja3proxy/recorder"
	"github.com/lylemi/ja3proxy/internal/ja3proxy/upstreamtls"
	utls "github.com/refraction-networking/utls"
)

type TunnelHandler struct {
	Recorder            *recorder.Recorder
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
	switch upstreamtls.NormalizeProtocol(profile.Protocol) {
	case upstreamtls.ProtocolUTLS:
		uTLSConn, err := handler.utlsWrap(conn, serverName, nextProtos, fingerprint.TLSFingerprint{
			Client:  profile.Client,
			Version: profile.Version,
		})
		if err != nil {
			return nil, err
		}
		return &upstreamTLSConn{
			Conn:               uTLSConn,
			negotiatedProtocol: uTLSConn.ConnectionState().NegotiatedProtocol,
		}, nil
	default:
		return nil, fmt.Errorf("unsupported upstream TLS protocol %q", profile.Protocol)
	}
}

func (handler *TunnelHandler) customTLSWrap(conn net.Conn, sni string, nextProtos []string) (*utls.UConn, error) {
	return handler.utlsWrap(conn, sni, nextProtos, handler.configuredTLSFingerprint())
}

func (handler *TunnelHandler) utlsWrap(conn net.Conn, sni string, nextProtos []string, fp fingerprint.TLSFingerprint) (*utls.UConn, error) {
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
			limitSpecALPN(&spec, nextProtos)
			uTLSConn = utls.UClient(conn, tlsConfig, utls.HelloCustom)
			if err := uTLSConn.ApplyPreset(&spec); err != nil {
				return nil, err
			}
		}
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

func limitSpecALPN(spec *utls.ClientHelloSpec, nextProtos []string) {
	extensions := make([]utls.TLSExtension, 0, len(spec.Extensions)+1)
	for _, extension := range spec.Extensions {
		switch ext := extension.(type) {
		case *utls.ALPNExtension:
			ext.AlpnProtocols = nextProtos
			extensions = append(extensions, extension)
		case *utls.ApplicationSettingsExtension:
			ext.SupportedProtocols = matchingProtocols(ext.SupportedProtocols, nextProtos)
			if len(ext.SupportedProtocols) > 0 {
				extensions = append(extensions, extension)
			}
		default:
			extensions = append(extensions, extension)
		}
	}

	spec.Extensions = extensions
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
	logger := logutil.WithComponent("tls_tunnel", "sni", sni)
	// Resolve once. A runtime profile change cannot relabel a running handshake.
	profile := handler.configuredUpstreamTLSProfile(sni)
	if handler.Mode == "BLOCK" {
		return
	}
	if handler.Recorder != nil {
		mode := handler.Mode
		if mode == "" {
			mode = "MITM_REISSUE"
		}
		id := recorder.NewID()
		meta := recorder.Meta{ConnectionID: id, CapturePoint: "CLIENT_IN", Direction: "inbound", Mode: mode, Destination: sni, Source: netutil.RemoteAddr(clientConn)}
		outMeta := meta
		outMeta.CapturePoint = "PROXY_OUT"
		outMeta.Direction = "outbound"
		if mode == "MITM_REISSUE" {
			outMeta.Profile = profile.Client + "@" + profile.Version
		}
		if mode == "PASSTHROUGH" || mode == "OBSERVE_ONLY" {
			in := tlshello.Wrap(clientConn, true, tlshello.DefaultLimits(), func(c tlshello.Capture) { handler.Recorder.TryCapture(meta, c) })
			out := tlshello.Wrap(destConn, false, tlshello.DefaultLimits(), func(c tlshello.Capture) { handler.Recorder.TryCapture(outMeta, c) })
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

			tlsCert, err := handler.generateCertificate(serverName)
			if err != nil {
				return nil, fmt.Errorf("generate certificate: %w", err)
			}

			destTLSConn, err = handler.wrapUpstreamTLSProfile(destConn, serverName, upstreamALPN(hello.SupportedProtos), profile)
			if err != nil {
				return nil, err
			}

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

func (handler *TunnelHandler) captureTimeout() time.Duration {
	if handler.CaptureTimeout > 0 {
		return handler.CaptureTimeout
	}
	return 5 * time.Second
}
