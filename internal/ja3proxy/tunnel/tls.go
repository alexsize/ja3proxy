package tunnel

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	dnscapture "github.com/lylemi/ja3proxy/internal/ja3proxy/capture/dns"
	"github.com/lylemi/ja3proxy/internal/ja3proxy/capture/http1"
	http2capture "github.com/lylemi/ja3proxy/internal/ja3proxy/capture/http2"
	"github.com/lylemi/ja3proxy/internal/ja3proxy/capture/tlshello"
	"github.com/lylemi/ja3proxy/internal/ja3proxy/certstore"
	"github.com/lylemi/ja3proxy/internal/ja3proxy/device"
	"github.com/lylemi/ja3proxy/internal/ja3proxy/fingerprint"
	"github.com/lylemi/ja3proxy/internal/ja3proxy/flowid"
	"github.com/lylemi/ja3proxy/internal/ja3proxy/logutil"
	"github.com/lylemi/ja3proxy/internal/ja3proxy/netutil"
	"github.com/lylemi/ja3proxy/internal/ja3proxy/pipe"
	"github.com/lylemi/ja3proxy/internal/ja3proxy/recorder"
	"github.com/lylemi/ja3proxy/internal/ja3proxy/routing"
	"github.com/lylemi/ja3proxy/internal/ja3proxy/tlsprofile"
	"github.com/lylemi/ja3proxy/internal/ja3proxy/traffic"
	"github.com/lylemi/ja3proxy/internal/ja3proxy/upstreamtls"
	utls "github.com/refraction-networking/utls"
)

type TunnelHandler struct {
	sessionCacheMu      sync.Mutex
	sessionCache        utls.ClientSessionCache
	Recorder            *recorder.Recorder
	DNSCorrelator       *dnscapture.Correlator
	Devices             *device.Store
	TLSProfiles         *tlsprofile.Store
	Mode                string
	CaptureTimeout      time.Duration
	TLSKeyLogFile       string
	Debug               bool
	CA                  *certstore.CertificateAuthority
	SessionKey          *certstore.SessionKeyHelper
	TLSFingerprints     *fingerprint.TLSFingerprintStore
	UpstreamTLSProfiles *upstreamtls.UpstreamTLSProfileStore
	Routes              *routing.Store
	DefaultTLSClient    string
	DefaultTLSVersion   string
	// DialUpstream opens a connection through a route-specific upstream proxy.
	DialUpstream func(ConnectRequest, string) (net.Conn, error)
	// DialDefault opens a direct/default-upstream connection after routing has
	// completed. It is used when the proxy defers dialing until after
	// ClientHello inspection.
	DialDefault func(ConnectRequest) (net.Conn, error)
}

type scopedSessionCache struct {
	cache  utls.ClientSessionCache
	prefix string
}

func (cache scopedSessionCache) Get(key string) (*utls.ClientSessionState, bool) {
	return cache.cache.Get(cache.prefix + ":" + key)
}

func (cache scopedSessionCache) Put(key string, state *utls.ClientSessionState) {
	cache.cache.Put(cache.prefix+":"+key, state)
}

// uTLS keys sessions only by ServerName. Include the effective TLS profile and
// ALPN offer so a profile change cannot resume a ticket from another variant.
func (handler *TunnelHandler) getUpstreamSessionCache(profile any, protocols []string) utls.ClientSessionCache {
	if handler == nil {
		return nil
	}
	scope, err := json.Marshal(struct {
		Profile   any      `json:"profile"`
		Protocols []string `json:"protocols"`
	}{Profile: profile, Protocols: protocols})
	if err != nil {
		return nil // No resumption is safer than an ambiguous cache namespace.
	}
	digest := sha256.Sum256(scope)
	handler.sessionCacheMu.Lock()
	defer handler.sessionCacheMu.Unlock()
	if handler.sessionCache == nil {
		handler.sessionCache = utls.NewLRUClientSessionCache(256)
	}
	return scopedSessionCache{cache: handler.sessionCache, prefix: hex.EncodeToString(digest[:])}
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
	profile, _, _ := handler.configuredUpstreamTLSProfileWithVersion(host)
	return profile
}

func (handler *TunnelHandler) configuredUpstreamTLSProfileWithVersion(host string) (upstreamtls.UpstreamTLSProfile, uint64, bool) {
	resolution := handler.configuredUpstreamTLSResolution(host)
	return resolution.Profile, resolution.ConfigVersion, resolution.Matched
}

func (handler *TunnelHandler) configuredUpstreamTLSResolution(host string) upstreamtls.RouteResolution {
	if handler != nil && handler.UpstreamTLSProfiles != nil {
		resolution := handler.UpstreamTLSProfiles.Resolve(host)
		if resolution.Matched {
			return resolution
		}
	}
	return upstreamtls.RouteResolution{
		Profile:     upstreamtls.ProfileFromFingerprint(handler.configuredTLSFingerprint()),
		MatchReason: "fingerprint_fallback",
		Matched:     true,
	}
}

type upstreamTLSConn struct {
	net.Conn
	negotiatedProtocol string
	runtimeMutations   []recorder.RuntimeMutation
}

type ConnectRequest struct {
	Host       string
	Port       int
	Username   string
	ClientAddr string
}

// resolvedDestinationIP is populated only for direct connections. When an
// upstream proxy is involved, net.Conn.RemoteAddr identifies that proxy, not
// the destination server, so reporting it as the destination would be false
// evidence. The empty value deliberately means "not resolved here".
func resolvedDestinationIP(conn net.Conn, upstream string) string {
	if conn == nil || strings.TrimSpace(upstream) != "" {
		return ""
	}
	address := conn.RemoteAddr()
	if address == nil {
		return ""
	}
	host, _, err := net.SplitHostPort(address.String())
	if err != nil {
		host = address.String()
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		return ip.String()
	}
	return ""
}

type routeSnapshot struct {
	config  routing.Config
	version uint64
}

func (conn *upstreamTLSConn) NegotiatedProtocol() string {
	if conn == nil {
		return ""
	}
	return conn.negotiatedProtocol
}

func (conn *upstreamTLSConn) ConnectionState() utls.ConnectionState {
	if conn == nil {
		return utls.ConnectionState{}
	}
	if uTLSConn, ok := conn.Conn.(*utls.UConn); ok {
		return uTLSConn.ConnectionState()
	}
	return utls.ConnectionState{NegotiatedProtocol: conn.negotiatedProtocol}
}

func (handler *TunnelHandler) wrapUpstreamTLS(conn net.Conn, routeHost string, serverName string, nextProtos []string) (*upstreamTLSConn, error) {
	profile := handler.configuredUpstreamTLSProfile(routeHost)
	return handler.wrapUpstreamTLSProfile(conn, serverName, nextProtos, profile)
}

func (handler *TunnelHandler) wrapUpstreamTLSProfile(conn net.Conn, serverName string, nextProtos []string, profile upstreamtls.UpstreamTLSProfile) (*upstreamTLSConn, error) {
	return handler.wrapUpstreamTLSSelection(conn, serverName, nextProtos, profile, nil)
}

func (handler *TunnelHandler) wrapUpstreamTLSSelection(conn net.Conn, serverName string, nextProtos []string, profile upstreamtls.UpstreamTLSProfile, template *tlsprofile.Template) (*upstreamTLSConn, error) {
	return handler.wrapUpstreamTLSSelectionWithMutationSink(conn, serverName, nextProtos, profile, template, nil)
}

func (handler *TunnelHandler) wrapUpstreamTLSSelectionWithMutationSink(conn net.Conn, serverName string, nextProtos []string, profile upstreamtls.UpstreamTLSProfile, template *tlsprofile.Template, mutationSink func([]recorder.RuntimeMutation)) (*upstreamTLSConn, error) {
	if template != nil {
		uTLSConn, err := handler.utlsWrapTemplate(conn, serverName, nextProtos, *template)
		if err != nil {
			return nil, err
		}
		return &upstreamTLSConn{Conn: uTLSConn, negotiatedProtocol: uTLSConn.ConnectionState().NegotiatedProtocol}, nil
	}
	switch upstreamtls.NormalizeProtocol(profile.Protocol) {
	case upstreamtls.ProtocolUTLS:
		uTLSConn, mutations, err := handler.utlsWrapAuditedWithMutationSink(conn, serverName, nextProtos, fingerprint.TLSFingerprint{
			Client:  profile.Client,
			Version: profile.Version,
		}, mutationSink)
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

func (handler *TunnelHandler) utlsWrapTemplate(conn net.Conn, serverName string, nextProtos []string, template tlsprofile.Template) (*utls.UConn, error) {
	materialized, err := tlsprofile.Materialize(template, serverName)
	if err != nil {
		return nil, err
	}
	protocols := append([]string(nil), template.Fields.ALPN...)
	if template.ProfileType == tlsprofile.ProfileTypeRandomized {
		protocols = append([]string(nil), nextProtos...)
		if len(protocols) == 0 && template.RandomizedALPN != tlsprofile.RandomizedALPNDisabled {
			protocols = []string{"h2", "http/1.1"}
		}
	}
	config := &utls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: true,
		NextProtos:         protocols,
		ClientSessionCache: handler.getUpstreamSessionCache(template, protocols),
	}
	if materialized.RandomizedID != nil {
		config.CurvePreferences = []utls.CurveID{utls.X25519, utls.CurveP256, utls.CurveP384, utls.CurveP521}
		uTLSConn := utls.UClient(conn, config, *materialized.RandomizedID)
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
	uTLSConn := utls.UClient(conn, config, utls.HelloCustom)
	if materialized.Spec == nil {
		return nil, errors.New("TLS-профиль не содержит ClientHelloSpec")
	}
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
	return handler.utlsWrapAuditedWithMutationSink(conn, sni, nextProtos, fp, nil)
}

func (handler *TunnelHandler) utlsWrapAuditedWithMutationSink(conn net.Conn, sni string, nextProtos []string, fp fingerprint.TLSFingerprint, mutationSink func([]recorder.RuntimeMutation)) (*utls.UConn, []recorder.RuntimeMutation, error) {
	clientHelloID := utls.ClientHelloID{
		Client: fp.Client, Version: fp.Version, Seed: nil, Weights: nil,
	}

	tlsConfig := &utls.Config{
		ServerName:         sni,
		InsecureSkipVerify: true,
		NextProtos:         nextProtos,
		ClientSessionCache: handler.getUpstreamSessionCache(fp, nextProtos),
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
			if mutationSink != nil {
				mutationSink(mutations)
			}
			uTLSConn = utls.UClient(conn, tlsConfig, utls.HelloCustom)
			if err := uTLSConn.ApplyPreset(&spec); err != nil {
				return nil, mutations, err
			}
			handshaken, handshakeErr := handler.handshakeUTLS(uTLSConn)
			return handshaken, mutations, handshakeErr
		}
	}
	if mutationSink != nil {
		mutationSink(nil)
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
	handler.ConnectWithRequest(ConnectRequest{Host: sni}, destConn, clientConn)
}

func (handler *TunnelHandler) ConnectWithRequest(request ConnectRequest, destConn net.Conn, clientConn net.Conn) {
	handler.connectWithRequest(request, destConn, clientConn, nil)
}

// ConnectWithRequestAndSession is used when the proxy defers upstream dialing
// until routing has inspected the bounded ClientHello. It keeps the newly
// selected connection attached to the existing traffic session.
func (handler *TunnelHandler) ConnectWithRequestAndSession(request ConnectRequest, destConn net.Conn, clientConn net.Conn, session *traffic.TrafficSessionHandle) {
	handler.connectWithRequest(request, destConn, clientConn, session)
}

func (handler *TunnelHandler) connectWithRequest(request ConnectRequest, destConn net.Conn, clientConn net.Conn, session *traffic.TrafficSessionHandle) {
	sni := request.Host
	snapshot := handler.routeSnapshot()
	routeDecision := handler.resolvePreTLSRouteAt(request, clientConn, snapshot)
	mode := handler.Mode
	mode = applyRouteMode(mode, routeDecision.Action.Mode)
	defer clientConn.Close()
	defer func() {
		if destConn != nil {
			_ = destConn.Close()
		}
	}()
	var postRoute routing.Decision
	postRouteResolved := false
	observedSNI := ""
	authorityMismatch := false
	selectedUpstream := strings.TrimSpace(routeDecision.Action.Upstream)
	observeOnlyLocked := strings.EqualFold(strings.TrimSpace(mode), "OBSERVE_ONLY")
	captureFailurePolicy := routing.NormalizeCaptureFailurePolicy(routeDecision.Action.CaptureFailurePolicy)
	var initialCapture *tlshello.Capture
	skipRecordingAfterCaptureFailure := false
	if mode != "BLOCK" && handler.hasRoutePhase(routing.PhasePostClientHello, snapshot) {
		var capture tlshello.Capture
		var sniffErr error
		clientConn, capture, sniffErr = tlshello.Sniff(clientConn, handler.captureTimeout(), tlshello.DefaultLimits())
		captureFailed := sniffErr != nil || capture.Status != "complete"
		if !captureFailed {
			if hello, parseErr := tlshello.Parse(capture.Raw); parseErr == nil {
				observedSNI = hello.ServerName
				serverName := hello.ServerName
				if serverName == "" {
					serverName = request.Host
				}
				authorityMismatch = authoritiesMismatch(request.Host, observedSNI)
				var fingerprints *tlshello.Fingerprints
				if calculated, fingerprintErr := tlshello.Calculate(hello, capture.Raw, capture.Records); fingerprintErr == nil {
					fingerprints = &calculated
				}
				postRoute = handler.resolvePostTLSRouteMetadata(request, serverName, hello, fingerprints, clientConn, snapshot)
				postRouteResolved = true
				mode = applyPostRouteMode(mode, postRoute.Action.Mode, observeOnlyLocked)
				policy := routeDecision.Action.MatchPolicy
				if strings.TrimSpace(postRoute.Action.MatchPolicy) != "" {
					policy = postRoute.Action.MatchPolicy
				}
				if !observeOnlyLocked {
					mode = applyAuthorityPolicy(mode, policy, authorityMismatch)
				}
			} else {
				capture.Status = "malformed"
				capture.ErrorStage = "parse"
				capture.ErrorCode = "malformed_client_hello"
				captureFailed = true
			}
		}
		if captureFailed {
			initialCapture = &capture
			var blocked bool
			mode, skipRecordingAfterCaptureFailure, blocked = applyCaptureFailurePolicy(mode, captureFailurePolicy)
			if blocked {
				handler.recordCaptureFailure(request, clientConn, destConn, routeDecision, capture, mode)
				return
			}
		}
	}
	if mode != "BLOCK" {
		if !observeOnlyLocked && postRouteResolved && strings.TrimSpace(postRoute.Action.Upstream) != "" {
			selectedUpstream = strings.TrimSpace(postRoute.Action.Upstream)
		}
		if destConn == nil {
			var dialErr error
			if selectedUpstream != "" {
				if handler.DialUpstream == nil {
					logutil.Warn("tls_tunnel", "route upstream dialer is unavailable", "route_id", routeDecision.MatchedRuleID)
					return
				}
				destConn, dialErr = handler.DialUpstream(request, selectedUpstream)
			} else if handler.DialDefault != nil {
				destConn, dialErr = handler.DialDefault(request)
			} else {
				dialErr = fmt.Errorf("default upstream dialer is unavailable")
			}
			if dialErr != nil {
				logutil.Warn("tls_tunnel", "upstream dial failed", "route_id", routeDecision.MatchedRuleID, "err", dialErr)
				return
			}
			if session != nil {
				destConn, _ = traffic.WrapTunnel(session, destConn, nil)
			}
		} else if postRouteResolved && selectedUpstream != strings.TrimSpace(routeDecision.Action.Upstream) && handler.DialUpstream != nil {
			nextConn, dialErr := handler.DialUpstream(request, selectedUpstream)
			if dialErr != nil {
				logutil.Warn("tls_tunnel", "post-clienthello upstream dial failed", "route_id", postRoute.MatchedRuleID, "err", dialErr)
				return
			}
			_ = destConn.Close()
			destConn = nextConn
			if session != nil {
				destConn, _ = traffic.WrapTunnel(session, destConn, nil)
			}
		}
	}
	var destTLSConn *upstreamTLSConn
	var outMeta recorder.Meta
	serverCaptureWrapped := false
	var serverCaptureMu sync.Mutex
	serverCaptureSequence := 0
	var pendingServerCapture *tlshello.Capture
	var pendingServerMeta recorder.Meta
	var clientRandomMu sync.RWMutex
	var clientRandom []byte
	wrapServerCapture := func() {
		if handler.Recorder == nil || serverCaptureWrapped || destConn == nil {
			return
		}
		serverMeta := outMeta
		serverMeta.CapturePoint = "SERVER_IN"
		serverMeta.Direction = "inbound"
		serverMeta.ByteSource = "upstream_socket_read"
		var serverConn net.Conn = tlshello.WrapServerHello(destConn, true, tlshello.DefaultLimits(), func(c tlshello.Capture) {
			serverCaptureMu.Lock()
			serverCaptureSequence++
			captureMeta := serverMeta
			captureMeta.HandshakeSequence = serverCaptureSequence
			captureMeta.HandshakeEvent = "SERVER_HELLO"
			helperMerge := false
			if c.Status == "complete" {
				if hello, err := tlshello.ParseServerHello(c.Raw); err == nil {
					if hello.Fields.HelloRetryRequest.Value {
						captureMeta.HandshakeEvent = tlshello.HelloRetryRequestType
					} else if hello.Fields.TLSVersion.Value == 0x0304 && handler.TLSKeyLogFile != "" && (mode == "PASSTHROUGH" || mode == "OBSERVE_ONLY") {
						helperMerge = true
					}
				}
			}
			if helperMerge {
				copyCapture := c
				pendingServerCapture, pendingServerMeta = &copyCapture, captureMeta
			}
			serverCaptureMu.Unlock()
			if !helperMerge {
				handler.Recorder.TryCaptureServer(captureMeta, c)
			}
		})
		if handler.TLSKeyLogFile != "" && (mode == "PASSTHROUGH" || mode == "OBSERVE_ONLY") {
			serverConn = tlshello.WrapEncryptedExtensions(serverConn, handler.TLSKeyLogFile, func() []byte {
				clientRandomMu.RLock()
				defer clientRandomMu.RUnlock()
				return append([]byte(nil), clientRandom...)
			}, func(capture tlshello.EncryptedExtensionsCapture) {
				serverCaptureMu.Lock()
				pending := pendingServerCapture
				captureMeta := pendingServerMeta
				pendingServerCapture = nil
				pendingServerMeta = recorder.Meta{}
				serverCaptureMu.Unlock()
				if pending != nil {
					handler.Recorder.TryCaptureServerWithEncryptedExtensions(captureMeta, *pending, capture)
				}
			})
		}
		destConn = serverConn
		serverCaptureWrapped = true
	}
	logger := logutil.WithComponent("tls_tunnel", "sni", sni)
	// Resolve once. A runtime profile change cannot relabel a running handshake.
	profileHost := sni
	if observedSNI != "" {
		profileHost = observedSNI
	}
	upstreamResolution := handler.configuredUpstreamTLSResolution(profileHost)
	profile := upstreamResolution.Profile
	var selectedTemplate *tlsprofile.Template
	var selectedConfigVersion uint64
	var profileMutations []recorder.RuntimeMutation
	if handler.TLSProfiles != nil {
		var template tlsprofile.Template
		var configVersion uint64
		var ok bool
		profileRoute := routeDecision
		if postRouteResolved && postRoute.Action.TLSProfile != "" {
			profileRoute = postRoute
		}
		if profileRoute.Action.TLSProfile != "" {
			template, configVersion, ok = handler.TLSProfiles.ResolveByID(profileRoute.Action.TLSProfile)
			if !ok {
				logutil.Warn("tls_tunnel", "route TLS profile is unavailable", "route_id", profileRoute.MatchedRuleID, "profile_id", profileRoute.Action.TLSProfile)
				return
			}
		} else {
			template, configVersion, ok = handler.TLSProfiles.ResolveWithVersion(profileHost)
		}
		if ok {
			selectedTemplate = &template
			selectedConfigVersion = configVersion
		}
	}
	if mode == "BLOCK" {
		return
	}
	if handler.Recorder != nil {
		recordMode := mode
		if recordMode == "" {
			recordMode = "MITM_REISSUE"
		}
		id := flowid.From(clientConn)
		if id == "" {
			// Direct TunnelHandler users do not pass through MixedProxyListener.
			id = recorder.NewID()
		}
		meta := recorder.Meta{
			ConnectionID: id, CapturePoint: "CLIENT_IN", Direction: "inbound", ByteSource: "client_socket_read",
			Mode: recordMode, Destination: sni, DestinationHost: request.Host,
			DestinationIP: resolvedDestinationIP(destConn, selectedUpstream), DestinationPort: request.Port,
			ConnectHost: request.Host, SNI: observedSNI,
			AuthorityMismatch: authorityMismatch, Source: netutil.RemoteAddr(clientConn),
		}
		meta = applyIdentityEvidenceWithRegistry(meta, clientConn, handler.Devices)
		meta.Routing = routingSnapshotWithPost(routeDecision, postRoute, postRouteResolved)
		outMeta = meta
		// Keep inbound and outbound snapshots independent: the post-ClientHello
		// decision is attached only to the outbound observation later.
		outMeta.Routing = routingSnapshotWithPost(routeDecision, postRoute, postRouteResolved)
		outMeta.CapturePoint = "PROXY_OUT"
		outMeta.Direction = "outbound"
		outMeta.ByteSource = "upstream_socket_successful_write"
		if recordMode == "MITM_REISSUE" {
			outMeta.UpstreamConfigVersion = upstreamResolution.ConfigVersion
			outMeta.MatchedRouteID = upstreamResolution.RouteID
			if upstreamResolution.Matched && upstreamResolution.MatchReason != "fingerprint_fallback" {
				priority := upstreamResolution.Priority
				outMeta.MatchedRoutePriority = &priority
			}
			outMeta.RouteMatchReason = upstreamResolution.MatchReason
			if selectedTemplate != nil {
				outMeta.Profile = selectedTemplate.Name
				outMeta.ProfileType = selectedTemplate.ProfileType
				outMeta.ProfileID = selectedTemplate.ID
				outMeta.ProfileVersion = selectedTemplate.Version
				outMeta.ConfigVersion = selectedConfigVersion
			} else {
				outMeta.Profile = profile.Client + "@" + profile.Version
			}
		}
		if skipRecordingAfterCaptureFailure && initialCapture != nil {
			meta.Mode = mode
			handler.tryCapture(meta, *initialCapture)
			if mode == "PASSTHROUGH" || mode == "OBSERVE_ONLY" {
				pipe.Junction(destConn, clientConn)
				return
			}
		}
		if recordMode == "PASSTHROUGH" || recordMode == "OBSERVE_ONLY" {
			var forwardingMu sync.Mutex
			var forwarded *recorder.ForwardingExpected
			in := tlshello.Wrap(clientConn, true, tlshello.DefaultLimits(), func(c tlshello.Capture) {
				if c.Status == "complete" {
					if random, err := tlshello.ClientRandom(c.Raw); err == nil {
						clientRandomMu.Lock()
						clientRandom = random
						clientRandomMu.Unlock()
					}
				}
				forwardingMu.Lock()
				forwarded = recorder.ForwardingFromCapture(c)
				forwardingMu.Unlock()
				handler.tryCapture(meta, c)
			})
			wrapServerCapture()
			out := tlshello.Wrap(destConn, false, tlshello.DefaultLimits(), func(c tlshello.Capture) {
				forwardingMu.Lock()
				outboundMeta := outMeta
				if forwarded != nil {
					copyExpected := *forwarded
					outboundMeta.Forwarded = &copyExpected
				}
				forwardingMu.Unlock()
				handler.tryCapture(outboundMeta, c)
			})
			defer in.Close()
			defer out.Close()
			pipe.Junction(out, in)
			return
		}
		replayed, capture, err := tlshello.Sniff(clientConn, handler.captureTimeout(), tlshello.DefaultLimits())
		clientConn = replayed
		_, parseErr := tlshello.Parse(capture.Raw)
		if err != nil || capture.Status != "complete" || parseErr != nil {
			if capture.Status == "complete" {
				capture.Status = "malformed"
				capture.ErrorStage = "parse"
				capture.ErrorCode = "malformed_client_hello"
			}
			var blocked, recordFailure bool
			fallbackMode := mode
			fallbackMode, recordFailure, blocked = applyCaptureFailurePolicy(fallbackMode, captureFailurePolicy)
			if blocked {
				handler.tryCapture(meta, capture)
				return
			}
			meta.Mode = fallbackMode
			outMeta.Mode = fallbackMode
			outMeta.Profile = ""
			outMeta.Forwarded = recorder.ForwardingFromCapture(capture)
			handler.tryCapture(meta, capture)
			if !recordFailure {
				pipe.Junction(destConn, clientConn)
				return
			}
			out := tlshello.Wrap(destConn, false, tlshello.DefaultLimits(), func(c tlshello.Capture) { handler.tryCapture(outMeta, c) })
			defer out.Close()
			pipe.Junction(out, clientConn)
			return
		}
		handler.tryCapture(meta, capture)
		wrapServerCapture()
		out := tlshello.Wrap(destConn, false, tlshello.DefaultLimits(), func(c tlshello.Capture) { handler.tryCapture(outMeta, c) })
		defer out.Close()
		destConn = out
	} else if mode == "PASSTHROUGH" || mode == "OBSERVE_ONLY" {
		pipe.Junction(destConn, clientConn)
		return
	}

	config := &tls.Config{
		InsecureSkipVerify: true,
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			recordProfileConflict := func() {
				if handler.Recorder == nil {
					return
				}
				conflictMeta := outMeta
				conflictMeta.CapturePoint = "PROXY_OUT"
				conflictMeta.Direction = "outbound"
				conflictMeta.ByteSource = "upstream_socket_successful_write"
				conflictMeta.HandshakeEvent = "PROFILE_PROTOCOL_CONFLICT"
				handler.Recorder.TryCapture(conflictMeta, tlshello.Capture{Status: "policy_conflict", ErrorStage: "policy", ErrorCode: "PROFILE_PROTOCOL_CONFLICT"})
			}
			serverName := sni
			if hello.ServerName != "" {
				serverName = hello.ServerName
			}
			resolvedPostRoute := postRoute
			if !postRouteResolved {
				resolvedPostRoute = handler.resolvePostTLSRoute(request, serverName, clientConn)
			}
			if postEvidence := routeDecisionEvidence(resolvedPostRoute); postEvidence != nil {
				if outMeta.Routing == nil {
					outMeta.Routing = &recorder.RoutingSnapshot{}
				}
				outMeta.Routing.PostClientHello = postEvidence
			}
			if resolvedPostRoute.MatchedRuleID != "" && strings.EqualFold(resolvedPostRoute.Action.Mode, "BLOCK") {
				return nil, fmt.Errorf("route %q blocked POST_CLIENTHELLO", resolvedPostRoute.MatchedRuleID)
			}
			connectionTemplate := selectedTemplate
			if selectedTemplate != nil {
				if selectedTemplate.ProfileType != tlsprofile.ProfileTypeRandomized {
					effective, mutations, constrainErr := tlsprofile.ConstrainALPNAudited(*selectedTemplate, upstreamALPN(hello.SupportedProtos))
					if constrainErr != nil {
						if errors.Is(constrainErr, tlsprofile.ErrProtocolConflict) {
							recordProfileConflict()
						}
						return nil, fmt.Errorf("TLS profile ALPN/ALPS: %w", constrainErr)
					}
					connectionTemplate = &effective
					profileMutations = append(profileMutations, mutations...)
				}
				materialized, materializeErr := tlsprofile.Materialize(*connectionTemplate, serverName)
				if materializeErr != nil {
					if errors.Is(materializeErr, tlsprofile.ErrProtocolConflict) {
						recordProfileConflict()
					}
					return nil, fmt.Errorf("materialize TLS profile: %w", materializeErr)
				}
				profileMutations = append(profileMutations, materialized.RuntimeMutations...)
				if materialized.RandomizedID == nil {
					outMeta.Expected = expectedForRecorder(materialized.Expected, connectionTemplate.Policy)
				} else {
					outMeta.Expected = nil
				}
			}
			outMeta.RuntimeMutations = append([]recorder.RuntimeMutation(nil), profileMutations...)

			tlsCert, err := handler.generateCertificate(serverName)
			if err != nil {
				return nil, fmt.Errorf("generate certificate: %w", err)
			}

			wrapServerCapture()
			destTLSConn, err = handler.wrapUpstreamTLSSelectionWithMutationSink(destConn, serverName, upstreamALPN(hello.SupportedProtos), profile, connectionTemplate, func(mutations []recorder.RuntimeMutation) {
				outMeta.RuntimeMutations = append(append([]recorder.RuntimeMutation(nil), profileMutations...), mutations...)
			})
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

	if handler.Recorder != nil {
		clientCaptureMeta := outMeta
		clientCaptureMeta.CapturePoint = "CLIENT_IN"
		clientCaptureMeta.Direction = "inbound"
		clientCaptureMeta.ByteSource = "client_socket_read"
		clientCaptureMeta.HandshakeEvent = "CLIENT_HELLO_AFTER_HRR"
		clientConn = wrapClientHelloRetryCapture(clientConn, clientCaptureMeta, handler)
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
	if handler.Recorder != nil {
		state := destTLSConn.ConnectionState()
		handshakeType := tlshello.HandshakeTypeFull
		if state.DidResume {
			handshakeType = tlshello.HandshakeTypeResumed
		}
		negotiatedMeta := outMeta
		negotiatedMeta.CapturePoint = "SERVER_IN"
		negotiatedMeta.Direction = "inbound"
		negotiatedMeta.ByteSource = "upstream_tls_negotiated_state"
		negotiatedMeta.HandshakeEvent = "NEGOTIATED_STATE"
		handler.Recorder.TryCaptureNegotiated(negotiatedMeta, recorder.NegotiatedState{
			ProtocolVersion:             state.Version,
			CipherSuite:                 state.CipherSuite,
			NegotiatedProtocol:          state.NegotiatedProtocol,
			ServerName:                  state.ServerName,
			HandshakeType:               handshakeType,
			SessionResumption:           state.DidResume,
			HandshakeComplete:           state.HandshakeComplete,
			PeerApplicationSettingsSize: len(state.PeerApplicationSettings),
		})
	}

	var clientPipeConn net.Conn = clientTLSConn
	var destPipeConn net.Conn = destTLSConn
	if handler.Recorder != nil {
		requestMeta := outMeta
		requestMeta.CapturePoint = "CLIENT_IN"
		requestMeta.Direction = "inbound"
		requestMeta.ByteSource = "client_socket_read"
		requestMeta.HandshakeEvent = "HTTP1_REQUEST"
		responseMeta := outMeta
		responseMeta.CapturePoint = "SERVER_IN"
		responseMeta.Direction = "inbound"
		responseMeta.ByteSource = "upstream_tls_http1_read"
		responseMeta.HandshakeEvent = "HTTP1_RESPONSE"
		clientPipeConn = http1.WrapConn(clientTLSConn, "client_to_upstream", func(message http1.Message) {
			handler.Recorder.TryCaptureHTTP1(requestMeta, message)
		})
		destPipeConn = http1.WrapConn(destTLSConn, "upstream_to_client", func(message http1.Message) {
			handler.Recorder.TryCaptureHTTP1(responseMeta, message)
		})
		if clientTLSConn.ConnectionState().NegotiatedProtocol == "h2" || destTLSConn.ConnectionState().NegotiatedProtocol == "h2" {
			h2RequestMeta := requestMeta
			h2RequestMeta.HandshakeEvent = "HTTP2_CLIENT"
			h2ResponseMeta := responseMeta
			h2ResponseMeta.ByteSource = "upstream_tls_http2_read"
			h2ResponseMeta.HandshakeEvent = "HTTP2_SERVER"
			clientPipeConn = http2capture.WrapConn(clientPipeConn, "client_to_upstream", func(fingerprint http2capture.Fingerprint) {
				handler.Recorder.TryCaptureHTTP2(h2RequestMeta, fingerprint)
			})
			destPipeConn = http2capture.WrapConn(destPipeConn, "upstream_to_client", func(fingerprint http2capture.Fingerprint) {
				handler.Recorder.TryCaptureHTTP2(h2ResponseMeta, fingerprint)
			})
		}
	}
	if handler != nil && handler.Debug {
		pipe.DebugJunction(destPipeConn, clientPipeConn)
	} else {
		pipe.Junction(destPipeConn, clientPipeConn)
	}
}

// wrapClientHelloRetryCapture observes TLS 1.3 HRR sent by the local MITM TLS
// server and records the following client ClientHello. The first ClientHello
// was already captured before tls.Server consumed the replay connection.
func wrapClientHelloRetryCapture(conn net.Conn, meta recorder.Meta, handler *TunnelHandler) net.Conn {
	var mu sync.Mutex
	sawHelloRetryRequest := false
	serverObserved := tlshello.WrapServerHello(conn, false, tlshello.DefaultLimits(), func(capture tlshello.Capture) {
		if capture.Status != "complete" {
			return
		}
		hello, err := tlshello.ParseServerHello(capture.Raw)
		if err != nil || !hello.Fields.HelloRetryRequest.Available || !hello.Fields.HelloRetryRequest.Value {
			return
		}
		mu.Lock()
		sawHelloRetryRequest = true
		mu.Unlock()
	})
	clientSequence := 0
	return tlshello.Wrap(serverObserved, true, tlshello.DefaultLimits(), func(capture tlshello.Capture) {
		clientSequence++
		if clientSequence == 1 {
			return // The initial ClientHello has its own CLIENT_IN observation.
		}
		mu.Lock()
		afterRetry := sawHelloRetryRequest
		mu.Unlock()
		if !afterRetry {
			return
		}
		captureMeta := meta
		captureMeta.HandshakeSequence = capture.HandshakeSequence
		captureMeta.HandshakeEvent = "CLIENT_HELLO_AFTER_HRR"
		handler.tryCapture(captureMeta, capture)
	})
}

func (handler *TunnelHandler) tryCapture(meta recorder.Meta, capture tlshello.Capture) bool {
	if handler == nil || handler.Recorder == nil {
		return false
	}
	if handler.DNSCorrelator != nil && capture.Status == "complete" &&
		(meta.CapturePoint == "CLIENT_IN" || meta.CapturePoint == "PROXY_OUT") {
		client := netip.Addr{}
		if parsed, err := netip.ParseAddr(strings.TrimSpace(meta.IdentityValue)); err == nil {
			client = parsed
		}
		if !client.IsValid() {
			host, _, err := net.SplitHostPort(strings.TrimSpace(meta.Source))
			if err == nil {
				client, _ = netip.ParseAddr(strings.Trim(host, "[]"))
			}
		}
		destination, err := netip.ParseAddr(strings.TrimSpace(meta.DestinationIP))
		if err == nil && client.IsValid() {
			correlation := handler.DNSCorrelator.CorrelateTLS(client.String(), destination, time.Now().UTC())
			if correlation.Status != "unmatched" {
				meta.DNSCorrelation = &correlation
			}
		}
	}
	return handler.Recorder.TryCapture(meta, capture)
}

func (handler *TunnelHandler) resolvePreTLSRoute(request ConnectRequest, clientConn net.Conn) routing.Decision {
	return handler.resolvePreTLSRouteAt(request, clientConn, nil)
}

func (handler *TunnelHandler) resolvePostTLSRoute(request ConnectRequest, sni string, clientConn net.Conn) routing.Decision {
	return handler.resolvePostTLSRouteAt(request, sni, clientConn, nil)
}

func (handler *TunnelHandler) resolvePreTLSRouteAt(request ConnectRequest, clientConn net.Conn, snapshot *routeSnapshot) routing.Decision {
	return handler.resolveRouteAt(routing.PhasePreTLS, request, "", clientConn, snapshot, nil)
}

func (handler *TunnelHandler) resolvePostTLSRouteAt(request ConnectRequest, sni string, clientConn net.Conn, snapshot *routeSnapshot) routing.Decision {
	return handler.resolveRouteAt(routing.PhasePostClientHello, request, sni, clientConn, snapshot, nil)
}

func (handler *TunnelHandler) resolvePostTLSRouteMetadata(request ConnectRequest, sni string, hello *tlshello.Hello, fingerprints *tlshello.Fingerprints, clientConn net.Conn, snapshot *routeSnapshot) routing.Decision {
	metadata := &routing.Request{}
	if hello != nil {
		metadata.ALPN = append([]string(nil), helloALPN(hello)...)
		metadata.TLSVersions = append([]uint16(nil), hello.SupportedVersions...)
	}
	if fingerprints != nil {
		metadata.JA3 = fingerprints.JA3
		metadata.JA3Hash = fingerprints.JA3Hash
		metadata.JA4 = fingerprints.JA4
	}
	return handler.resolveRouteAt(routing.PhasePostClientHello, request, sni, clientConn, snapshot, metadata)
}

func (handler *TunnelHandler) resolveRoute(phase routing.Phase, request ConnectRequest, sni string, clientConn net.Conn) routing.Decision {
	return handler.resolveRouteAt(phase, request, sni, clientConn, nil, nil)
}

func (handler *TunnelHandler) resolveRouteAt(phase routing.Phase, request ConnectRequest, sni string, clientConn net.Conn, snapshot *routeSnapshot, metadata *routing.Request) routing.Decision {
	if handler == nil || handler.Routes == nil {
		return routing.Decision{}
	}
	var ip netip.Addr
	clientAddr := request.ClientAddr
	if clientAddr == "" {
		clientAddr = netutil.RemoteAddr(clientConn)
	}
	if host := clientAddr; host != "" {
		if parsed, _, err := net.SplitHostPort(host); err == nil {
			ip, _ = netip.ParseAddr(parsed)
		}
	}
	deviceID := ""
	var deviceTags []string
	if handler.Devices != nil {
		sourceIP := ""
		if ip.IsValid() {
			sourceIP = ip.String()
		}
		resolution := handler.Devices.ResolveAt(request.Username, sourceIP, time.Now().UTC())
		if !resolution.Ambiguous {
			deviceID = resolution.DeviceID
			deviceTags = append([]string(nil), resolution.DeviceTags...)
		}
	}
	routingRequest := routing.Request{
		Host: request.Host, SNI: sni, IP: ip, Port: request.Port, DeviceID: deviceID, DeviceTags: deviceTags, Username: request.Username,
	}
	if metadata != nil {
		routingRequest.ALPN = append([]string(nil), metadata.ALPN...)
		routingRequest.TLSVersions = append([]uint16(nil), metadata.TLSVersions...)
		routingRequest.JA3 = metadata.JA3
		routingRequest.JA3Hash = metadata.JA3Hash
		routingRequest.JA4 = metadata.JA4
	}
	if snapshot != nil {
		return routing.ResolveSnapshot(snapshot.config, snapshot.version, phase, routingRequest)
	}
	return handler.Routes.Resolve(phase, routingRequest)
}

func (handler *TunnelHandler) routeSnapshot() *routeSnapshot {
	if handler == nil || handler.Routes == nil {
		return nil
	}
	config, version, ok := handler.Routes.Snapshot()
	if !ok {
		return nil
	}
	return &routeSnapshot{config: config, version: version}
}

func (handler *TunnelHandler) hasRoutePhase(phase routing.Phase, snapshot *routeSnapshot) bool {
	if snapshot != nil {
		for _, rule := range snapshot.config.Rules {
			if rule.Enabled && rule.Phase == phase {
				return true
			}
		}
		return false
	}
	return handler != nil && handler.Routes != nil && handler.Routes.HasPhase(phase)
}

func routingSnapshot(decision routing.Decision) *recorder.RoutingSnapshot {
	return routingSnapshotWithPost(decision, routing.Decision{}, false)
}

func routingSnapshotWithPost(pre, post routing.Decision, postResolved bool) *recorder.RoutingSnapshot {
	preEvidence := routeDecisionEvidence(pre)
	postEvidence := routeDecisionEvidence(post)
	if !postResolved {
		postEvidence = nil
	}
	if preEvidence == nil && postEvidence == nil {
		return nil
	}
	return &recorder.RoutingSnapshot{PreTLS: preEvidence, PostClientHello: postEvidence}
}

func applyRouteMode(current, action string) string {
	if strings.TrimSpace(action) == "" {
		return current
	}
	mode := strings.ToUpper(strings.TrimSpace(action))
	if mode == "ALLOW_AND_RECORD" {
		return "MITM_REISSUE"
	}
	return mode
}

func applyPostRouteMode(current, action string, observeOnlyLocked bool) string {
	if observeOnlyLocked && strings.EqualFold(strings.TrimSpace(current), "OBSERVE_ONLY") {
		return "OBSERVE_ONLY"
	}
	return applyRouteMode(current, action)
}

func applyCaptureFailurePolicy(mode, policy string) (nextMode string, record bool, blocked bool) {
	switch routing.NormalizeCaptureFailurePolicy(policy) {
	case routing.CaptureFailureBlock:
		return "BLOCK", true, true
	case routing.CaptureFailureContinueWithoutRecording:
		return "PASSTHROUGH", false, false
	default:
		return "PASSTHROUGH", true, false
	}
}

func (handler *TunnelHandler) recordCaptureFailure(request ConnectRequest, clientConn, destConn net.Conn, routeDecision routing.Decision, capture tlshello.Capture, mode string) {
	if handler == nil || handler.Recorder == nil {
		return
	}
	id := flowid.From(clientConn)
	if id == "" {
		id = recorder.NewID()
	}
	meta := recorder.Meta{
		ConnectionID: id, CapturePoint: "CLIENT_IN", Direction: "inbound", ByteSource: "client_socket_read",
		Mode: mode, Destination: request.Host, DestinationHost: request.Host,
		DestinationIP: resolvedDestinationIP(destConn, ""), DestinationPort: request.Port,
		ConnectHost: request.Host, Source: netutil.RemoteAddr(clientConn),
	}
	meta = applyIdentityEvidenceWithRegistry(meta, clientConn, handler.Devices)
	meta.Routing = routingSnapshotWithPost(routeDecision, routing.Decision{}, false)
	handler.tryCapture(meta, capture)
}

func authoritiesMismatch(connectHost, sni string) bool {
	connectHost = strings.ToLower(strings.TrimSuffix(netutil.StripPort(strings.TrimSpace(connectHost)), "."))
	sni = strings.ToLower(strings.TrimSuffix(netutil.StripPort(strings.TrimSpace(sni)), "."))
	return connectHost != "" && sni != "" && connectHost != sni
}

func helloALPN(hello *tlshello.Hello) []string {
	if hello == nil {
		return nil
	}
	protocols := make([]string, 0, len(hello.ALPN))
	for _, encoded := range hello.ALPN {
		decoded, err := hex.DecodeString(encoded)
		if err == nil {
			protocols = append(protocols, string(decoded))
			continue
		}
		protocols = append(protocols, encoded)
	}
	return protocols
}

func applyAuthorityPolicy(current, policy string, mismatch bool) string {
	if !mismatch {
		return current
	}
	switch strings.ToLower(strings.TrimSpace(policy)) {
	case "block":
		return "BLOCK"
	case "passthrough":
		return "PASSTHROUGH"
	default:
		return current
	}
}

func routeDecisionEvidence(decision routing.Decision) *recorder.RouteDecision {
	if decision.ConfigVersion == 0 && decision.MatchedRuleID == "" && decision.MatchReason == "" {
		return nil
	}
	evidence := &recorder.RouteDecision{
		ConfigVersion:          decision.ConfigVersion,
		EvaluatedConfigVersion: decision.ConfigVersion,
		CandidateRuleIDs:       append([]string(nil), decision.CandidateRuleIDs...),
		MatchedRuleID:          decision.MatchedRuleID,
		MatchReason:            decision.MatchReason,
		ActionMode:             strings.ToUpper(strings.TrimSpace(decision.Action.Mode)),
		MatchPolicy:            strings.ToLower(strings.TrimSpace(decision.Action.MatchPolicy)),
		CaptureFailurePolicy:   routing.NormalizeCaptureFailurePolicy(decision.Action.CaptureFailurePolicy),
	}
	if decision.MatchedRuleID != "" {
		priority := decision.MatchedRulePriority
		evidence.MatchedRulePriority = &priority
	}
	return evidence
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
