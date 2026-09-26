package ja3proxy

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/lylemi/ja3proxy/internal/ja3proxy/certstore"
	"github.com/lylemi/ja3proxy/internal/ja3proxy/dialer"
	"github.com/lylemi/ja3proxy/internal/ja3proxy/fingerprint"
	httpproxy "github.com/lylemi/ja3proxy/internal/ja3proxy/proxy"
	"github.com/lylemi/ja3proxy/internal/ja3proxy/routing"
	"github.com/lylemi/ja3proxy/internal/ja3proxy/state"
	"github.com/lylemi/ja3proxy/internal/ja3proxy/tlsprofile"
	"github.com/lylemi/ja3proxy/internal/ja3proxy/traffic"
	"github.com/lylemi/ja3proxy/internal/ja3proxy/webpanel"
)

func newRuntimeTestApp(t *testing.T) *App {
	t.Helper()

	config := &RunningConfig{
		Addr:       "127.0.0.1",
		Port:       "0",
		TLSClient:  "Golang",
		TLSVersion: "0",
	}
	ca := &certstore.CertificateAuthority{}
	sessionKey := &certstore.SessionKeyHelper{}
	fingerprints := &fingerprint.TLSFingerprintStore{}

	return &App{
		Config:          config,
		CA:              ca,
		SessionKey:      sessionKey,
		TLSFingerprints: fingerprints,
	}
}

func TestEnsureCAReturnsErrorWhenOnlyCertExists(t *testing.T) {
	app := newRuntimeTestApp(t)
	dir := t.TempDir()
	app.Config.Cert = filepath.Join(dir, "cert.pem")
	app.Config.Key = filepath.Join(dir, "key.pem")

	if err := os.WriteFile(app.Config.Cert, []byte("cert"), 0600); err != nil {
		t.Fatalf("write cert: %v", err)
	}

	err := app.ensureCA()
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "found CA cert") {
		t.Fatalf("error = %q, want CA cert context", err)
	}
}

func TestEnsureCAReturnsErrorWhenOnlyKeyExists(t *testing.T) {
	app := newRuntimeTestApp(t)
	dir := t.TempDir()
	app.Config.Cert = filepath.Join(dir, "cert.pem")
	app.Config.Key = filepath.Join(dir, "key.pem")

	if err := os.WriteFile(app.Config.Key, []byte("key"), 0600); err != nil {
		t.Fatalf("write key: %v", err)
	}

	err := app.ensureCA()
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "found CA key") {
		t.Fatalf("error = %q, want CA key context", err)
	}
}

func TestParseFlagsAppliesNormalizedArgs(t *testing.T) {
	app := newRuntimeTestApp(t)

	err := app.parseFlags([]string{
		"--ca-cert", "custom-cert.pem",
		"--ca-key", "custom-key.pem",
		"--listen", "127.0.0.1:9090",
		"--tls-fingerprint", "chrome@120",
		"--tls-profile-file", "upstream-tls.json",
		"--proxy-username", "client",
		"--proxy-password", "secret",
		"--upstream-proxy", "socks5://127.0.0.1:1080",
		"--log-level", "warn",
	})
	if err != nil {
		t.Fatalf("parse flags: %v", err)
	}

	if app.Config.Cert != "custom-cert.pem" {
		t.Fatalf("cert = %q, want custom-cert.pem", app.Config.Cert)
	}
	if app.Config.Key != "custom-key.pem" {
		t.Fatalf("key = %q, want custom-key.pem", app.Config.Key)
	}
	if app.Config.Listen != "127.0.0.1:9090" {
		t.Fatalf("listen = %q, want 127.0.0.1:9090", app.Config.Listen)
	}
	if app.Config.Addr != "127.0.0.1" {
		t.Fatalf("addr = %q, want 127.0.0.1", app.Config.Addr)
	}
	if app.Config.Port != "9090" {
		t.Fatalf("port = %q, want 9090", app.Config.Port)
	}
	if app.Config.TLSClient != "Chrome" {
		t.Fatalf("client = %q, want Chrome", app.Config.TLSClient)
	}
	if app.Config.TLSVersion != "120" {
		t.Fatalf("version = %q, want 120", app.Config.TLSVersion)
	}
	if app.Config.FingerprintConfig != "" {
		t.Fatalf("fingerprint config = %q, want empty", app.Config.FingerprintConfig)
	}
	if app.Config.UpstreamTLSConfig != "upstream-tls.json" {
		t.Fatalf("upstream TLS config = %q, want upstream-tls.json", app.Config.UpstreamTLSConfig)
	}
	if app.Config.Upstream != "socks5://127.0.0.1:1080" {
		t.Fatalf("upstream = %q, want socks5://127.0.0.1:1080", app.Config.Upstream)
	}
	if app.Config.ProxyUsername != "client" || app.Config.ProxyPassword != "secret" {
		t.Fatalf("proxy credentials = %q/%q", app.Config.ProxyUsername, app.Config.ProxyPassword)
	}
	if app.Config.LogLevel != "warn" {
		t.Fatalf("log level = %q, want warn", app.Config.LogLevel)
	}
	if app.Config.DumpTraffic {
		t.Fatal("dump traffic = true, want false")
	}
	if flag.CommandLine.Lookup("cert") != nil {
		t.Fatal("parseFlags registered cert on global flag.CommandLine")
	}
}

func TestParseFlagsValidatesProxyCredentials(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{name: "username only", args: []string{"--proxy-username", "client"}},
		{name: "password only", args: []string{"--proxy-password", "secret"}},
		{name: "colon in username", args: []string{"--proxy-username", "bad:name", "--proxy-password", "secret"}},
		{name: "username too long", args: []string{"--proxy-username", strings.Repeat("u", 256), "--proxy-password", "secret"}},
		{name: "password too long", args: []string{"--proxy-username", "client", "--proxy-password", strings.Repeat("p", 256)}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			app := newRuntimeTestApp(t)
			if err := app.parseFlags(tt.args); err == nil {
				t.Fatal("parseFlags() error = nil, want credential validation error")
			}
		})
	}
}

func TestParseFlagsAppliesTLSFingerprintFile(t *testing.T) {
	app := newRuntimeTestApp(t)

	err := app.parseFlags([]string{"--tls-fingerprint-file", "fingerprints.json"})
	if err != nil {
		t.Fatalf("parse flags: %v", err)
	}
	if app.Config.FingerprintConfig != "fingerprints.json" {
		t.Fatalf("fingerprint config = %q, want fingerprints.json", app.Config.FingerprintConfig)
	}
}

func TestParseFlagsDumpTrafficImpliesDebugLogging(t *testing.T) {
	app := newRuntimeTestApp(t)

	err := app.parseFlags([]string{"--dump-traffic"})
	if err != nil {
		t.Fatalf("parse flags: %v", err)
	}
	if !app.Config.DumpTraffic {
		t.Fatal("dump traffic = false, want true")
	}
	if app.Config.LogLevel != "debug" {
		t.Fatalf("log level = %q, want debug", app.Config.LogLevel)
	}
}

func TestParseFlagsEnablesTUI(t *testing.T) {
	app := newRuntimeTestApp(t)

	err := app.parseFlags([]string{"--tui"})
	if err != nil {
		t.Fatalf("parse flags: %v", err)
	}
	if !app.Config.TUI {
		t.Fatal("tui = false, want true")
	}
}

func TestParseFlagsEnablesWebPanel(t *testing.T) {
	app := newRuntimeTestApp(t)

	err := app.parseFlags([]string{"--web-panel", "127.0.0.1:9090", "--web-panel-token-file", "credentials/panel.token"})
	if err != nil {
		t.Fatalf("parse flags: %v", err)
	}
	if app.Config.WebPanel != "127.0.0.1:9090" {
		t.Fatalf("web panel = %q, want 127.0.0.1:9090", app.Config.WebPanel)
	}
	if app.Config.WebPanelTokenFile != "credentials/panel.token" {
		t.Fatalf("web panel token file = %q, want credentials/panel.token", app.Config.WebPanelTokenFile)
	}
}

func TestParseFlagsWebPanelTLS(t *testing.T) {
	app := newRuntimeTestApp(t)
	if err := app.parseFlags([]string{
		"--web-panel", "0.0.0.0:9090",
		"--web-panel-token-file", "credentials/panel.token",
		"--web-panel-cert", "credentials/panel.crt",
		"--web-panel-key", "credentials/panel.key",
	}); err != nil {
		t.Fatalf("parse flags: %v", err)
	}
	if app.Config.WebPanelCert != "credentials/panel.crt" || app.Config.WebPanelKey != "credentials/panel.key" {
		t.Fatalf("web panel TLS files = %q/%q", app.Config.WebPanelCert, app.Config.WebPanelKey)
	}
}

func TestLoadWebPanelToken(t *testing.T) {
	app := newRuntimeTestApp(t)
	tokenPath := filepath.Join(t.TempDir(), "panel.token")
	if err := os.WriteFile(tokenPath, []byte("  0123456789abcdef  \n"), 0600); err != nil {
		t.Fatalf("write token: %v", err)
	}
	app.Config.WebPanelTokenFile = tokenPath

	if err := app.loadWebPanelToken(); err != nil {
		t.Fatalf("load token: %v", err)
	}
	if app.WebPanelToken != "0123456789abcdef" {
		t.Fatalf("token = %q, want trimmed token", app.WebPanelToken)
	}
	if strings.Join(app.WebPanelScopes, ",") != "read,write" {
		t.Fatalf("scopes = %v, want read,write", app.WebPanelScopes)
	}

	app.Config.WebPanelTokenFile = ""
	if err := app.loadWebPanelToken(); err != nil {
		t.Fatalf("clear token: %v", err)
	}
	if app.WebPanelToken != "" {
		t.Fatalf("token after clearing path = %q, want empty", app.WebPanelToken)
	}
}

func TestLoadWebPanelTokenReadsExplicitScopes(t *testing.T) {
	app := newRuntimeTestApp(t)
	tokenPath := filepath.Join(t.TempDir(), "panel.token.json")
	if err := os.WriteFile(tokenPath, []byte(`{"token":"0123456789abcdef","scopes":["read","raw","read"]}`), 0600); err != nil {
		t.Fatalf("write token: %v", err)
	}
	app.Config.WebPanelTokenFile = tokenPath

	if err := app.loadWebPanelToken(); err != nil {
		t.Fatalf("load token: %v", err)
	}
	if strings.Join(app.WebPanelScopes, ",") != "read,raw" {
		t.Fatalf("scopes = %v, want read,raw", app.WebPanelScopes)
	}
}

func TestLoadWebPanelTokenReadsRoleRegistry(t *testing.T) {
	app := newRuntimeTestApp(t)
	tokenPath := filepath.Join(t.TempDir(), "panel.tokens.json")
	contents := `{"tokens":[{"id":"viewer-1","token":"viewer-token-012345","role":"viewer"},{"id":"admin-1","token":"admin-token-012345","role":"admin"}]}`
	if err := os.WriteFile(tokenPath, []byte(contents), 0600); err != nil {
		t.Fatalf("write token registry: %v", err)
	}
	app.Config.WebPanelTokenFile = tokenPath

	if err := app.loadWebPanelToken(); err != nil {
		t.Fatalf("load token registry: %v", err)
	}
	if app.WebPanelToken != "" || len(app.WebPanelTokens) != 2 {
		t.Fatalf("legacy token fields = %q/%v, tokens = %+v", app.WebPanelToken, app.WebPanelScopes, app.WebPanelTokens)
	}
	if strings.Join(app.WebPanelTokens[0].Scopes, ",") != "read" || strings.Join(app.WebPanelTokens[1].Scopes, ",") != "read,write,raw,export" {
		t.Fatalf("role scopes = %+v", app.WebPanelTokens)
	}
}

func TestLoadWebPanelTokenRejectsRegistryWithOnlyRevokedTokens(t *testing.T) {
	app := newRuntimeTestApp(t)
	path := filepath.Join(t.TempDir(), "panel.tokens.json")
	if err := os.WriteFile(path, []byte(`{"tokens":[{"id":"old","token":"old-token-012345","role":"admin","revoked":true}]}`), 0600); err != nil {
		t.Fatalf("write token registry: %v", err)
	}
	app.Config.WebPanelTokenFile = path
	if err := app.loadWebPanelToken(); err == nil || !strings.Contains(err.Error(), "active token") {
		t.Fatalf("load revoked-only token registry error = %v", err)
	}
}

func TestLoadWebPanelTokenReadsExpiry(t *testing.T) {
	app := newRuntimeTestApp(t)
	tokenPath := filepath.Join(t.TempDir(), "panel.token.json")
	expiresAt := time.Now().UTC().Add(time.Hour).Truncate(time.Second)
	contents := fmt.Sprintf(`{"token":"0123456789abcdef","scopes":["read"],"expires_at":%q}`, expiresAt.Format(time.RFC3339))
	if err := os.WriteFile(tokenPath, []byte(contents), 0600); err != nil {
		t.Fatalf("write token: %v", err)
	}
	app.Config.WebPanelTokenFile = tokenPath

	if err := app.loadWebPanelToken(); err != nil {
		t.Fatalf("load token: %v", err)
	}
	if !app.WebPanelTokenExpiry.Equal(expiresAt) {
		t.Fatalf("expiry = %s, want %s", app.WebPanelTokenExpiry, expiresAt)
	}
}

func TestLoadWebPanelTokenRejectsExpiredToken(t *testing.T) {
	app := newRuntimeTestApp(t)
	tokenPath := filepath.Join(t.TempDir(), "panel.token.json")
	contents := `{"token":"0123456789abcdef","scopes":["read"],"expires_at":"2020-01-01T00:00:00Z"}`
	if err := os.WriteFile(tokenPath, []byte(contents), 0600); err != nil {
		t.Fatalf("write token: %v", err)
	}
	app.Config.WebPanelTokenFile = tokenPath

	if err := app.loadWebPanelToken(); err == nil {
		t.Fatal("load expired token error = nil")
	}
}

func TestLoadWebPanelTokenRejectsShortToken(t *testing.T) {
	app := newRuntimeTestApp(t)
	tokenPath := filepath.Join(t.TempDir(), "panel.token")
	if err := os.WriteFile(tokenPath, []byte("too-short"), 0600); err != nil {
		t.Fatalf("write token: %v", err)
	}
	app.Config.WebPanelTokenFile = tokenPath

	if err := app.loadWebPanelToken(); err == nil {
		t.Fatal("load token error = nil, want short-token error")
	}
}

func TestEnsureTrafficMonitorForWebPanel(t *testing.T) {
	app := newRuntimeTestApp(t)
	app.Config.WebPanel = "127.0.0.1:9090"

	app.ensureTrafficMonitor()

	if app.TrafficMonitor == nil {
		t.Fatal("traffic monitor = nil, want initialized monitor")
	}
}

func TestParseFlagsReturnsErrorForInvalidFlag(t *testing.T) {
	app := newRuntimeTestApp(t)

	err := app.parseFlags([]string{"-unknown"})
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "flag provided but not defined") {
		t.Fatalf("error = %q, want unknown flag context", err)
	}
	if flag.CommandLine.Lookup("unknown") != nil {
		t.Fatal("parseFlags registered unknown on global flag.CommandLine")
	}
}

func TestParseFlagsAppliesFingerprintShorthand(t *testing.T) {
	app := newRuntimeTestApp(t)

	err := app.parseFlags([]string{"--tls-fingerprint", "chrome@120"})
	if err != nil {
		t.Fatalf("parse flags: %v", err)
	}
	if app.Config.TLSClient != "Chrome" {
		t.Fatalf("client = %q, want Chrome", app.Config.TLSClient)
	}
	if app.Config.TLSVersion != "120" {
		t.Fatalf("version = %q, want 120", app.Config.TLSVersion)
	}
}

func TestParseFlagsReturnsErrorForInvalidFingerprintShorthand(t *testing.T) {
	app := newRuntimeTestApp(t)

	err := app.parseFlags([]string{"--tls-fingerprint", "chrome@999"})
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "available Chrome versions") {
		t.Fatalf("error = %q, want available versions", err)
	}
}

func TestParseFlagsRejectsRemovedFlag(t *testing.T) {
	app := newRuntimeTestApp(t)

	err := app.parseFlags([]string{"-port", "9090"})
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "flag provided but not defined") {
		t.Fatalf("error = %q, want unknown flag context", err)
	}
}

func TestParseFlagsRejectsFingerprintFileWithGlobalFingerprint(t *testing.T) {
	app := newRuntimeTestApp(t)

	err := app.parseFlags([]string{"--tls-fingerprint-file", "fingerprints.json", "--tls-fingerprint", "chrome@120"})
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "--tls-fingerprint-file") {
		t.Fatalf("error = %q, want fingerprint file conflict context", err)
	}
}

func TestParseFlagsListFingerprintsSkipsFingerprintParsing(t *testing.T) {
	app := newRuntimeTestApp(t)

	err := app.parseFlags([]string{"--list-tls-fingerprints", "--tls-fingerprint", "not-a-browser"})
	if err != nil {
		t.Fatalf("parse flags: %v", err)
	}
	if !app.Config.ListFingerprints {
		t.Fatal("list fingerprints = false, want true")
	}
}

func TestConfigureTLSFingerprintReturnsValidationError(t *testing.T) {
	app := newRuntimeTestApp(t)
	app.Config.TLSClient = "UnsupportedClient"
	app.Config.TLSVersion = "0"

	err := app.configureTLSFingerprint(context.Background())
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "failed configuring TLS fingerprint") {
		t.Fatalf("error = %q, want fingerprint context", err)
	}
}

func TestConfigureTLSFingerprintUsesSQLiteUnlessCLIOverridesIt(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	database, err := state.OpenSQLite(path)
	if err != nil {
		t.Fatal(err)
	}
	store := &fingerprint.TLSFingerprintStore{}
	if _, err := store.BindState(database); err != nil {
		t.Fatal(err)
	}
	if err := store.SetValidated(fingerprint.TLSFingerprint{Client: "Firefox", Version: "105"}); err != nil {
		t.Fatal(err)
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}

	database, err = state.OpenSQLite(path)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()

	app := newRuntimeTestApp(t)
	app.StateDB = database
	app.Config.TLSClient = "Golang"
	app.Config.TLSVersion = "0"
	if err := app.configureTLSFingerprint(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := app.configuredTLSFingerprint(); got.Client != "Firefox" || got.Version != "105" {
		t.Fatalf("SQLite fingerprint = %+v, want Firefox 105", got)
	}

	app.Config.TLSClient = "Chrome"
	app.Config.TLSVersion = "120"
	app.Config.TLSFingerprintExplicit = true
	if err := app.configureTLSFingerprint(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := app.configuredTLSFingerprint(); got.Client != "Chrome" || got.Version != "120" {
		t.Fatalf("explicit CLI fingerprint = %+v, want Chrome 120", got)
	}
}

func TestConfiguredTLSFingerprintFallsBackToConfig(t *testing.T) {
	app := newRuntimeTestApp(t)
	app.Config.TLSClient = "Chrome"
	app.Config.TLSVersion = "106"

	got := app.configuredTLSFingerprint()
	if got.Client != "Chrome" || got.Version != "106" {
		t.Fatalf("App.configuredTLSFingerprint() = %+v, want Chrome 106", got)
	}
}

func TestSetTLSFingerprintOverridesConfig(t *testing.T) {
	app := newRuntimeTestApp(t)
	app.Config.TLSClient = "Golang"
	app.Config.TLSVersion = "0"

	if err := app.TLSFingerprints.SetValidated(fingerprint.TLSFingerprint{Client: "Firefox", Version: "105"}); err != nil {
		t.Fatalf("TLSFingerprintStore.SetValidated() error = %v", err)
	}

	got := app.configuredTLSFingerprint()
	if got.Client != "Firefox" || got.Version != "105" {
		t.Fatalf("App.configuredTLSFingerprint() = %+v, want Firefox 105", got)
	}
}

func TestConfigureTLSFingerprintReturnsFileError(t *testing.T) {
	app := newRuntimeTestApp(t)
	app.Config.FingerprintConfig = filepath.Join(t.TempDir(), "missing.json")

	err := app.configureTLSFingerprint(context.Background())
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "failed loading fingerprint config") {
		t.Fatalf("error = %q, want fingerprint file context", err)
	}
}

func TestConfigureTLSFingerprintPassesContextToWatcher(t *testing.T) {
	type contextKey struct{}

	app := newRuntimeTestApp(t)
	app.Config.FingerprintConfig = filepath.Join(t.TempDir(), "fingerprint.json")

	baseCtx, cancel := context.WithCancel(context.Background())
	ctx := context.WithValue(baseCtx, contextKey{}, "runtime")
	called := false
	app.watchFingerprintFile = func(gotCtx context.Context, path string, interval time.Duration) error {
		called = true
		if gotCtx.Value(contextKey{}) != "runtime" {
			t.Fatal("watcher did not receive configured context")
		}
		if path != app.Config.FingerprintConfig {
			t.Fatalf("watch path = %q, want %q", path, app.Config.FingerprintConfig)
		}
		if interval != 2*time.Second {
			t.Fatalf("watch interval = %s, want 2s", interval)
		}

		cancel()
		select {
		case <-gotCtx.Done():
		default:
			t.Fatal("watcher context was not canceled")
		}
		return nil
	}

	if err := app.configureTLSFingerprint(ctx); err != nil {
		t.Fatalf("configureTLSFingerprint() error = %v", err)
	}
	if !called {
		t.Fatal("watcher was not called")
	}
}

func TestBuildProxyReturnsUpstreamValidationError(t *testing.T) {
	app := newRuntimeTestApp(t)
	app.Config.Upstream = "https://127.0.0.1:1080"

	proxy, err := app.buildProxy()
	if err == nil {
		t.Fatal("expected error")
	}
	if proxy != nil {
		t.Fatalf("proxy = %#v, want nil", proxy)
	}
	if !strings.Contains(err.Error(), "configure upstream proxy") {
		t.Fatalf("error = %q, want upstream context", err)
	}
}

func TestValidateRouteReferencesRejectsInvalidUpstream(t *testing.T) {
	app := newRuntimeTestApp(t)
	app.Routes = &routing.Store{}
	if err := app.Routes.SetValidated(routing.Config{Rules: []routing.Rule{{
		ID: "broken-upstream", Enabled: true, Phase: routing.PhasePreTLS,
		Match:  routing.Match{Host: "example.com"},
		Action: routing.Action{Upstream: "https://127.0.0.1:1080"},
	}}}); err != nil {
		t.Fatalf("configure route: %v", err)
	}
	if err := app.validateRouteReferences(); err == nil || !strings.Contains(err.Error(), `route "broken-upstream" upstream`) {
		t.Fatalf("validation error = %v", err)
	}
}

func TestValidateRouteReferencesRejectsUnavailableTLSProfile(t *testing.T) {
	app := newRuntimeTestApp(t)
	app.Routes = &routing.Store{}
	app.TLSProfiles = &tlsprofile.Store{}
	if err := app.Routes.SetValidated(routing.Config{Rules: []routing.Rule{{
		ID: "missing-profile", Enabled: true, Phase: routing.PhasePreTLS,
		Match:  routing.Match{Host: "example.com"},
		Action: routing.Action{TLSProfile: "does-not-exist"},
	}}}); err != nil {
		t.Fatalf("configure route: %v", err)
	}
	if err := app.validateRouteReferences(); err == nil || !strings.Contains(err.Error(), `tls_profile "does-not-exist"`) {
		t.Fatalf("validation error = %v", err)
	}
}

func TestBuildProxyAttachesTrafficMonitor(t *testing.T) {
	app := newRuntimeTestApp(t)
	monitor := traffic.NewTrafficMonitor()
	app.TrafficMonitor = monitor

	proxy, err := app.buildProxy()
	if err != nil {
		t.Fatalf("buildProxy() error = %v", err)
	}
	if proxy.TrafficMonitor() != monitor {
		t.Fatal("proxy monitor was not attached")
	}
}

func TestDialRoutedTunnelUsesRouteUpstream(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen route upstream: %v", err)
	}
	defer listener.Close()

	requestCh := make(chan *http.Request, 1)
	errorCh := make(chan error, 1)
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			errorCh <- acceptErr
			return
		}
		defer conn.Close()
		request, requestErr := http.ReadRequest(bufio.NewReader(conn))
		if requestErr != nil {
			errorCh <- requestErr
			return
		}
		requestCh <- request
		_, writeErr := io.WriteString(conn, "HTTP/1.1 200 Connection Established\r\n\r\n")
		errorCh <- writeErr
	}()

	app := newRuntimeTestApp(t)
	app.Routes = &routing.Store{}
	if err := app.Routes.SetValidated(routing.Config{Rules: []routing.Rule{{
		ID: "mobile-upstream", Enabled: true, Phase: routing.PhasePreTLS,
		Match:  routing.Match{Host: "example.com"},
		Action: routing.Action{Upstream: "http://" + listener.Addr().String()},
	}}}); err != nil {
		t.Fatalf("configure routes: %v", err)
	}
	defaultDialer, err := dialer.NewDynamicUpstreamDialer("", time.Second)
	if err != nil {
		t.Fatalf("create default dialer: %v", err)
	}

	conn, err := app.dialRoutedTunnel(httpproxy.TunnelRequest{Host: "example.com", Port: 443}, defaultDialer)
	if err != nil {
		t.Fatalf("dial routed tunnel: %v", err)
	}
	conn.Close()

	select {
	case request := <-requestCh:
		if request.Method != http.MethodConnect || request.Host != "example.com:443" {
			t.Fatalf("route upstream request = %s %s", request.Method, request.Host)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for route upstream request")
	}
	if err := <-errorCh; err != nil {
		t.Fatalf("route upstream server: %v", err)
	}
}

func TestUpdateProxyConfigChangesFingerprintAndRoute(t *testing.T) {
	app := newRuntimeTestApp(t)
	app.TrafficMonitor = traffic.NewTrafficMonitor()
	if _, err := app.buildProxy(); err != nil {
		t.Fatalf("buildProxy() error = %v", err)
	}
	fingerprintSpec := "chrome@120"
	upstream := "socks5://user:secret@127.0.0.1:1080"

	status, err := app.updateProxyConfig(webpanel.ConfigUpdate{TLSFingerprint: &fingerprintSpec, Upstream: &upstream})
	if err != nil {
		t.Fatalf("updateProxyConfig() error = %v", err)
	}
	if status.TLSClient != "Chrome" || status.TLSVersion != "120" {
		t.Fatalf("fingerprint = %s@%s, want Chrome@120", status.TLSClient, status.TLSVersion)
	}
	if status.ConfigVersion != 1 {
		t.Fatalf("config version = %d, want 1", status.ConfigVersion)
	}
	if status.Upstream != "socks5://user@127.0.0.1:1080" {
		t.Fatalf("display upstream = %q, want redacted credentials", status.Upstream)
	}
	if !status.UpstreamEnabled || len(status.Chain) != 4 {
		t.Fatalf("runtime status = %+v", status)
	}
	if app.Config.Upstream != upstream {
		t.Fatalf("config upstream = %q, want %q", app.Config.Upstream, upstream)
	}
}

func TestUpdateProxyConfigRejectsStaleExpectedVersionWithoutMutation(t *testing.T) {
	app := newRuntimeTestApp(t)
	if _, err := app.buildProxy(); err != nil {
		t.Fatalf("buildProxy() error = %v", err)
	}
	fingerprintSpec := "chrome@120"
	expected := uint64(0)
	if _, err := app.updateProxyConfig(webpanel.ConfigUpdate{ExpectedVersion: &expected, TLSFingerprint: &fingerprintSpec}); err != nil {
		t.Fatalf("initial update: %v", err)
	}

	stale := uint64(0)
	upstream := "socks5://127.0.0.1:1080"
	if _, err := app.updateProxyConfig(webpanel.ConfigUpdate{ExpectedVersion: &stale, Upstream: &upstream}); !errors.Is(err, webpanel.ErrConfigVersionConflict) {
		t.Fatalf("stale update error = %v, want conflict", err)
	}
	if got := app.UpstreamDialer.Upstream(); got != "" {
		t.Fatalf("stale update mutated upstream = %q", got)
	}
	if got := app.runtimeConfigVersion; got != 1 {
		t.Fatalf("config version after stale update = %d, want 1", got)
	}
}

func TestUpdateProxyConfigChangesDownstreamAuthentication(t *testing.T) {
	app := newRuntimeTestApp(t)
	if _, err := app.buildProxy(); err != nil {
		t.Fatalf("buildProxy() error = %v", err)
	}
	enabled := true
	username := "client"
	password := "secret"
	status, err := app.updateProxyConfig(webpanel.ConfigUpdate{
		ProxyAuthEnabled: &enabled,
		ProxyUsername:    &username,
		ProxyPassword:    &password,
	})
	if err != nil {
		t.Fatalf("enable proxy authentication: %v", err)
	}
	if !status.ProxyAuthEnabled || status.ProxyUsername != username {
		t.Fatalf("runtime status = %+v", status)
	}
	if app.Config.ProxyUsername != username || app.Config.ProxyPassword != password {
		t.Fatalf("configured credentials = %q/%q", app.Config.ProxyUsername, app.Config.ProxyPassword)
	}
	request := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	response := httptest.NewRecorder()
	app.ProxyServer.ServeHTTP(response, request)
	if response.Code != http.StatusProxyAuthRequired {
		t.Fatalf("unauthenticated HTTP status = %d, want %d", response.Code, http.StatusProxyAuthRequired)
	}

	nextUsername := "next-client"
	status, err = app.updateProxyConfig(webpanel.ConfigUpdate{
		ProxyAuthEnabled: &enabled,
		ProxyUsername:    &nextUsername,
	})
	if err != nil {
		t.Fatalf("change proxy username while preserving password: %v", err)
	}
	if status.ProxyUsername != nextUsername || app.Config.ProxyPassword != password {
		t.Fatalf("updated credentials = %q/%q", app.Config.ProxyUsername, app.Config.ProxyPassword)
	}

	enabled = false
	status, err = app.updateProxyConfig(webpanel.ConfigUpdate{ProxyAuthEnabled: &enabled})
	if err != nil {
		t.Fatalf("disable proxy authentication: %v", err)
	}
	if status.ProxyAuthEnabled || status.ProxyUsername != "" || app.Config.ProxyPassword != "" {
		t.Fatalf("authentication was not cleared: status=%+v config=%+v", status, app.Config)
	}
}

func TestUpdateProxyConfigRejectsIncompleteDownstreamAuthentication(t *testing.T) {
	app := newRuntimeTestApp(t)
	if _, err := app.buildProxy(); err != nil {
		t.Fatalf("buildProxy() error = %v", err)
	}
	enabled := true
	username := "client"
	if _, err := app.updateProxyConfig(webpanel.ConfigUpdate{
		ProxyAuthEnabled: &enabled,
		ProxyUsername:    &username,
	}); err == nil {
		t.Fatal("updateProxyConfig() error = nil, want missing password error")
	}
	if app.Config.ProxyUsername != "" || app.Config.ProxyPassword != "" {
		t.Fatalf("invalid credentials were applied: %+v", app.Config)
	}
}

func TestUpdateProxyConfigDoesNotApplyRouteWhenFingerprintIsInvalid(t *testing.T) {
	app := newRuntimeTestApp(t)
	if _, err := app.buildProxy(); err != nil {
		t.Fatalf("buildProxy() error = %v", err)
	}
	fingerprintSpec := "not-a-fingerprint"
	upstream := "socks5://127.0.0.1:1080"

	if _, err := app.updateProxyConfig(webpanel.ConfigUpdate{TLSFingerprint: &fingerprintSpec, Upstream: &upstream}); err == nil {
		t.Fatal("updateProxyConfig() error = nil, want validation error")
	}
	if got := app.UpstreamDialer.Upstream(); got != "" {
		t.Fatalf("upstream = %q, invalid update was partially applied", got)
	}
}

func TestUpdateProxyConfigRebindsProxyPort(t *testing.T) {
	app := newRuntimeTestApp(t)
	if _, err := app.buildProxy(); err != nil {
		t.Fatalf("buildProxy() error = %v", err)
	}
	initial, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen on initial socket: %v", err)
	}
	app.proxyListener = newRebindableListener(initial)
	t.Cleanup(func() { _ = app.proxyListener.Close() })

	available, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("find available port: %v", err)
	}
	port := available.Addr().(*net.TCPAddr).Port
	_ = available.Close()

	status, err := app.updateProxyConfig(webpanel.ConfigUpdate{ProxyPort: &port})
	if err != nil {
		t.Fatalf("updateProxyConfig() error = %v", err)
	}
	if status.ProxyPort != port {
		t.Fatalf("proxy port = %d, want %d", status.ProxyPort, port)
	}
	if app.Config.Port != strconv.Itoa(port) {
		t.Fatalf("config port = %q, want %d", app.Config.Port, port)
	}
	conn, err := net.DialTimeout("tcp", status.ProxyListen, time.Second)
	if err != nil {
		t.Fatalf("dial rebound listener: %v", err)
	}
	_ = conn.Close()
}

func TestUpdateProxyConfigKeepsCurrentPortWhenReplacementIsOccupied(t *testing.T) {
	app := newRuntimeTestApp(t)
	initial, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen on initial socket: %v", err)
	}
	app.proxyListener = newRebindableListener(initial)
	t.Cleanup(func() { _ = app.proxyListener.Close() })
	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen on occupied socket: %v", err)
	}
	defer occupied.Close()
	port := occupied.Addr().(*net.TCPAddr).Port
	current := app.proxyListener.Addr().String()

	if _, err := app.updateProxyConfig(webpanel.ConfigUpdate{ProxyPort: &port}); err == nil {
		t.Fatal("updateProxyConfig() error = nil, want occupied-port error")
	}
	if got := app.proxyListener.Addr().String(); got != current {
		t.Fatalf("proxy listener = %q, want unchanged %q", got, current)
	}
}

func TestUpdateProxyConfigChangesListenProtocol(t *testing.T) {
	app := newRuntimeTestApp(t)
	base, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	app.protocolListener = httpproxy.NewMixedProxyListener(base, httpproxy.NewProxy(nil, nil, nil))
	t.Cleanup(func() { _ = app.protocolListener.Close() })
	protocol := httpproxy.ProtocolSOCKS5

	status, err := app.updateProxyConfig(webpanel.ConfigUpdate{ProxyProtocol: &protocol})
	if err != nil {
		t.Fatalf("updateProxyConfig() error = %v", err)
	}
	if status.ProxyProtocol != httpproxy.ProtocolSOCKS5 || app.Config.ProxyProtocol != httpproxy.ProtocolSOCKS5 {
		t.Fatalf("proxy protocol status/config = %q/%q, want socks5", status.ProxyProtocol, app.Config.ProxyProtocol)
	}
}

func TestUpdateProxyConfigRejectsUnknownListenProtocol(t *testing.T) {
	app := newRuntimeTestApp(t)
	base, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	app.protocolListener = httpproxy.NewMixedProxyListener(base, httpproxy.NewProxy(nil, nil, nil))
	t.Cleanup(func() { _ = app.protocolListener.Close() })
	protocol := "ftp"

	if _, err := app.updateProxyConfig(webpanel.ConfigUpdate{ProxyProtocol: &protocol}); err == nil {
		t.Fatal("updateProxyConfig() error = nil, want validation error")
	}
	if got := app.protocolListener.Protocol(); got != httpproxy.ProtocolMixed {
		t.Fatalf("proxy protocol = %q, want unchanged mixed", got)
	}
}

func TestRedactUpstreamHidesPasswordWithoutExplicitScheme(t *testing.T) {
	if got := redactUpstream("user:secret@127.0.0.1:1080"); got != "socks5://user@127.0.0.1:1080" {
		t.Fatalf("redactUpstream() = %q", got)
	}
}

func TestServeReturnsCanceledContext(t *testing.T) {
	app := newRuntimeTestApp(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := app.serve(ctx, httpproxy.NewProxy(nil, nil, nil))
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("serve() error = %v, want context.Canceled", err)
	}
}

func TestRunServicesStopsPeersWhenServiceFails(t *testing.T) {
	wantErr := errors.New("panel failed")
	peerStopped := make(chan struct{})

	err := runServices(context.Background(),
		func(context.Context) error { return wantErr },
		func(ctx context.Context) error {
			<-ctx.Done()
			close(peerStopped)
			return ctx.Err()
		},
	)

	if !errors.Is(err, wantErr) {
		t.Fatalf("runServices() error = %v, want %v", err, wantErr)
	}
	select {
	case <-peerStopped:
	default:
		t.Fatal("peer service did not stop")
	}
}
