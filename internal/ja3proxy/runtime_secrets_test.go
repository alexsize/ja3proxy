package ja3proxy

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/lylemi/ja3proxy/internal/ja3proxy/certstore"
)

func TestRuntimeStatusExposesCACertificateValidity(t *testing.T) {
	dir := t.TempDir()
	ca := &certstore.CertificateAuthority{}
	if err := ca.Generate(filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key")); err != nil {
		t.Fatal(err)
	}
	app := newDefaultApp()
	app.CA = ca
	app.Config.WebPanelCert = filepath.Join(dir, "ca.crt")
	status := app.webPanelRuntimeStatusLocked()
	if status.MITMCACertificateStatus != "VALID" || status.MITMCACertificateNotAfter == nil || status.MITMCACertificateDaysRemaining == nil || *status.MITMCACertificateDaysRemaining <= 0 {
		t.Fatalf("CA validity status = %+v", status)
	}
	if status.PanelCertificateStatus != "VALID" || status.PanelCertificateNotAfter == nil || status.PanelCertificateDaysRemaining == nil {
		t.Fatalf("panel certificate validity = %+v", status)
	}
}

func TestResolveProxyCredentialFilesUsesSecretProvider(t *testing.T) {
	dir := t.TempDir()
	usernameFile := filepath.Join(dir, "proxy-user")
	passwordFile := filepath.Join(dir, "proxy-password")
	if err := os.WriteFile(usernameFile, []byte("local-user"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(passwordFile, []byte("local-password"), 0600); err != nil {
		t.Fatal(err)
	}
	app := newDefaultApp()
	app.Config.ProxyUsernameFile = usernameFile
	app.Config.ProxyPasswordFile = passwordFile
	if err := app.resolveProxyCredentialFiles(); err != nil {
		t.Fatal(err)
	}
	if app.Config.ProxyUsername != "local-user" || app.Config.ProxyPassword != "local-password" {
		t.Fatalf("resolved incoming credentials = %q/%q", app.Config.ProxyUsername, app.Config.ProxyPassword)
	}
	if app.Config.ProxyUsernameFile != usernameFile || app.Config.ProxyPasswordFile != passwordFile {
		t.Fatal("secret references were not retained for runtime configuration")
	}
}

func TestValidateProxyCredentialSourcesRequiresPairAndSingleSource(t *testing.T) {
	for _, tc := range []struct {
		name                       string
		username, password         string
		usernameFile, passwordFile string
		wantError                  bool
	}{
		{name: "both files", usernameFile: "user", passwordFile: "pass"},
		{name: "mixed literal and file", username: "user", passwordFile: "pass", wantError: true},
		{name: "username file only", usernameFile: "user", wantError: true},
		{name: "literal pair", username: "user", password: "pass"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := validateProxyCredentialSources(tc.username, tc.password, tc.usernameFile, tc.passwordFile)
			if (err != nil) != tc.wantError {
				t.Fatalf("validateProxyCredentialSources() error = %v, wantError %v", err, tc.wantError)
			}
		})
	}
}

func TestResolveProxyCredentialFilesRejectsEmptyFiles(t *testing.T) {
	dir := t.TempDir()
	usernameFile := filepath.Join(dir, "proxy-user")
	passwordFile := filepath.Join(dir, "proxy-password")
	if err := os.WriteFile(usernameFile, []byte("user"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(passwordFile, nil, 0600); err != nil {
		t.Fatal(err)
	}
	app := newDefaultApp()
	app.Config.ProxyUsernameFile = usernameFile
	app.Config.ProxyPasswordFile = passwordFile
	if err := app.resolveProxyCredentialFiles(); err == nil {
		t.Fatal("empty password file was accepted")
	}
}
