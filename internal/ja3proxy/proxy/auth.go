package proxy

import (
	"crypto/subtle"
	"encoding/base64"
	"net/http"
	"strings"
)

const proxyAuthRealm = `Basic realm="JA3Proxy"`

type proxyCredentials struct {
	username string
	password string
}

func (credentials proxyCredentials) enabled() bool {
	return credentials.username != "" || credentials.password != ""
}

func (credentials proxyCredentials) matches(username, password string) bool {
	usernameMatch := subtle.ConstantTimeCompare([]byte(username), []byte(credentials.username))
	passwordMatch := subtle.ConstantTimeCompare([]byte(password), []byte(credentials.password))
	return usernameMatch&passwordMatch == 1
}

func (p *Proxy) WithAuthentication(username, password string) *Proxy {
	p.SetAuthentication(username, password)
	return p
}

// SetAuthentication changes the credentials used by new HTTP and SOCKS5
// authentication handshakes without interrupting established connections.
func (p *Proxy) SetAuthentication(username, password string) {
	if p == nil {
		return
	}
	p.credentialsMu.Lock()
	p.credentials = proxyCredentials{username: username, password: password}
	p.credentialsMu.Unlock()
}

func (p *Proxy) authentication() proxyCredentials {
	if p == nil {
		return proxyCredentials{}
	}
	p.credentialsMu.RLock()
	defer p.credentialsMu.RUnlock()
	return p.credentials
}

func (p *Proxy) authenticateHTTP(response http.ResponseWriter, request *http.Request) bool {
	_, ok := p.authenticateHTTPIdentity(response, request)
	return ok
}

func (p *Proxy) authenticateHTTPIdentity(response http.ResponseWriter, request *http.Request) (string, bool) {
	credentials := p.authentication()
	if !credentials.enabled() {
		return "", true
	}

	authorization := request.Header.Get("Proxy-Authorization")
	scheme, encoded, ok := strings.Cut(authorization, " ")
	if ok && strings.EqualFold(scheme, "Basic") {
		decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(encoded))
		if err == nil {
			username, password, found := strings.Cut(string(decoded), ":")
			if found && credentials.matches(username, password) {
				request.Header.Del("Proxy-Authorization")
				return username, true
			}
		}
	}

	response.Header().Set("Proxy-Authenticate", proxyAuthRealm)
	http.Error(response, "Proxy Authentication Required", http.StatusProxyAuthRequired)
	return "", false
}
