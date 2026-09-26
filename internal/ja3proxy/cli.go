package ja3proxy

import (
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/lylemi/ja3proxy/internal/ja3proxy/fingerprint"
)

const (
	defaultListen       = ":8080"
	defaultCACertPath   = "credentials/cert.pem"
	defaultCAKeyPath    = "credentials/key.pem"
	defaultTLSClient    = "Golang"
	defaultTLSVersion   = "0"
	defaultLogLevelName = "info"
)

type cliOptions struct {
	captureTLS             bool
	captureTCPInterface    string
	listCaptureInterfaces  bool
	captureRaw             bool
	tlsKeyLogFile          string
	captureJSONL           string
	captureSQLite          string
	captureSQLiteRetention int
	stateSQLite            string
	captureSpool           string
	captureSpoolKey        string
	captureSpoolMaxBytes   int64
	auditLog               string
	auditSQLite            string
	deviceMapFile          string
	tlsMode                string
	tlsTemplateFile        string
	listen                 string
	caCert                 string
	caKey                  string
	tlsFingerprint         string
	tlsFingerprintFile     string
	tlsProfileFile         string
	routeConfigFile        string
	upstreamProxy          string
	proxyUsername          string
	proxyPassword          string
	proxyUsernameFile      string
	proxyPasswordFile      string
	logLevel               string
	dumpTraffic            bool
	tui                    bool
	webPanel               string
	webPanelTokenFile      string
	webPanelCert           string
	webPanelKey            string
	listTLSFingerprints    bool
}

func (app *App) parseFlags(args []string) error {
	if app.Config == nil {
		app.Config = &RunningConfig{}
	}

	options := newDefaultCLIOptions()
	flags := flag.NewFlagSet(os.Args[0], flag.ContinueOnError)
	flags.Usage = func() {
		writeCLIUsage(flags.Output())
	}
	registerCLIFlags(flags, &options)

	if err := flags.Parse(args); err != nil {
		return err
	}
	return applyCLIOptions(app.Config, options, visitedFlagNames(flags))
}

func newDefaultCLIOptions() cliOptions {
	return cliOptions{
		listen:                 defaultListen,
		caCert:                 defaultCACertPath,
		caKey:                  defaultCAKeyPath,
		logLevel:               defaultLogLevelName,
		tlsTemplateFile:        "profiles/tls-templates.jsonl",
		captureSQLiteRetention: 100000,
	}
}

func registerCLIFlags(flags *flag.FlagSet, options *cliOptions) {
	flags.BoolVar(&options.captureTLS, "capture-tls", false, "записывать ClientHello в памяти и общей SQLite-базе")
	flags.StringVar(&options.captureTCPInterface, "capture-tcp-interface", "", "пассивно фиксировать TCP SYN/JA4T, DNS и QUIC v1/v2 через сетевой интерфейс")
	flags.BoolVar(&options.listCaptureInterfaces, "list-capture-interfaces", false, "вывести сетевые интерфейсы packet capture и завершить работу")
	flags.BoolVar(&options.captureRaw, "capture-raw", false, "сохранять чувствительные raw-данные TLS; требуется --capture-tls")
	flags.StringVar(&options.tlsKeyLogFile, "tls-keylog-file", "", "NSS key-log файл для расшифрования TLS 1.3 EncryptedExtensions")
	flags.StringVar(&options.captureJSONL, "capture-jsonl", "", "создать новый JSONL-файл наблюдений; требуется --capture-tls")
	flags.StringVar(&options.captureSQLite, "capture-sqlite", "", "сохранять наблюдения в общей SQLite-базе; требуется --capture-tls")
	flags.IntVar(&options.captureSQLiteRetention, "capture-sqlite-retention", 100000, "максимальное число наблюдений в SQLite (1..1000000)")
	flags.StringVar(&options.stateSQLite, "state-sqlite", "", "единая SQLite-база для профилей, устройств, маршрутов и хранилищ проекта")
	flags.StringVar(&options.captureSpool, "capture-spool", "", "зашифрованный bounded spool каталога recorder при сбое SQLite")
	flags.StringVar(&options.captureSpoolKey, "capture-spool-key", "", "файл 32-байтного ключа зашифрованного recorder spool")
	flags.Int64Var(&options.captureSpoolMaxBytes, "capture-spool-max-bytes", 512<<20, "максимальный размер recorder spool (1..4294967296)")
	flags.StringVar(&options.auditLog, "audit-log", "", "однократный импорт прежнего JSONL-аудита в общую SQLite-базу")
	flags.StringVar(&options.auditSQLite, "audit-sqlite", "", "путь общей SQLite-базы аудита (должен совпадать с --state-sqlite)")
	flags.StringVar(&options.deviceMapFile, "device-map-file", "", "однократный импорт прежнего JSON-реестра устройств")
	flags.StringVar(&options.tlsMode, "tls-mode", "MITM_REISSUE", "режим туннеля: MITM_REISSUE, PASSTHROUGH, OBSERVE_ONLY, BLOCK")
	flags.StringVar(&options.tlsTemplateFile, "tls-template-file", "profiles/tls-templates.jsonl", "однократный импорт прежнего JSONL-журнала TLS-профилей")
	flags.StringVar(&options.listen, "listen", defaultListen, "адрес прослушивания, например :8080 или 127.0.0.1:8080")

	flags.StringVar(&options.caCert, "ca-cert", defaultCACertPath, "путь к сертификату CA прокси")
	flags.StringVar(&options.caKey, "ca-key", defaultCAKeyPath, "путь к закрытому ключу CA прокси")

	flags.StringVar(&options.tlsFingerprint, "tls-fingerprint", "", "глобальный fingerprint uTLS, например chrome@120")
	flags.StringVar(&options.tlsFingerprintFile, "tls-fingerprint-file", "", "JSON-файл глобального fingerprint с автообновлением")
	flags.StringVar(&options.tlsProfileFile, "tls-profile-file", "", "однократный импорт прежних upstream TLS-профилей из JSON")
	flags.StringVar(&options.routeConfigFile, "route-config-file", "", "однократный импорт прежних маршрутов из JSON")
	flags.BoolVar(&options.listTLSFingerprints, "list-tls-fingerprints", false, "вывести поддерживаемые fingerprints uTLS и завершить работу")

	flags.StringVar(&options.proxyUsername, "proxy-username", "", "имя пользователя для входящих HTTP- и SOCKS5-клиентов")
	flags.StringVar(&options.proxyPassword, "proxy-password", "", "пароль для входящих HTTP- и SOCKS5-клиентов")
	flags.StringVar(&options.proxyUsernameFile, "proxy-username-file", "", "файл имени пользователя для входящих клиентов (вместо --proxy-username)")
	flags.StringVar(&options.proxyPasswordFile, "proxy-password-file", "", "файл пароля для входящих клиентов (вместо --proxy-password)")
	flags.StringVar(&options.upstreamProxy, "upstream-proxy", "", "URL следующего SOCKS5- или HTTP-прокси")

	flags.StringVar(&options.logLevel, "log-level", defaultLogLevelName, "уровень журнала: debug, info, warn, error")
	flags.BoolVar(&options.dumpTraffic, "dump-traffic", false, "записывать содержимое трафика; чувствительные данные; включает debug")
	flags.BoolVar(&options.tui, "tui", false, "показывать терминальную панель трафика")
	flags.StringVar(&options.webPanel, "web-panel", "", "запустить веб-панель, например 127.0.0.1:9090")
	flags.StringVar(&options.webPanelTokenFile, "web-panel-token-file", "", "файл bearer-токена для API веб-панели")
	flags.StringVar(&options.webPanelCert, "web-panel-cert", "", "сертификат HTTPS веб-панели; обязателен для non-loopback")
	flags.StringVar(&options.webPanelKey, "web-panel-key", "", "закрытый ключ HTTPS веб-панели; обязателен для non-loopback")
}

func writeCLIUsage(output io.Writer) {
	fmt.Fprint(output, `Использование:
  ja3proxy [параметры]

Сервер:
  --listen string                 адрес прослушивания, например :8080 или 127.0.0.1:8080 (по умолчанию ":8080")

Центр сертификации:
  --ca-cert string                путь к сертификату CA прокси (по умолчанию "credentials/cert.pem")
  --ca-key string                 путь к закрытому ключу CA прокси (по умолчанию "credentials/key.pem")

TLS fingerprint:
  --tls-fingerprint string        глобальный fingerprint uTLS, например chrome@120
  --tls-fingerprint-file string   JSON-файл глобального fingerprint с автообновлением
  --tls-profile-file string       однократный импорт прежних upstream TLS-профилей из JSON
  --route-config-file string      однократный импорт прежних маршрутов из JSON
  --list-tls-fingerprints         вывести поддерживаемые fingerprints uTLS и завершить работу

Прокси:
  --proxy-username string         имя пользователя для входящих HTTP- и SOCKS5-клиентов
  --proxy-password string         пароль для входящих HTTP- и SOCKS5-клиентов
  --proxy-username-file string    файл имени пользователя вместо --proxy-username
  --proxy-password-file string    файл пароля вместо --proxy-password
  --upstream-proxy string         URL следующего SOCKS5- или HTTP-прокси

Recorder и диагностика:
  --capture-tls                   включить запись ClientHello в памяти и общей SQLite-базе
  --capture-tcp-interface string   включить пассивный TCP SYN/JA4T, DNS и QUIC v1/v2 capture на интерфейсе
  --list-capture-interfaces        показать доступные packet-capture интерфейсы
  --capture-raw                   сохранять чувствительные raw-данные TLS
  --tls-keylog-file string        NSS key-log файл для TLS 1.3 EncryptedExtensions
  --capture-jsonl string          создать новый JSONL-файл, лимит 256 МиБ
  --capture-sqlite string         переопределить путь общей SQLite-базы наблюдений
  --state-sqlite string           единая SQLite-база состояния (по умолчанию "state/ja3proxy.db")
  --capture-sqlite-retention int  максимальное число наблюдений в SQLite (1..1000000)
  --capture-spool string           зашифрованный bounded spool при сбое SQLite
  --capture-spool-key string       файл 32-байтного ключа recorder spool
  --capture-spool-max-bytes int    максимальный размер recorder spool
  --audit-log string              однократный импорт прежнего JSONL-аудита
  --audit-sqlite string           SQLite-файл общей базы; путь должен совпадать с --state-sqlite
  --device-map-file string        однократный импорт прежнего JSON-реестра username/IP
  --tls-mode string               MITM_REISSUE, PASSTHROUGH, OBSERVE_ONLY, BLOCK
  --tls-template-file string      однократный импорт прежнего JSONL-журнала TLS-профилей
  --log-level string              debug, info, warn или error (по умолчанию "info")
  --dump-traffic                  записывать содержимое трафика; включает debug
  --tui                           показывать терминальную панель трафика
  --web-panel string              запустить веб-панель, например 127.0.0.1:9090
  --web-panel-token-file string   файл bearer-токена для API веб-панели
  --web-panel-cert string         сертификат HTTPS веб-панели; обязателен для non-loopback
  --web-panel-key string          закрытый ключ HTTPS веб-панели; обязателен для non-loopback
`)
}

func visitedFlagNames(flags *flag.FlagSet) map[string]bool {
	visited := make(map[string]bool)
	flags.Visit(func(flag *flag.Flag) {
		visited[flag.Name] = true
	})
	return visited
}

func applyCLIOptions(config *RunningConfig, options cliOptions, specified map[string]bool) error {
	config.ListFingerprints = options.listTLSFingerprints
	config.ListCaptureInterfaces = options.listCaptureInterfaces
	config.CaptureTCPInterface = strings.TrimSpace(options.captureTCPInterface)
	if config.ListFingerprints {
		return nil
	}
	if options.captureRaw && !options.captureTLS {
		return fmt.Errorf("--capture-raw требует --capture-tls")
	}
	if strings.TrimSpace(options.tlsKeyLogFile) != "" && !options.captureTLS {
		return fmt.Errorf("--tls-keylog-file требует --capture-tls")
	}
	if !options.captureTLS && config.CaptureTCPInterface == "" && (options.captureJSONL != "" || options.captureSQLite != "") {
		return fmt.Errorf("--capture-jsonl и --capture-sqlite требуют --capture-tls или --capture-tcp-interface")
	}
	if options.captureSQLiteRetention < 1 || options.captureSQLiteRetention > 1000000 {
		return fmt.Errorf("--capture-sqlite-retention должно быть от 1 до 1000000")
	}
	stateSQLite := strings.TrimSpace(options.stateSQLite)
	if stateSQLite == "" {
		switch {
		case strings.TrimSpace(options.captureSQLite) != "":
			stateSQLite = strings.TrimSpace(options.captureSQLite)
		case strings.TrimSpace(options.auditSQLite) != "":
			stateSQLite = strings.TrimSpace(options.auditSQLite)
		default:
			stateSQLite = filepath.Join("state", "ja3proxy.db")
		}
	}
	captureSQLite := strings.TrimSpace(options.captureSQLite)
	if (options.captureTLS || config.CaptureTCPInterface != "") && captureSQLite == "" {
		captureSQLite = stateSQLite
	}
	if options.captureSpool != "" || options.captureSpoolKey != "" {
		if (!options.captureTLS && config.CaptureTCPInterface == "") || captureSQLite == "" {
			return fmt.Errorf("--capture-spool требует включённый recorder")
		}
		if options.captureSpool == "" || options.captureSpoolKey == "" {
			return fmt.Errorf("--capture-spool и --capture-spool-key должны использоваться вместе")
		}
		if options.captureSpoolMaxBytes < 1 || options.captureSpoolMaxBytes > 4<<30 {
			return fmt.Errorf("--capture-spool-max-bytes должно быть от 1 до 4294967296")
		}
	}
	for _, alias := range []struct{ flagName, path string }{{"--capture-sqlite", options.captureSQLite}, {"--audit-sqlite", options.auditSQLite}} {
		if strings.TrimSpace(alias.path) != "" && !sameSQLitePath(stateSQLite, alias.path) {
			return fmt.Errorf("%s должен указывать на общую базу --state-sqlite (%s)", alias.flagName, stateSQLite)
		}
	}
	mode := strings.ToUpper(options.tlsMode)
	if mode == "" {
		mode = "MITM_REISSUE"
	}
	switch mode {
	case "MITM_REISSUE", "PASSTHROUGH", "OBSERVE_ONLY", "BLOCK":
	default:
		return fmt.Errorf("недопустимое значение --tls-mode")
	}
	config.CaptureTLS = options.captureTLS
	config.CaptureRaw = options.captureRaw
	config.TLSKeyLogFile = strings.TrimSpace(options.tlsKeyLogFile)
	config.CaptureJSONL = options.captureJSONL
	config.CaptureSQLite = captureSQLite
	config.CaptureSQLiteRetention = options.captureSQLiteRetention
	config.StateSQLite = stateSQLite
	config.CaptureSpool = options.captureSpool
	config.CaptureSpoolKey = options.captureSpoolKey
	config.CaptureSpoolMaxBytes = options.captureSpoolMaxBytes
	config.AuditLog = options.auditLog
	config.AuditSQLite = options.auditSQLite
	config.DeviceMapFile = options.deviceMapFile
	config.TLSMode = mode
	config.TLSTemplateFile = options.tlsTemplateFile

	listen, addr, port, err := resolveListenOption(options)
	if err != nil {
		return err
	}
	config.Listen = listen
	config.Addr = addr
	config.Port = port

	config.Cert = options.caCert
	config.Key = options.caKey
	config.TLSFingerprintExplicit = specified["tls-fingerprint"]
	config.FingerprintConfig = options.tlsFingerprintFile
	config.UpstreamTLSConfig = options.tlsProfileFile
	config.RouteConfigFile = options.routeConfigFile
	config.Upstream = options.upstreamProxy
	if err := validateProxyCredentialSources(options.proxyUsername, options.proxyPassword, options.proxyUsernameFile, options.proxyPasswordFile); err != nil {
		return err
	}
	config.ProxyUsername = options.proxyUsername
	config.ProxyPassword = options.proxyPassword
	config.ProxyUsernameFile = strings.TrimSpace(options.proxyUsernameFile)
	config.ProxyPasswordFile = strings.TrimSpace(options.proxyPasswordFile)
	config.TUI = options.tui
	config.WebPanel = options.webPanel
	config.WebPanelTokenFile = options.webPanelTokenFile
	config.WebPanelCert = options.webPanelCert
	config.WebPanelKey = options.webPanelKey
	if (config.WebPanelCert == "") != (config.WebPanelKey == "") {
		return fmt.Errorf("--web-panel-cert и --web-panel-key должны использоваться вместе")
	}

	if err := applyTLSFingerprintOptions(config, options, specified); err != nil {
		return err
	}
	if err := applyDiagnosticOptions(config, options, specified); err != nil {
		return err
	}
	return nil
}

func validateProxyCredentialSources(username, password, usernameFile, passwordFile string) error {
	usernameFile = strings.TrimSpace(usernameFile)
	passwordFile = strings.TrimSpace(passwordFile)
	hasLiteral := username != "" || password != ""
	hasFiles := usernameFile != "" || passwordFile != ""
	if hasLiteral && hasFiles {
		return fmt.Errorf("use either literal proxy credentials or credential files, not both for the same field")
	}
	if (username != "" || usernameFile != "") != (password != "" || passwordFile != "") {
		return fmt.Errorf("proxy username and password must both be configured")
	}
	if usernameFile == "" && passwordFile == "" {
		return validateProxyCredentials(username, password)
	}
	return nil
}

func sameSQLitePath(left, right string) bool {
	left = filepath.Clean(strings.TrimSpace(left))
	right = filepath.Clean(strings.TrimSpace(right))
	return strings.EqualFold(left, right)
}

func validateProxyCredentials(username, password string) error {
	if (username == "") != (password == "") {
		return fmt.Errorf("--proxy-username and --proxy-password must be used together")
	}
	if len(username) > 255 {
		return fmt.Errorf("--proxy-username must be at most 255 bytes for SOCKS5 authentication")
	}
	if strings.Contains(username, ":") {
		return fmt.Errorf("--proxy-username cannot contain ':' because HTTP Basic authentication uses it as a separator")
	}
	if len(password) > 255 {
		return fmt.Errorf("--proxy-password must be at most 255 bytes for SOCKS5 authentication")
	}
	return nil
}

func resolveListenOption(options cliOptions) (listen string, addr string, port string, err error) {
	return normalizeListenAddress(options.listen)
}

func normalizeListenAddress(address string) (listen string, addr string, port string, err error) {
	address = strings.TrimSpace(address)
	if address == "" {
		return "", "", "", fmt.Errorf("listen address is required")
	}
	if !strings.Contains(address, ":") {
		if _, parseErr := strconv.Atoi(address); parseErr != nil {
			return "", "", "", fmt.Errorf("listen address must include a port")
		}
		address = ":" + address
	}

	host, listenPort, err := net.SplitHostPort(address)
	if err != nil {
		return "", "", "", err
	}
	if listenPort == "" {
		return "", "", "", fmt.Errorf("listen port is required")
	}
	portNumber, err := strconv.Atoi(listenPort)
	if err != nil || portNumber < 1 || portNumber > 65535 {
		return "", "", "", fmt.Errorf("listen port must be a number from 1 to 65535")
	}
	return net.JoinHostPort(host, listenPort), host, listenPort, nil
}

func applyTLSFingerprintOptions(config *RunningConfig, options cliOptions, specified map[string]bool) error {
	fingerprintSpec := ""
	hasFingerprintSpec := false
	if specified["tls-fingerprint"] {
		fingerprintSpec = options.tlsFingerprint
		hasFingerprintSpec = true
	}

	if config.FingerprintConfig != "" && hasFingerprintSpec {
		return fmt.Errorf("use either --tls-fingerprint-file or global TLS fingerprint flags, not both")
	}

	config.TLSClient = defaultTLSClient
	config.TLSVersion = defaultTLSVersion
	if !hasFingerprintSpec {
		return nil
	}

	fp, err := fingerprint.ParseSpec(fingerprintSpec)
	if err != nil {
		return err
	}
	config.TLSClient = fp.Client
	config.TLSVersion = fp.Version
	return nil
}

func applyDiagnosticOptions(config *RunningConfig, options cliOptions, specified map[string]bool) error {
	config.DumpTraffic = options.dumpTraffic

	logLevel := options.logLevel
	if !specified["log-level"] && config.DumpTraffic {
		logLevel = "debug"
	}
	normalized, err := normalizeLogLevelName(logLevel)
	if err != nil {
		return err
	}
	if config.DumpTraffic {
		normalized = "debug"
	}
	config.LogLevel = normalized
	return nil
}

func normalizeLogLevelName(logLevel string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(logLevel)) {
	case "", "info":
		return "info", nil
	case "debug":
		return "debug", nil
	case "warn", "warning":
		return "warn", nil
	case "error":
		return "error", nil
	default:
		return "", fmt.Errorf("unsupported log level %q", logLevel)
	}
}

func logLevelFromName(logLevel string) slog.Level {
	switch strings.ToLower(strings.TrimSpace(logLevel)) {
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

func (config *RunningConfig) listenAddress() string {
	if config == nil {
		return defaultListen
	}
	if config.Listen != "" {
		return config.Listen
	}
	if config.Port == "" {
		return defaultListen
	}
	return net.JoinHostPort(config.Addr, config.Port)
}

func (config *RunningConfig) dumpTrafficEnabled() bool {
	return config != nil && config.DumpTraffic
}
