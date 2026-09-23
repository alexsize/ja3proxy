package ja3proxy

import (
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
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
	captureRaw             bool
	captureJSONL           string
	captureSQLite          string
	captureSQLiteRetention int
	tlsMode                string
	tlsTemplateFile        string
	listen                 string
	caCert                 string
	caKey                  string
	tlsFingerprint         string
	tlsFingerprintFile     string
	tlsProfileFile         string
	upstreamProxy          string
	proxyUsername          string
	proxyPassword          string
	logLevel               string
	dumpTraffic            bool
	tui                    bool
	webPanel               string
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
	flags.BoolVar(&options.captureTLS, "capture-tls", false, "записывать входящий и исходящий ClientHello в ограниченной памяти")
	flags.BoolVar(&options.captureRaw, "capture-raw", false, "сохранять чувствительные raw-данные TLS; требуется --capture-tls")
	flags.StringVar(&options.captureJSONL, "capture-jsonl", "", "создать новый JSONL-файл наблюдений; требуется --capture-tls")
	flags.StringVar(&options.captureSQLite, "capture-sqlite", "", "сохранять наблюдения в SQLite; требуется --capture-tls")
	flags.IntVar(&options.captureSQLiteRetention, "capture-sqlite-retention", 100000, "максимальное число наблюдений в SQLite (1..1000000)")
	flags.StringVar(&options.tlsMode, "tls-mode", "MITM_REISSUE", "режим туннеля: MITM_REISSUE, PASSTHROUGH, OBSERVE_ONLY, BLOCK")
	flags.StringVar(&options.tlsTemplateFile, "tls-template-file", "profiles/tls-templates.jsonl", "журнал версий редактируемых TLS-профилей")
	flags.StringVar(&options.listen, "listen", defaultListen, "адрес прослушивания, например :8080 или 127.0.0.1:8080")

	flags.StringVar(&options.caCert, "ca-cert", defaultCACertPath, "путь к сертификату CA прокси")
	flags.StringVar(&options.caKey, "ca-key", defaultCAKeyPath, "путь к закрытому ключу CA прокси")

	flags.StringVar(&options.tlsFingerprint, "tls-fingerprint", "", "глобальный fingerprint uTLS, например chrome@120")
	flags.StringVar(&options.tlsFingerprintFile, "tls-fingerprint-file", "", "JSON-файл глобального fingerprint с автообновлением")
	flags.StringVar(&options.tlsProfileFile, "tls-profile-file", "", "JSON-файл исходящих TLS-профилей по хостам")
	flags.BoolVar(&options.listTLSFingerprints, "list-tls-fingerprints", false, "вывести поддерживаемые fingerprints uTLS и завершить работу")

	flags.StringVar(&options.proxyUsername, "proxy-username", "", "имя пользователя для входящих HTTP- и SOCKS5-клиентов")
	flags.StringVar(&options.proxyPassword, "proxy-password", "", "пароль для входящих HTTP- и SOCKS5-клиентов")
	flags.StringVar(&options.upstreamProxy, "upstream-proxy", "", "URL следующего SOCKS5- или HTTP-прокси")

	flags.StringVar(&options.logLevel, "log-level", defaultLogLevelName, "уровень журнала: debug, info, warn, error")
	flags.BoolVar(&options.dumpTraffic, "dump-traffic", false, "записывать содержимое трафика; чувствительные данные; включает debug")
	flags.BoolVar(&options.tui, "tui", false, "показывать терминальную панель трафика")
	flags.StringVar(&options.webPanel, "web-panel", "", "запустить веб-панель, например 127.0.0.1:9090")
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
  --tls-profile-file string       JSON-файл исходящих TLS-профилей по хостам
  --list-tls-fingerprints         вывести поддерживаемые fingerprints uTLS и завершить работу

Прокси:
  --proxy-username string         имя пользователя для входящих HTTP- и SOCKS5-клиентов
  --proxy-password string         пароль для входящих HTTP- и SOCKS5-клиентов
  --upstream-proxy string         URL следующего SOCKS5- или HTTP-прокси

Recorder и диагностика:
  --capture-tls                   включить ограниченную запись ClientHello
  --capture-raw                   сохранять чувствительные raw-данные TLS
  --capture-jsonl string          создать новый JSONL-файл, лимит 256 МиБ
  --capture-sqlite string         durable SQLite-хранилище наблюдений; retention по умолчанию 100000
  --capture-sqlite-retention int  максимальное число наблюдений в SQLite (1..1000000)
  --tls-mode string               MITM_REISSUE, PASSTHROUGH, OBSERVE_ONLY, BLOCK
  --tls-template-file string      журнал редактируемых TLS-профилей (по умолчанию "profiles/tls-templates.jsonl")
  --log-level string              debug, info, warn или error (по умолчанию "info")
  --dump-traffic                  записывать содержимое трафика; включает debug
  --tui                           показывать терминальную панель трафика
  --web-panel string              запустить веб-панель, например 127.0.0.1:9090
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
	if config.ListFingerprints {
		return nil
	}
	if !options.captureTLS && (options.captureRaw || options.captureJSONL != "" || options.captureSQLite != "") {
		return fmt.Errorf("--capture-raw, --capture-jsonl и --capture-sqlite требуют --capture-tls")
	}
	if options.captureSQLiteRetention < 1 || options.captureSQLiteRetention > 1000000 {
		return fmt.Errorf("--capture-sqlite-retention должно быть от 1 до 1000000")
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
	config.CaptureJSONL = options.captureJSONL
	config.CaptureSQLite = options.captureSQLite
	config.CaptureSQLiteRetention = options.captureSQLiteRetention
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
	config.FingerprintConfig = options.tlsFingerprintFile
	config.UpstreamTLSConfig = options.tlsProfileFile
	config.Upstream = options.upstreamProxy
	if err := validateProxyCredentials(options.proxyUsername, options.proxyPassword); err != nil {
		return err
	}
	config.ProxyUsername = options.proxyUsername
	config.ProxyPassword = options.proxyPassword
	config.TUI = options.tui
	config.WebPanel = options.webPanel

	if err := applyTLSFingerprintOptions(config, options, specified); err != nil {
		return err
	}
	if err := applyDiagnosticOptions(config, options, specified); err != nil {
		return err
	}
	return nil
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
