package ja3proxy

type RunningConfig struct {
	CaptureTLS        bool
	CaptureRaw        bool
	CaptureJSONL      string
	TLSMode           string
	TLSTemplateFile   string
	DumpTraffic       bool
	LogLevel          string
	Listen            string
	Addr              string
	Port              string
	TLSVersion        string
	TLSClient         string
	ListFingerprints  bool
	FingerprintConfig string
	UpstreamTLSConfig string
	Cert              string
	Key               string
	Upstream          string
	ProxyUsername     string
	ProxyPassword     string
	TUI               bool
	WebPanel          string
	ProxyProtocol     string
}
