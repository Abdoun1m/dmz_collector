package config

import (
	"log/slog"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	ServiceName string
	APIAddr     string

	StorageBackend string
	EventsFile     string
	SpoolFile      string
	DataDir        string

	IngestToken string
	LogLevel    slog.Level

	Splunk SplunkConfig
	Syslog SyslogConfig
	Vault  VaultConfig

	EnableFirewallSyslog bool
	FirewallSyslogAddr   string

	EnableOTPull bool
	OTBaseURL    string
	OTPollEvery  time.Duration
	EnableOTSSE  bool

	QueueBatchSize int
}

type SplunkConfig struct {
	Enabled   bool
	URL       string
	Token     string
	Index     string
	Source    string
	VerifyTLS bool
	Timeout   time.Duration
}

type SyslogConfig struct {
	Enabled  bool
	Host     string
	Port     int
	Protocol string
}

type VaultConfig struct {
	Enabled    bool
	Addr       string
	Token      string
	SecretPath string
}

func Load() Config {
	return Config{
		ServiceName:          getenv("SERVICE_NAME", "dmz_collector"),
		APIAddr:              getenv("API_ADDR", "0.0.0.0:9000"),
		StorageBackend:       strings.ToLower(getenv("STORAGE_BACKEND", "jsonl")),
		EventsFile:           getenv("EVENTS_FILE", "/data/events.jsonl"),
		SpoolFile:            getenv("SPOOL_FILE", "/data/spool/events.jsonl"),
		DataDir:              getenv("DATA_DIR", "/data"),
		IngestToken:          strings.TrimSpace(os.Getenv("DMZ_INGEST_TOKEN")),
		LogLevel:             parseLevel(getenv("LOG_LEVEL", "info")),
		Splunk:               loadSplunk(),
		Syslog:               loadSyslog(),
		Vault:                loadVault(),
		EnableFirewallSyslog: parseBool(getenv("FIREWALL_SYSLOG_ENABLED", "true")),
		FirewallSyslogAddr:   getenv("FIREWALL_SYSLOG_ADDR", "0.0.0.0:5514"),
		EnableOTPull:         parseBool(getenv("OT_PULL_ENABLED", "false")),
		OTBaseURL:            strings.TrimRight(getenv("OT_COLLECTOR_URL", "http://192.168.1.70:8088"), "/"),
		OTPollEvery:          time.Duration(parseInt(getenv("OT_PULL_INTERVAL_SECONDS", "10"), 10)) * time.Second,
		EnableOTSSE:          parseBool(getenv("OT_SSE_ENABLED", "false")),
		QueueBatchSize:       parseInt(getenv("FORWARD_BATCH_SIZE", "50"), 50),
	}
}

func loadSplunk() SplunkConfig {
	return SplunkConfig{
		Enabled:   parseBool(getenv("SPLUNK_HEC_ENABLED", "false")),
		URL:       getenv("SPLUNK_HEC_URL", ""),
		Token:     getenv("SPLUNK_HEC_TOKEN", ""),
		Index:     getenv("SPLUNK_INDEX", "ot_security"),
		Source:    getenv("SPLUNK_SOURCE", "labshock_dmz_collector"),
		VerifyTLS: parseBool(getenv("SPLUNK_VERIFY_TLS", "false")),
		Timeout:   5 * time.Second,
	}
}

func loadSyslog() SyslogConfig {
	return SyslogConfig{
		Enabled:  parseBool(getenv("SYSLOG_FORWARD_ENABLED", "false")),
		Host:     getenv("SYSLOG_FORWARD_HOST", ""),
		Port:     parseInt(getenv("SYSLOG_FORWARD_PORT", "514"), 514),
		Protocol: strings.ToLower(getenv("SYSLOG_FORWARD_PROTOCOL", "udp")),
	}
}

func loadVault() VaultConfig {
	return VaultConfig{
		Enabled:    parseBool(getenv("VAULT_ENABLED", "false")),
		Addr:       getenv("VAULT_ADDR", "http://192.168.10.10:8200"),
		Token:      getenv("VAULT_TOKEN", ""),
		SecretPath: getenv("VAULT_SECRET_PATH", "secret/data/dmz_collector/splunk"),
	}
}

func getenv(key, def string) string {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	return v
}

func parseBool(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

func parseInt(v string, def int) int {
	n, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil || n <= 0 {
		return def
	}
	return n
}

func parseLevel(v string) slog.Level {
	switch strings.ToLower(strings.TrimSpace(v)) {
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
