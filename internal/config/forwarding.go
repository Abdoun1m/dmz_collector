package config

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
)

type ForwardingConfig struct {
	SplunkEnabled         bool   `json:"splunk_enabled"`
	SplunkHECURL          string `json:"splunk_hec_url"`
	SplunkHECToken        string `json:"splunk_hec_token"`
	SplunkIndex           string `json:"splunk_index"`
	SplunkSource          string `json:"splunk_source"`
	SplunkVerifyTLS       bool   `json:"splunk_verify_tls"`
	SyslogForwardEnabled  bool   `json:"syslog_forward_enabled"`
	SyslogForwardHost     string `json:"syslog_forward_host"`
	SyslogForwardPort     int    `json:"syslog_forward_port"`
	SyslogForwardProtocol string `json:"syslog_forward_protocol"`
	Paused                bool   `json:"paused"`
}

type ForwardingStatus struct {
	Queued       int64  `json:"queued"`
	Forwarded    int64  `json:"forwarded"`
	Failed       int64  `json:"failed"`
	LastSuccess  string `json:"last_success"`
	LastFailure  string `json:"last_failure"`
	LastResponse string `json:"last_response"`
}

type ForwardingStore struct {
	mu   sync.RWMutex
	path string
	cfg  ForwardingConfig
}

func NewForwardingStore(path string, fromEnv Config) (*ForwardingStore, error) {
	s := &ForwardingStore{
		path: path,
		cfg: ForwardingConfig{
			SplunkEnabled:         fromEnv.Splunk.Enabled,
			SplunkHECURL:          fromEnv.Splunk.URL,
			SplunkHECToken:        fromEnv.Splunk.Token,
			SplunkIndex:           fromEnv.Splunk.Index,
			SplunkSource:          fromEnv.Splunk.Source,
			SplunkVerifyTLS:       fromEnv.Splunk.VerifyTLS,
			SyslogForwardEnabled:  fromEnv.Syslog.Enabled,
			SyslogForwardHost:     fromEnv.Syslog.Host,
			SyslogForwardPort:     fromEnv.Syslog.Port,
			SyslogForwardProtocol: fromEnv.Syslog.Protocol,
			Paused:                false,
		},
	}
	if err := s.loadOrInit(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *ForwardingStore) Get() ForwardingConfig {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.cfg
}

func (s *ForwardingStore) Replace(cfg ForwardingConfig) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if cfg.SplunkIndex == "" {
		cfg.SplunkIndex = "ot_security"
	}
	if cfg.SplunkSource == "" {
		cfg.SplunkSource = "labshock_dmz_collector"
	}
	if cfg.SyslogForwardPort == 0 {
		cfg.SyslogForwardPort = 514
	}
	if cfg.SyslogForwardProtocol == "" {
		cfg.SyslogForwardProtocol = "udp"
	}
	s.cfg = cfg
	return s.persistLocked()
}

func (s *ForwardingStore) UpdatePaused(v bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cfg.Paused = v
	return s.persistLocked()
}

func (s *ForwardingStore) loadOrInit() error {
	if err := os.MkdirAll(filepath.Dir(s.path), 0o755); err != nil {
		return err
	}
	b, err := os.ReadFile(s.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return s.persistLocked()
		}
		return err
	}
	if len(b) == 0 {
		return s.persistLocked()
	}
	var cfg ForwardingConfig
	if err := json.Unmarshal(b, &cfg); err != nil {
		return err
	}
	s.cfg = cfg
	return s.persistLocked()
}

func (s *ForwardingStore) persistLocked() error {
	b, err := json.MarshalIndent(s.cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.path, b, 0o644)
}

