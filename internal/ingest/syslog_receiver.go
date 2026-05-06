package ingest

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"time"

	"github.com/Abdoun1m/dmz_collector/internal/event"
)

type SyslogHandler func(event.Event)

func RunFirewallSyslogUDP(ctx context.Context, addr string, logger *slog.Logger, handler SyslogHandler) error {
	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		return err
	}
	logger.Info("firewall syslog listener started", "addr", addr)
	go func() {
		<-ctx.Done()
		_ = pc.Close()
	}()
	buf := make([]byte, 65535)
	for {
		n, remote, err := pc.ReadFrom(buf)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			logger.Warn("firewall syslog read failed", "error", err)
			continue
		}
		line := strings.TrimSpace(string(buf[:n]))
		handler(normalizeFirewall(line, remote.String()))
	}
}

func normalizeFirewall(raw, remote string) event.Event {
	ip := remote
	if host, _, err := net.SplitHostPort(remote); err == nil {
		ip = host
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	evt := event.Event{
		ID:            "",
		Timestamp:     now,
		ReceivedAt:    now,
		Zone:          "DMZ",
		SourceType:    "firewall",
		AssetName:     "firewall",
		AssetIP:       fallbackFirewallIP(ip),
		Severity:      "warning",
		Protocol:      "syslog",
		EventCategory: "security",
		Message:       raw,
		Raw:           fmt.Sprintf("%s", raw),
		Tags: map[string]any{
			"ingest": "firewall_syslog",
		},
	}
	evt.EnsureDefaults()
	evt.OriginalRaw = []byte(raw)
	return evt
}

func fallbackFirewallIP(ip string) string {
	if strings.TrimSpace(ip) == "" || ip == "::1" || ip == "127.0.0.1" {
		return "192.168.10.254"
	}
	return ip
}

