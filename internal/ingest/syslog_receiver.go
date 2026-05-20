package ingest

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"regexp"
	"strconv"
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
		handler(normalizeSyslogLine(line, remote.String()))
	}
}

func normalizeSyslogLine(raw, remote string) event.Event {
	parsed := parseSyslogLine(raw)
	parsed.Remote = remote
	if isJumphostSyslog(parsed) {
		return NormalizeJumphostSyslog(parsed)
	}
	return normalizeFirewall(raw, remote)
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

type syslogRecord struct {
	Raw       string
	Message   string
	Hostname  string
	AppName   string
	ProcID    string
	Facility  string
	Severity  string
	DockerTag string
	Remote    string
}

var (
	syslogPRIRe     = regexp.MustCompile(`^<(\d{1,3})>`)
	syslogRFC5424Re = regexp.MustCompile(`^<(\d{1,3})>1\s+\S+\s+(\S+)\s+(\S+)\s+(\S+)\s+\S+\s+(?:-|\[[^\]]*\])\s*(.*)$`)
	syslogRFC3164Re = regexp.MustCompile(`^<(\d{1,3})>[A-Z][a-z]{2}\s+\d{1,2}\s+\d\d:\d\d:\d\d\s+(\S+)\s+([^:\s]+)(?:\[(\d+)\])?:\s*(.*)$`)
)

func parseSyslogLine(raw string) syslogRecord {
	rec := syslogRecord{Raw: raw, Message: raw}
	if m := syslogRFC5424Re.FindStringSubmatch(raw); len(m) == 6 {
		rec.Hostname = cleanSyslogNil(m[2])
		rec.AppName = cleanSyslogNil(m[3])
		rec.ProcID = cleanSyslogNil(m[4])
		rec.Message = strings.TrimSpace(m[5])
		rec.DockerTag = rec.AppName
		setSyslogPriority(&rec, m[1])
		return rec
	}
	if m := syslogRFC3164Re.FindStringSubmatch(raw); len(m) == 6 {
		rec.Hostname = cleanSyslogNil(m[2])
		rec.AppName = cleanSyslogNil(m[3])
		rec.ProcID = cleanSyslogNil(m[4])
		rec.Message = strings.TrimSpace(m[5])
		rec.DockerTag = rec.AppName
		setSyslogPriority(&rec, m[1])
		return rec
	}
	if m := syslogPRIRe.FindStringSubmatch(raw); len(m) == 2 {
		setSyslogPriority(&rec, m[1])
		rec.Message = strings.TrimSpace(syslogPRIRe.ReplaceAllString(raw, ""))
	}
	return rec
}

func setSyslogPriority(rec *syslogRecord, priText string) {
	pri, err := strconv.Atoi(priText)
	if err != nil {
		return
	}
	rec.Facility = strconv.Itoa(pri / 8)
	rec.Severity = strconv.Itoa(pri % 8)
}

func cleanSyslogNil(v string) string {
	v = strings.TrimSpace(v)
	if v == "-" {
		return ""
	}
	return v
}

func isJumphostSyslog(rec syslogRecord) bool {
	identity := strings.ToLower(strings.Join([]string{rec.Hostname, rec.AppName, rec.ProcID, rec.DockerTag}, " "))
	if strings.Contains(identity, "labshock_jumphost") {
		return true
	}
	blob := strings.ToLower(strings.Join([]string{identity, rec.Message}, " "))
	for _, needle := range []string{
		"sshd", "sshd.pam", "sshd-session.pam", "jumpadmin", "invaliduser",
		"accepted publickey", "failed publickey", "failed password", "invalid user",
		"permission denied", "administratively prohibited", "open failed",
	} {
		if strings.Contains(blob, strings.ToLower(needle)) {
			return true
		}
	}
	return false
}

func fallbackFirewallIP(ip string) string {
	if strings.TrimSpace(ip) == "" || ip == "::1" || ip == "127.0.0.1" {
		return "192.168.10.254"
	}
	return ip
}
