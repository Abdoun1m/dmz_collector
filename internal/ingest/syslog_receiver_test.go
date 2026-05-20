package ingest

import (
	"strings"
	"testing"
)

func TestNormalizeSyslogJumphostAcceptedPublickey(t *testing.T) {
	line := `<38>1 2026-05-20T15:30:00Z kali labshock_jumphost 123 - - Accepted publickey for jumpadmin from 192.168.20.5 port 53210 ssh2: RSA-CERT ID jumpadmin-cert`
	ev := normalizeSyslogLine(line, "192.168.10.5:514")
	if ev.SourceType != "jumphost" || ev.Source != "jumphost_syslog" {
		t.Fatalf("expected jumphost syslog event, got %#v", ev)
	}
	if ev.Message != "jump_cert_login_success" || ev.EventCategory != "access_control" || ev.Severity != "info" {
		t.Fatalf("unexpected classification: %s %s %s", ev.Message, ev.EventCategory, ev.Severity)
	}
	if ev.Tags["high_value"] != true {
		t.Fatalf("expected high_value tag, got %#v", ev.Tags)
	}
	if ev.Tags["user"] != "jumpadmin" || ev.Tags["src_ip"] != "192.168.20.5" || ev.Tags["src_port"] != "53210" {
		t.Fatalf("expected login metadata, got %#v", ev.Tags)
	}
	if !strings.Contains(ev.Raw, `"syslog_appname":"labshock_jumphost"`) || !strings.Contains(ev.Raw, `"docker_tag":"labshock_jumphost"`) {
		t.Fatalf("expected original syslog fields in raw, got %s", ev.Raw)
	}
}

func TestNormalizeSyslogJumphostInvalidUser(t *testing.T) {
	line := `<38>1 2026-05-20T15:31:00Z kali labshock_jumphost 123 - - Invalid user invaliduser from 10.10.10.50 port 50022`
	ev := normalizeSyslogLine(line, "192.168.10.5:514")
	if ev.Message != "jump_invalid_user" || ev.EventCategory != "access_control" || ev.Severity != "warning" {
		t.Fatalf("unexpected invalid-user classification: %s %s %s", ev.Message, ev.EventCategory, ev.Severity)
	}
	if ev.Tags["user"] != "invaliduser" || ev.Tags["src_ip"] != "10.10.10.50" {
		t.Fatalf("expected invalid-user metadata, got %#v", ev.Tags)
	}
}

func TestNormalizeSyslogJumphostForwardDenied(t *testing.T) {
	line := `<38>1 2026-05-20T15:32:00Z kali labshock_jumphost 123 - - channel 3: open failed: administratively prohibited: open failed`
	ev := normalizeSyslogLine(line, "192.168.10.5:514")
	if ev.Message != "jump_forward_denied" || ev.EventCategory != "security" || ev.Severity != "warning" {
		t.Fatalf("unexpected forwarding classification: %s %s %s", ev.Message, ev.EventCategory, ev.Severity)
	}
	if ev.Tags["high_value"] != true || ev.Protocol != "ssh" {
		t.Fatalf("expected high-value ssh forwarding denial, protocol=%s tags=%#v", ev.Protocol, ev.Tags)
	}
}

func TestNormalizeSyslogJumphostCronNoiseLowValue(t *testing.T) {
	line := `<38>1 2026-05-20T15:33:00Z kali labshock_jumphost 123 - - crond[22]: USER root pid 1234 cmd run-parts /etc/periodic`
	ev := normalizeSyslogLine(line, "192.168.10.5:514")
	if ev.SourceType != "jumphost" || ev.Message != "jump_event_unknown" {
		t.Fatalf("expected unknown jumphost event, got %#v", ev)
	}
	if ev.Tags["low_value"] != true || ev.Tags["collector_decision_hint"] != "sample" {
		t.Fatalf("expected low-value sample tags, got %#v", ev.Tags)
	}
}

func TestNormalizeSyslogJumphostUnknownAccepted(t *testing.T) {
	line := `<38>1 2026-05-20T15:34:00Z kali labshock_jumphost 123 - - custom jump host diagnostic line`
	ev := normalizeSyslogLine(line, "192.168.10.5:514")
	if ev.SourceType != "jumphost" || ev.Message != "jump_event_unknown" {
		t.Fatalf("expected unknown jumphost event, got %#v", ev)
	}
	if ev.Source != "jumphost_syslog" || ev.Tags["parser_version"] != jumphostParserVersion {
		t.Fatalf("unexpected source/tags: source=%s tags=%#v", ev.Source, ev.Tags)
	}
}

func TestNormalizeSyslogNonJumphostStillFirewall(t *testing.T) {
	line := `<38>1 2026-05-20T15:35:00Z opnsense filterlog 123 - - block in on em0`
	ev := normalizeSyslogLine(line, "192.168.10.254:514")
	if ev.SourceType != "firewall" {
		t.Fatalf("expected firewall fallback, got %#v", ev)
	}
}
