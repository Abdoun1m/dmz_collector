package ingest

import (
	"strings"
	"testing"
)

func TestNormalizeJumphostLoginFailed(t *testing.T) {
	ev, err := NormalizeJumphostEvent([]byte(`{
		"message":"jump_login_failed",
		"event_category":"access_control",
		"severity":"warning",
		"raw":{"user":"test","src_ip":"192.168.10.5"}
	}`))
	if err != nil {
		t.Fatalf("NormalizeJumphostEvent returned error: %v", err)
	}
	if ev.SourceType != "jumphost" || ev.AssetName != "labshock_jumphost" || ev.AssetIP != "192.168.10.5" {
		t.Fatalf("unexpected identity: %#v", ev)
	}
	if ev.Message != "jump_login_failed" || ev.EventCategory != "access_control" || ev.Severity != "warning" {
		t.Fatalf("unexpected classification: %s %s %s", ev.Message, ev.EventCategory, ev.Severity)
	}
	if ev.Protocol != "ssh" {
		t.Fatalf("expected ssh protocol, got %q", ev.Protocol)
	}
	if ev.Tags["parser_version"] != jumphostParserVersion || ev.Tags["splunk_sourcetype"] != jumphostSourcetype {
		t.Fatalf("unexpected tags: %#v", ev.Tags)
	}
	if ev.Tags["alert_candidate"] != true {
		t.Fatalf("expected alert candidate tag, got %#v", ev.Tags)
	}
}

func TestNormalizeJumphostManyAcceptsArrayAndText(t *testing.T) {
	events, err := NormalizeJumphostEventsMany([]byte(`[
		{"message":"jump_login_success","raw":{"user":"alice"}},
		{"message":"jump_heartbeat","raw":{"status":"ok"}}
	]`))
	if err != nil {
		t.Fatalf("NormalizeJumphostEventsMany returned error: %v", err)
	}
	if len(events) != 2 || events[0].Message != "jump_login_success" || events[1].Message != "jump_heartbeat" {
		t.Fatalf("unexpected array events: %#v", events)
	}

	events, err = NormalizeJumphostEventsMany([]byte("completely unfamiliar jump host log line\n"))
	if err != nil {
		t.Fatalf("NormalizeJumphostEventsMany text returned error: %v", err)
	}
	if len(events) != 1 || events[0].Message != "jump_event_unknown" || events[0].EventCategory != "system" {
		t.Fatalf("unexpected text fallback event: %#v", events)
	}
	if !strings.Contains(events[0].Raw, "completely unfamiliar jump host log line") {
		t.Fatalf("expected raw text to be preserved, got %s", events[0].Raw)
	}
}

func TestNormalizeJumphostSudoMetadata(t *testing.T) {
	ev, err := NormalizeJumphostEvent([]byte(`{
		"message":"jump_sudo_executed",
		"raw":{"user":"engineer","sudo_command":"/usr/bin/systemctl restart nginx","target_zone":"DMZ"}
	}`))
	if err != nil {
		t.Fatalf("NormalizeJumphostEvent returned error: %v", err)
	}
	if ev.Message != "jump_sudo_executed" || ev.EventCategory != "security" || ev.Severity != "warning" {
		t.Fatalf("unexpected sudo classification: %s %s %s", ev.Message, ev.EventCategory, ev.Severity)
	}
	if ev.Protocol != "syslog" {
		t.Fatalf("expected sudo protocol to remain syslog, got %q", ev.Protocol)
	}
	if ev.Tags["sudo_command"] != "/usr/bin/systemctl restart nginx" || ev.ExtraFields["target_zone"] != "DMZ" {
		t.Fatalf("expected sudo metadata to be promoted, tags=%#v extra=%#v", ev.Tags, ev.ExtraFields)
	}
}

func TestNormalizeJumphostRedaction(t *testing.T) {
	ev, err := NormalizeJumphostEvent([]byte(`{
		"message":"jump_login_success",
		"raw":{
			"user":"engineer",
			"password":"secret",
			"nested":{"authorization":"Bearer secret","private_key":"-----BEGIN PRIVATE KEY-----\nabc"}
		},
		"tags":{"credential":"do-not-store","token":"abc"}
	}`))
	if err != nil {
		t.Fatalf("NormalizeJumphostEvent returned error: %v", err)
	}
	blob := ev.Raw + " " + stringAny(ev.Tags["credential"]) + " " + stringAny(ev.Tags["token"])
	for _, forbidden := range []string{"secret", "Bearer secret", "BEGIN PRIVATE KEY", "do-not-store", "abc"} {
		if strings.Contains(blob, forbidden) {
			t.Fatalf("expected %q to be redacted from %s", forbidden, blob)
		}
	}
	if !strings.Contains(ev.Raw, "[REDACTED]") || ev.Tags["credential"] != "[REDACTED]" || ev.Tags["token"] != "[REDACTED]" {
		t.Fatalf("expected redacted values, raw=%s tags=%#v", ev.Raw, ev.Tags)
	}
}
