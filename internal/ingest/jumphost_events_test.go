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

func TestNormalizeJumphostUnknownMessageReparsesRawLine(t *testing.T) {
	tests := []struct {
		name       string
		line       string
		wantMsg    string
		wantCat    string
		wantSev    string
		wantFields map[string]any
	}{
		{
			name:    "accepted certificate id",
			line:    `Accepted certificate ID "vault-userpass-otadmin-86f31e305c1f80dd4ffe4148347ca0c39b50e26aa3d2d0cf66b1e82d6c42aead" (serial 11876948199668790762) signed by RSA CA SHA256:M3GZglFNuvC8ceE/raXQh702jwNYvWeDW2gZucLiFUk via /config/sshd/vault-ssh-ca.pub`,
			wantMsg: "jump_cert_accepted",
			wantCat: "access_control",
			wantSev: "info",
			wantFields: map[string]any{
				"cert_id":        "vault-userpass-otadmin-86f31e305c1f80dd4ffe4148347ca0c39b50e26aa3d2d0cf66b1e82d6c42aead",
				"cert_serial":    "11876948199668790762",
				"ca_fingerprint": "SHA256:M3GZglFNuvC8ceE/raXQh702jwNYvWeDW2gZucLiFUk",
			},
		},
		{
			name:    "postponed publickey",
			line:    `Postponed publickey for jumpadmin from 192.168.10.249 port 56714 ssh2 [preauth]`,
			wantMsg: "jump_pubkey_postponed",
			wantCat: "access_control",
			wantSev: "info",
			wantFields: map[string]any{
				"user":     "jumpadmin",
				"src_ip":   "192.168.10.249",
				"src_port": "56714",
			},
		},
		{
			name:    "received disconnect",
			line:    `Received disconnect from 192.168.10.249 port 56714:11: disconnected by user`,
			wantMsg: "jump_session_disconnected",
			wantCat: "session",
			wantSev: "info",
			wantFields: map[string]any{
				"src_ip":   "192.168.10.249",
				"src_port": "56714",
			},
		},
		{
			name:    "disconnected from user",
			line:    `Disconnected from user jumpadmin 192.168.10.249 port 56714`,
			wantMsg: "jump_session_closed_user",
			wantCat: "session",
			wantSev: "info",
			wantFields: map[string]any{
				"user":     "jumpadmin",
				"src_ip":   "192.168.10.249",
				"src_port": "56714",
			},
		},
		{
			name:    "host key mismatch",
			line:    `Unable to negotiate with 192.168.10.249 port 46522: no matching host key type found. Their offer: ecdsa-sha2-nistp256 [preauth]`,
			wantMsg: "jump_hostkey_mismatch",
			wantCat: "security",
			wantSev: "warning",
			wantFields: map[string]any{
				"src_ip":             "192.168.10.249",
				"src_port":           "46522",
				"offered_algorithms": "ecdsa-sha2-nistp256",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ev, err := NormalizeJumphostEvent(mustJSON(map[string]any{
				"message":        "jump_event_unknown",
				"event_category": "jumphost",
				"severity":       "info",
				"source":         "jumphost_internal_sshd_log",
				"raw": map[string]any{
					"forwarder":   "jumphost-internal-sshd-forwarder",
					"line":        tt.line + "\r",
					"parser_hint": "sshd_auth_log",
				},
				"tags": map[string]any{
					"component":            "jumphost",
					"normalization_source": "jumphost_internal_forwarder",
					"risk_level":           "LOW",
				},
			}))
			if err != nil {
				t.Fatalf("NormalizeJumphostEvent returned error: %v", err)
			}
			if ev.Message != tt.wantMsg || ev.EventCategory != tt.wantCat || ev.Severity != tt.wantSev {
				t.Fatalf("unexpected classification: %s %s %s", ev.Message, ev.EventCategory, ev.Severity)
			}
			if ev.Tags["risk_level"] != riskForJumphost(tt.wantMsg, tt.wantCat, tt.wantSev) {
				t.Fatalf("expected mapped risk level, got %#v", ev.Tags["risk_level"])
			}
			if ev.Tags["parser_hint"] != "sshd_auth_log" {
				t.Fatalf("expected parser hint to be preserved/promoted, got %#v", ev.Tags)
			}
			if !strings.Contains(ev.Raw, `"line"`) || !strings.Contains(ev.Raw, `sshd_auth_log`) {
				t.Fatalf("expected raw line and parser hint to be preserved, got %s", ev.Raw)
			}
			for key, want := range tt.wantFields {
				if ev.Tags[key] != want {
					t.Fatalf("expected %s=%#v, got %#v in tags %#v", key, want, ev.Tags[key], ev.Tags)
				}
			}
		})
	}
}

func TestNormalizeJumphostKeepsAlreadyNormalizedMessage(t *testing.T) {
	ev, err := NormalizeJumphostEvent(mustJSON(map[string]any{
		"message":        "jump_login_success",
		"event_category": "access_control",
		"severity":       "info",
		"raw": map[string]any{
			"line": "Accepted certificate ID \"vault-test\" signed by RSA CA SHA256:abc",
		},
	}))
	if err != nil {
		t.Fatalf("NormalizeJumphostEvent returned error: %v", err)
	}
	if ev.Message != "jump_login_success" {
		t.Fatalf("expected already-normalized message to be preserved, got %s", ev.Message)
	}
}
