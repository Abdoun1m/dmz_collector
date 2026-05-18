package ingest

import (
	"encoding/json"
	"testing"
)

func TestNormalizeVaultAuditPermissionDenied(t *testing.T) {
	raw := []byte(`{
		"type":"response",
		"time":"2026-05-18T12:19:32.587246477Z",
		"error":"permission denied",
		"auth":{
			"display_name":"root",
			"policies":["root"],
			"token_policies":["root"]
		},
		"request":{
			"id":"c9121682-90c6-e96a-ca6b-afcd73cac59a",
			"operation":"read",
			"path":"sys/internal/ui/mounts/secret/labshock/audit-test",
			"remote_address":"192.168.10.10",
			"remote_port":53360,
			"mount_type":"system",
			"client_token_accessor":"hmac-sha256:a2280384d7e0"
		}
	}`)

	ev, err := NormalizeVaultAudit(raw)
	if err != nil {
		t.Fatalf("NormalizeVaultAudit returned error: %v", err)
	}
	if ev.SourceType != "vault" || ev.Zone != "DMZ" {
		t.Fatalf("unexpected source identity: source_type=%q zone=%q", ev.SourceType, ev.Zone)
	}
	if ev.Message != "vault_policy_violation" || ev.EventCategory != "security" || ev.Severity != "critical" {
		t.Fatalf("unexpected classification: %s %s %s", ev.Message, ev.EventCategory, ev.Severity)
	}
	if ev.Tags["splunk_sourcetype"] != "labshock:dmz:vault" {
		t.Fatalf("unexpected sourcetype: %#v", ev.Tags["splunk_sourcetype"])
	}
	if ev.Tags["alert_candidate"] != true || ev.Tags["risk_level"] != "CRITICAL" {
		t.Fatalf("unexpected alert tags: %#v", ev.Tags)
	}

	var safeRaw map[string]any
	if err := json.Unmarshal([]byte(ev.Raw), &safeRaw); err != nil {
		t.Fatalf("raw is not JSON: %v", err)
	}
	if safeRaw["client_token"] != nil {
		t.Fatalf("raw leaked client token: %#v", safeRaw)
	}
	if safeRaw["vault_path"] != "sys/internal/ui/mounts/secret/labshock/audit-test" {
		t.Fatalf("unexpected vault path in raw: %#v", safeRaw)
	}
}

func TestNormalizeVaultAuditJSONL(t *testing.T) {
	raw := []byte(`{"type":"request","time":"2026-05-18T12:19:31Z","request":{"operation":"read","path":"auth/token/lookup-self"}}
{"type":"response","time":"2026-05-18T12:19:32Z","request":{"operation":"read","path":"auth/token/lookup-self"}}
{"type":"response","time":"2026-05-18T12:19:33Z","request":{"operation":"read","path":"secret/data/example"}}`)

	events, err := NormalizeVaultAuditMany(raw)
	if err != nil {
		t.Fatalf("NormalizeVaultAuditMany returned error: %v", err)
	}
	if len(events) != 2 {
		t.Fatalf("expected 2 events, got %d", len(events))
	}
	if events[0].SourceType != "vault" || events[1].SourceType != "vault" {
		t.Fatalf("unexpected source types: %#v", events)
	}
}

func TestNormalizeVaultAuditPKIReads(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		expected string
	}{
		{name: "ca chain", path: "pki-int/ca_chain", expected: "vault_pki_ca_chain_read"},
		{name: "intermediate crl", path: "pki-int/crl/pem", expected: "vault_pki_crl_read"},
		{name: "root issuer crl", path: "pki-root/issuer/f4e8cc06-e50b-dd54-6fbf-752dd4180352/crl/pem", expected: "vault_pki_crl_read"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			raw := []byte(`{"type":"response","time":"2026-05-18T12:19:32Z","request":{"operation":"read","path":"` + tt.path + `","mount_type":"pki"}}`)
			ev, err := NormalizeVaultAudit(raw)
			if err != nil {
				t.Fatalf("NormalizeVaultAudit returned error: %v", err)
			}
			if ev.Message != tt.expected {
				t.Fatalf("expected %s, got %s", tt.expected, ev.Message)
			}
			if ev.EventCategory != "pki_validation" {
				t.Fatalf("expected pki_validation, got %s", ev.EventCategory)
			}
		})
	}
}

func TestNormalizeVaultAuditSuppressesRoutineRequests(t *testing.T) {
	raw := []byte(`{"type":"request","time":"2026-05-18T12:19:31Z","request":{"operation":"read","path":"auth/token/lookup-self"}}`)
	ev, err := NormalizeVaultAudit(raw)
	if err != nil {
		t.Fatalf("NormalizeVaultAudit returned error: %v", err)
	}
	if ev.Message != "" {
		t.Fatalf("expected suppressed event, got %s", ev.Message)
	}
}
