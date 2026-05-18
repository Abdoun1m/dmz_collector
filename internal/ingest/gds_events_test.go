package ingest

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestNormalizeGDSEventCertificateIssued(t *testing.T) {
	raw := []byte(`{
		"event_type":"certificate_issued",
		"created_at":"2026-05-18T13:00:00Z",
		"actor":"labshock_gds",
		"target":"certificate:42",
		"details_json":{
			"request_id":"req-1",
			"application_uri":"urn:dataprotect:opcua:dmz-gateway-client",
			"fingerprint_sha256":"abc123",
			"serial_number":"01:02"
		}
	}`)
	ev, err := NormalizeGDSEvent(raw)
	if err != nil {
		t.Fatalf("NormalizeGDSEvent returned error: %v", err)
	}
	if ev.SourceType != "gds" || ev.Zone != "DMZ" || ev.AssetName != "labshock_gds" {
		t.Fatalf("unexpected source identity: %#v", ev)
	}
	if ev.Message != "gds_certificate_issued" || ev.EventCategory != "certificate_lifecycle" || ev.Severity != "info" {
		t.Fatalf("unexpected classification: %s %s %s", ev.Message, ev.EventCategory, ev.Severity)
	}
	if ev.Tags["splunk_sourcetype"] != "labshock:dmz:gds" || ev.Tags["alert_candidate"] != true {
		t.Fatalf("unexpected tags: %#v", ev.Tags)
	}
	if ev.Tags["application_uri"] != "urn:dataprotect:opcua:dmz-gateway-client" || ev.Tags["fingerprint_sha256"] != "abc123" {
		t.Fatalf("missing safe details in tags: %#v", ev.Tags)
	}
}

func TestNormalizeGDSEventTrustListPublishedFromJSONLog(t *testing.T) {
	raw := []byte(`{"ts":"2026-05-18T13:01:00Z","level":"INFO","logger":"gds.api","msg":"artifact regenerated zone=OT role=server version=3 revision=7 reason=version_changed"}`)
	ev, err := NormalizeGDSEvent(raw)
	if err != nil {
		t.Fatalf("NormalizeGDSEvent returned error: %v", err)
	}
	if ev.Message != "gds_trust_list_published" || ev.EventCategory != "pki_trust_sync" {
		t.Fatalf("unexpected trust-list classification: %s %s", ev.Message, ev.EventCategory)
	}
	if ev.Tags["alert_candidate"] != true {
		t.Fatalf("expected alert candidate tag, got %#v", ev.Tags)
	}
}

func TestNormalizeGDSEventUnauthorizedRequest(t *testing.T) {
	raw := []byte(`{
		"event_type":"agent_auth_failure",
		"created_at":"2026-05-18T13:02:00Z",
		"actor":"opcua_dmz_gateway",
		"target":"artifact_read:OT:server",
		"source_ip":"192.168.10.20",
		"error_code":"invalid_token",
		"correlation_id":"corr-1"
	}`)
	ev, err := NormalizeGDSEvent(raw)
	if err != nil {
		t.Fatalf("NormalizeGDSEvent returned error: %v", err)
	}
	if ev.Message != "gds_unauthorized_request" || ev.EventCategory != "security" || ev.Severity != "warning" {
		t.Fatalf("unexpected auth failure classification: %s %s %s", ev.Message, ev.EventCategory, ev.Severity)
	}
	if ev.Tags["alert_candidate"] != true || ev.Tags["source_ip"] != "192.168.10.20" {
		t.Fatalf("unexpected auth failure tags: %#v", ev.Tags)
	}
}

func TestNormalizeGDSEventDBHealthFailure(t *testing.T) {
	raw := []byte(`{
		"status":"degraded",
		"reported_at":"2026-05-18T13:03:00Z",
		"checks":{"postgres":{"ok":false,"detail":"connection refused"}}
	}`)
	ev, err := NormalizeGDSEvent(raw)
	if err != nil {
		t.Fatalf("NormalizeGDSEvent returned error: %v", err)
	}
	if ev.Message != "gds_db_disconnected" || ev.EventCategory != "error" || ev.Severity != "critical" {
		t.Fatalf("unexpected DB classification: %s %s %s", ev.Message, ev.EventCategory, ev.Severity)
	}
	if ev.Tags["alert_candidate"] != true {
		t.Fatalf("expected DB failure alert candidate, got %#v", ev.Tags)
	}
}

func TestNormalizeGDSEventDBSnapshot(t *testing.T) {
	raw := []byte(`{
		"event_type":"gds_db_snapshot",
		"reported_at":"2026-05-18T13:04:00Z",
		"audit_events_count":120,
		"audit_events_latest_id":99,
		"certificates_count":5,
		"trust_artifacts_latest_id":7
	}`)
	ev, err := NormalizeGDSEvent(raw)
	if err != nil {
		t.Fatalf("NormalizeGDSEvent returned error: %v", err)
	}
	if ev.Message != "gds_db_snapshot" || ev.EventCategory != "system_health" || ev.Severity != "info" {
		t.Fatalf("unexpected DB snapshot classification: %s %s %s", ev.Message, ev.EventCategory, ev.Severity)
	}
	if ev.Tags["alert_candidate"] == true {
		t.Fatalf("DB snapshot should not be alert candidate: %#v", ev.Tags)
	}
}

func TestNormalizeGDSEventExplicitHealthEvents(t *testing.T) {
	tests := []struct {
		eventType string
		message   string
		category  string
		severity  string
		alert     bool
	}{
		{"gds_heartbeat", "gds_heartbeat", "system_health", "info", false},
		{"gds_db_connected", "gds_db_connected", "system_health", "info", false},
		{"gds_db_disconnected", "gds_db_disconnected", "error", "critical", true},
	}
	for _, tt := range tests {
		t.Run(tt.eventType, func(t *testing.T) {
			raw := []byte(`{"event_type":"` + tt.eventType + `","reported_at":"2026-05-18T13:05:00Z"}`)
			ev, err := NormalizeGDSEvent(raw)
			if err != nil {
				t.Fatalf("NormalizeGDSEvent returned error: %v", err)
			}
			if ev.Message != tt.message || ev.EventCategory != tt.category || ev.Severity != tt.severity {
				t.Fatalf("unexpected explicit health classification: %s %s %s", ev.Message, ev.EventCategory, ev.Severity)
			}
			if got := ev.Tags["alert_candidate"] == true; got != tt.alert {
				t.Fatalf("expected alert=%v, got tags %#v", tt.alert, ev.Tags)
			}
		})
	}
}

func TestNormalizeGDSTextLineStartup(t *testing.T) {
	events, err := NormalizeGDSEventsMany([]byte(`[gds-entrypoint] starting Uvicorn on 127.0.0.1:18081`))
	if err != nil {
		t.Fatalf("NormalizeGDSEventsMany returned error: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	if events[0].Message != "gds_started" || events[0].EventCategory != "system_health" {
		t.Fatalf("unexpected text classification: %s %s", events[0].Message, events[0].EventCategory)
	}
}

func TestNormalizeGDSEventRedactsSensitiveFields(t *testing.T) {
	raw := []byte(`{
		"event_type":"certificate_issued",
		"created_at":"2026-05-18T13:00:00Z",
		"role_id":"must-not-leak",
		"secret_id":"must-not-leak",
		"token":"must-not-leak",
		"private_key":"-----BEGIN PRIVATE KEY-----abc",
		"details_json":{
			"certificate_pem":"-----BEGIN CERTIFICATE-----abc",
			"csr_pem":"-----BEGIN CERTIFICATE REQUEST-----abc",
			"crl_base64":"abc",
			"fingerprint_sha256":"safe"
		}
	}`)
	ev, err := NormalizeGDSEvent(raw)
	if err != nil {
		t.Fatalf("NormalizeGDSEvent returned error: %v", err)
	}
	blob, _ := json.Marshal(ev.ToMap())
	for _, forbidden := range []string{"must-not-leak", "BEGIN PRIVATE KEY", "BEGIN CERTIFICATE", "crl_base64"} {
		if strings.Contains(string(blob), forbidden) {
			t.Fatalf("sensitive value leaked in event: %s", blob)
		}
	}
	if ev.Tags["fingerprint_sha256"] != "safe" {
		t.Fatalf("safe fingerprint was not preserved: %#v", ev.Tags)
	}
}
