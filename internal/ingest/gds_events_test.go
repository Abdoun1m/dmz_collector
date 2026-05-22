package ingest

import (
	"encoding/json"
	"fmt"
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
	if ev.Tags["splunk_sourcetype"] != "labshock:dmz:gds" || ev.Tags["parser_version"] != "v3.2.gds_pack_mapping" {
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
	if ev.Tags["parser_version"] != "v3.2.gds_pack_mapping" {
		t.Fatalf("expected parser version v3.2, got %#v", ev.Tags["parser_version"])
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
	if ev.Tags["gds_action"] != "gds_db_snapshot" {
		t.Fatalf("DB snapshot should preserve action tag: %#v", ev.Tags)
	}
}

func TestNormalizeGDSEventPackPayload(t *testing.T) {
	raw := []byte(`[
	  {
	    "source_type": "gds",
	    "sourcetype": "labshock:dmz:gds",
	    "zone": "DMZ",
	    "asset_name": "labshock_gds",
	    "asset_ip": "192.168.10.30",
	    "message": "gds_certificate_issued",
	    "event_category": "certificate_lifecycle",
	    "severity": "info",
	    "raw": {
	      "event_type": "certificate_issued",
	      "application_uri": "urn:dataprotect:opcua:dmz-gateway-client",
	      "certificate_id": "cert-123",
	      "fingerprint_sha256": "abc123",
	      "serial_number": "01A4"
	    }
	  },
	  {
	    "source_type": "gds",
	    "message": "gds_event",
	    "raw": {
	      "log_message": "gds_audit_event: trustlist_artifact_read"
	    }
	  },
	  {
	    "source_type": "gds",
	    "message": "gds_db_snapshot",
	    "event_category": "system_health",
	    "severity": "info",
	    "raw": {
	      "event_type": "gds_db_snapshot",
	      "db_connected": true,
	      "tables": {
	        "audit_events": {
	          "row_count": 1222,
	          "latest_id": 1222
	        },
	        "certificates": {
	          "row_count": 8,
	          "latest_id": 8
	        }
	      }
	    }
	  },
	  {
	    "source_type": "gds",
	    "raw": {
	      "event_type": "agent_auth_failure",
	      "source_ip": "192.168.1.30",
	      "target": "/api/v1/trustlists/OT/server/artifact",
	      "error_code": "invalid_agent_token"
	    }
	  }
	]`)
	events, err := NormalizeGDSEventsMany(raw)
	if err != nil {
		t.Fatalf("NormalizeGDSEventsMany returned error: %v", err)
	}
	if len(events) != 4 {
		t.Fatalf("expected 4 events, got %d", len(events))
	}
	want := []struct {
		message  string
		category string
		severity string
	}{
		{"gds_certificate_issued", "certificate_lifecycle", "info"},
		{"gds_client_pull_success", "pki_trust_sync", "info"},
		{"gds_db_snapshot", "system_health", "info"},
		{"gds_unauthorized_request", "security", "warning"},
	}
	for i, tt := range want {
		if events[i].Message != tt.message || events[i].EventCategory != tt.category || events[i].Severity != tt.severity {
			t.Fatalf("event %d got (%s,%s,%s), want (%s,%s,%s)", i, events[i].Message, events[i].EventCategory, events[i].Severity, tt.message, tt.category, tt.severity)
		}
	}
	if !strings.Contains(events[2].Raw, `"tables"`) || !strings.Contains(events[2].Raw, `"audit_events"`) || !strings.Contains(events[2].Raw, `"row_count":1222`) {
		t.Fatalf("expected compact DB table snapshot in raw, got %s", events[2].Raw)
	}
	if events[3].Tags["alert_candidate"] != true {
		t.Fatalf("expected auth failure alert candidate, got %#v", events[3].Tags)
	}
}

func TestNormalizeGDSOPCUAFacadeMethodCompleted(t *testing.T) {
	raw := []byte(`{
	  "source_type":"gds",
	  "source":"gds_opcua_facade",
	  "asset_name":"labshock_gds",
	  "asset_ip":"192.168.10.30",
	  "zone":"DMZ",
	  "protocol":"opcua",
	  "message":"gds_opcua_method_completed",
	  "event_category":"system_health",
	  "severity":"info",
	  "timestamp":"2026-05-19T10:00:00Z",
	  "raw":{
	    "method_name":"GetTrustMaterialStatus",
	    "method_class":"SENSITIVE_READ",
	    "application_uri":"urn:dataprotect:opcua:ot-server",
	    "decision":"allowed",
	    "reason":"ok",
	    "result_code":"ok",
	    "duration_ms":12,
	    "correlation_id":"abc",
	    "opcua_session_id":"anonymous"
	  },
	  "tags":{
	    "component":"gds_opcua_facade",
	    "parser_version":"v3.3.gds_opcua_facade",
	    "risk_level":"LOW"
	  }
	}`)
	ev, err := NormalizeGDSEvent(raw)
	if err != nil {
		t.Fatalf("NormalizeGDSEvent returned error: %v", err)
	}
	if ev.Message != "gds_opcua_method_completed" || ev.EventCategory != "system_health" || ev.Severity != "info" {
		t.Fatalf("unexpected facade classification: %s %s %s", ev.Message, ev.EventCategory, ev.Severity)
	}
	if ev.SourceType != "gds" || ev.Source != "gds_opcua_facade" || ev.Protocol != "opcua" || ev.Zone != "DMZ" {
		t.Fatalf("unexpected facade identity: %#v", ev)
	}
	if ev.Tags["component"] != "gds_opcua_facade" || ev.Tags["parser_version"] != "v3.3.gds_opcua_facade" || ev.Tags["facade_version"] != "v3.3.gds_opcua_facade" {
		t.Fatalf("unexpected facade tags: %#v", ev.Tags)
	}
	for _, key := range []string{"method_name", "method_class", "application_uri", "decision", "reason", "result_code", "duration_ms", "correlation_id", "opcua_session_id"} {
		if ev.Tags[key] == nil {
			t.Fatalf("expected metadata tag %s, got %#v", key, ev.Tags)
		}
		if !strings.Contains(ev.Raw, key) {
			t.Fatalf("expected raw to preserve %s, got %s", key, ev.Raw)
		}
	}
	if ev.Message == "gds_event_unknown" {
		t.Fatal("facade event was classified as unknown")
	}
}

func TestNormalizeGDSOPCUAFacadeObservedUnknownShape(t *testing.T) {
	raw := []byte(`{
	  "source_type":"gds",
	  "source":"gds_events",
	  "message":"gds_event_unknown",
	  "raw":{
	    "correlation_id":"0260b77c62a34a10ab6f43b9e1765cff",
	    "gds_action":"gds_opcua_method_called",
	    "gds_family":"gds_runtime",
	    "log_message":"gds_opcua_method_called"
	  },
	  "tags":{
	    "component":"gds",
	    "gds_action":"gds_opcua_method_called",
	    "gds_family":"gds_runtime",
	    "log_message":"gds_opcua_method_called",
	    "parser_version":"v3.2.gds_pack_mapping"
	  }
	}`)
	ev, err := NormalizeGDSEvent(raw)
	if err != nil {
		t.Fatalf("NormalizeGDSEvent returned error: %v", err)
	}
	if ev.Message != "gds_opcua_method_called" || ev.EventCategory != "access_control" || ev.Severity != "info" {
		t.Fatalf("unexpected observed facade classification: %s %s %s", ev.Message, ev.EventCategory, ev.Severity)
	}
	if ev.Source != "gds_opcua_facade" || ev.Protocol != "opcua" {
		t.Fatalf("expected facade source/protocol, got source=%q protocol=%q", ev.Source, ev.Protocol)
	}
	if ev.Tags["component"] != "gds_opcua_facade" || ev.Tags["parser_version"] != "v3.3.gds_opcua_facade" || ev.Tags["risk_level"] != "LOW" {
		t.Fatalf("unexpected observed facade tags: %#v", ev.Tags)
	}
	if ev.Tags["correlation_id"] != "0260b77c62a34a10ab6f43b9e1765cff" {
		t.Fatalf("expected correlation_id promotion, got %#v", ev.Tags)
	}
	if ev.Message == "gds_event_unknown" {
		t.Fatal("facade event was classified as unknown")
	}
}

func TestNormalizeGDSOPCUAFacadeMappings(t *testing.T) {
	tests := []struct {
		message  string
		category string
		severity string
		risk     string
	}{
		{"gds_opcua_method_called", "access_control", "info", "LOW"},
		{"gds_opcua_method_denied", "access_control", "warning", "HIGH"},
		{"gds_opcua_invalid_input", "access_control", "warning", "MEDIUM"},
		{"gds_opcua_rate_limited", "access_control", "warning", "MEDIUM"},
		{"gds_opcua_internal_api_failed", "error", "error", "HIGH"},
		{"gds_opcua_sensitive_material_blocked", "data_protection", "critical", "CRITICAL"},
	}
	for _, tt := range tests {
		t.Run(tt.message, func(t *testing.T) {
			raw := []byte(fmt.Sprintf(`{
				"source_type":"gds",
				"source":"gds_opcua_facade",
				"message":%q,
				"raw":{"method_name":"CreateSigningRequest","method_class":"WRITE_REQUEST","decision":"denied"},
				"tags":{"component":"gds_opcua_facade"}
			}`, tt.message))
			ev, err := NormalizeGDSEvent(raw)
			if err != nil {
				t.Fatalf("NormalizeGDSEvent returned error: %v", err)
			}
			if ev.Message != tt.message || ev.EventCategory != tt.category || ev.Severity != tt.severity || ev.Tags["risk_level"] != tt.risk {
				t.Fatalf("got (%s,%s,%s,%v), want (%s,%s,%s,%s)", ev.Message, ev.EventCategory, ev.Severity, ev.Tags["risk_level"], tt.message, tt.category, tt.severity, tt.risk)
			}
			if ev.Message == "gds_event_unknown" {
				t.Fatal("facade event was classified as unknown")
			}
		})
	}
}

func TestNormalizeGDSOPCUAFacadeAuditLogMessage(t *testing.T) {
	raw := []byte(`{
	  "source_type":"gds",
	  "source":"gds_events",
	  "message":"gds_event_unknown",
	  "raw":{
	    "log_message":"gds_audit_event: gds_opcua_invalid_input"
	  },
	  "tags":{
	    "log_message":"gds_audit_event: gds_opcua_invalid_input"
	  }
	}`)
	ev, err := NormalizeGDSEvent(raw)
	if err != nil {
		t.Fatalf("NormalizeGDSEvent returned error: %v", err)
	}
	if ev.Message != "gds_opcua_invalid_input" || ev.EventCategory != "access_control" || ev.Severity != "warning" || ev.Tags["risk_level"] != "MEDIUM" {
		t.Fatalf("unexpected audit facade classification: %s %s %s %#v", ev.Message, ev.EventCategory, ev.Severity, ev.Tags)
	}
}

func TestNormalizeGDSOPCUAFacadeSensitiveRedaction(t *testing.T) {
	raw := []byte(`{
	  "source_type":"gds",
	  "source":"gds_opcua_facade",
	  "message":"gds_opcua_sensitive_material_blocked",
	  "raw":{
	    "method_name":"GetTrustMaterialStatus",
	    "token":"secret-token",
	    "x-vault-token":"vault-token",
	    "x-gds-agent-token":"agent-token",
	    "private_key":"-----BEGIN RSA PRIVATE KEY-----\nabc",
	    "nested":{"password":"secret-password","accessor":"secret-accessor"}
	  },
	  "tags":{
	    "component":"gds_opcua_facade",
	    "authorization":"Bearer secret",
	    "secret_id":"sid"
	  }
	}`)
	ev, err := NormalizeGDSEvent(raw)
	if err != nil {
		t.Fatalf("NormalizeGDSEvent returned error: %v", err)
	}
	blob, _ := json.Marshal(ev.ToMap())
	for _, forbidden := range []string{"secret-token", "BEGIN RSA PRIVATE KEY", "secret-password", "secret-accessor", "Bearer secret", `:"sid"`} {
		if strings.Contains(string(blob), forbidden) {
			t.Fatalf("sensitive value leaked in event: %s", blob)
		}
	}
	if !strings.Contains(ev.Raw, "[REDACTED]") {
		t.Fatalf("expected redaction markers in raw, got %s", ev.Raw)
	}
	if ev.Tags["authorization"] != "[REDACTED]" || ev.Tags["secret_id"] != "[REDACTED]" {
		t.Fatalf("expected sensitive tags redacted, got %#v", ev.Tags)
	}
	if ev.Tags["parser_version"] != "v3.3.gds_opcua_facade" || ev.Tags["risk_level"] != "CRITICAL" {
		t.Fatalf("unexpected facade tags: %#v", ev.Tags)
	}
}

func TestNormalizeGDSContractCRLRotated(t *testing.T) {
	raw := []byte(`{
	  "source_type":"gds",
	  "source":"gds_events",
	  "asset_name":"labshock_gds",
	  "asset_ip":"192.168.10.30",
	  "zone":"DMZ",
	  "protocol":"http",
	  "message":"vault_crl_rotated",
	  "event_category":"pki_lifecycle",
	  "severity":"info",
	  "timestamp":"2026-05-22T10:15:30Z",
	  "raw":{
	    "vault_mount":"pki-int",
	    "crl_name":"intermediate",
	    "crl_next_update":"2026-05-25T10:15:30Z",
	    "expiry":"72h"
	  },
	  "tags":{
	    "component":"vault",
	    "vault_mount":"pki-int",
	    "crl_name":"intermediate"
	  }
	}`)
	ev, err := NormalizeGDSEvent(raw)
	if err != nil {
		t.Fatalf("NormalizeGDSEvent returned error: %v", err)
	}
	if ev.Message != "vault_crl_rotated" || ev.EventCategory != "pki_lifecycle" || ev.Severity != "info" || ev.Protocol != "http" {
		t.Fatalf("unexpected CRL contract event: %#v", ev)
	}
	if ev.Tags["component"] != "vault" || ev.Tags["parser_version"] != "v3.4.gds_pki_lifecycle" || ev.Tags["normalization_source"] != "gds_pki_lifecycle" || ev.Tags["risk_level"] != "LOW" {
		t.Fatalf("unexpected CRL tags: %#v", ev.Tags)
	}
	if ev.Tags["vault_mount"] != "pki-int" || ev.Tags["crl_name"] != "intermediate" || ev.Tags["expiry"] != "72h" {
		t.Fatalf("expected CRL metadata tags, got %#v", ev.Tags)
	}
}

func TestNormalizeGDSContractPromotesTagsGDSAction(t *testing.T) {
	raw := []byte(`{
	  "source_type":"gds",
	  "source":"gds_events",
	  "message":"gds_event_unknown",
	  "raw":{
	    "application_uri":"urn:dataprotect:opcua:ot-server",
	    "runtime_instance_id":"urn:dataprotect:opcua:ot-server",
	    "target":"ot-server",
	    "status":"failed",
	    "result_code":"validation_failed"
	  },
	  "tags":{
	    "gds_action":"client_gds_validation_failed",
	    "application_uri":"urn:dataprotect:opcua:ot-server"
	  }
	}`)
	ev, err := NormalizeGDSEvent(raw)
	if err != nil {
		t.Fatalf("NormalizeGDSEvent returned error: %v", err)
	}
	if ev.Message != "client_gds_validation_failed" || ev.EventCategory != "pki_lifecycle" || ev.Severity != "warning" {
		t.Fatalf("unexpected client lifecycle contract event: %s %s %s", ev.Message, ev.EventCategory, ev.Severity)
	}
	if ev.Source != "gds_client_lifecycle" || ev.Tags["component"] != "gds_client_lifecycle" || ev.Tags["parser_version"] != "v3.3.gds_client_lifecycle" {
		t.Fatalf("unexpected client lifecycle identity/tags: source=%s tags=%#v", ev.Source, ev.Tags)
	}
	if ev.Tags["risk_level"] != "HIGH" || ev.Tags["alert_candidate"] != true {
		t.Fatalf("expected high-risk alert tags, got %#v", ev.Tags)
	}
	if ev.Tags["application_uri"] != "urn:dataprotect:opcua:ot-server" || ev.Tags["target"] != "ot-server" || ev.Tags["result_code"] != "validation_failed" {
		t.Fatalf("expected client lifecycle metadata, got %#v", ev.Tags)
	}
}

func TestNormalizeGDSContractTrustArtifactFields(t *testing.T) {
	raw := []byte(`{
	  "source_type":"gds",
	  "message":"trust_artifact_regenerated",
	  "raw":{
	    "target":"trustlist_artifact:OT:server",
	    "trustlist_zone":"OT",
	    "trustlist_role":"server",
	    "artifact_revision":7,
	    "artifact_sha256":"abcdef0123456789",
	    "reason":"crl_refresh"
	  }
	}`)
	ev, err := NormalizeGDSEvent(raw)
	if err != nil {
		t.Fatalf("NormalizeGDSEvent returned error: %v", err)
	}
	if ev.Message != "trust_artifact_regenerated" || ev.EventCategory != "pki_trust_sync" || ev.Severity != "info" {
		t.Fatalf("unexpected trust artifact event: %s %s %s", ev.Message, ev.EventCategory, ev.Severity)
	}
	if ev.Source != "trust_artifact" || ev.Tags["component"] != "trust_artifact" || ev.Tags["risk_level"] != "LOW" {
		t.Fatalf("unexpected trust artifact identity/tags: source=%s tags=%#v", ev.Source, ev.Tags)
	}
	if ev.Tags["target"] != "trustlist_artifact:OT:server" || ev.Tags["trustlist_zone"] != "OT" || ev.Tags["trustlist_role"] != "server" || ev.Tags["artifact_revision"] != float64(7) {
		t.Fatalf("expected trust artifact metadata, got %#v", ev.Tags)
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

func TestNormalizeGDSEventAppJSONStartup(t *testing.T) {
	raw := []byte(`{"ts":"2026-05-18T13:07:00Z","level":"INFO","logger":"gds.api","msg":"artifact scan loop started interval_seconds=30"}`)
	ev, err := NormalizeGDSEvent(raw)
	if err != nil {
		t.Fatalf("NormalizeGDSEvent returned error: %v", err)
	}
	if ev.Message != "gds_started" || ev.EventCategory != "system_health" || ev.Severity != "info" {
		t.Fatalf("unexpected app JSON startup classification: %s %s %s", ev.Message, ev.EventCategory, ev.Severity)
	}
}

func TestNormalizeGDSEventHealthSuccess(t *testing.T) {
	raw := []byte(`{"status":"ok","checks":{"postgres":{"ok":true}}}`)
	ev, err := NormalizeGDSEvent(raw)
	if err != nil {
		t.Fatalf("NormalizeGDSEvent returned error: %v", err)
	}
	if ev.Message != "gds_db_connected" || ev.EventCategory != "system_health" || ev.Severity != "info" {
		t.Fatalf("unexpected health success classification: %s %s %s", ev.Message, ev.EventCategory, ev.Severity)
	}
}

func TestNormalizeGDSTextLineAPIReadSuccess(t *testing.T) {
	events, err := NormalizeGDSEventsMany([]byte("GET /api/v1/trustlists/OT/server/artifact HTTP/1.1 200"))
	if err != nil {
		t.Fatalf("NormalizeGDSEventsMany returned error: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	ev := events[0]
	if ev.Message != "gds_client_pull_success" || ev.EventCategory != "pki_trust_sync" || ev.Severity != "info" {
		t.Fatalf("unexpected API read classification: %s %s %s", ev.Message, ev.EventCategory, ev.Severity)
	}
	if ev.Tags["http_method"] != "GET" || ev.Tags["http_path"] != "/api/v1/trustlists/OT/server/artifact" || ev.Tags["http_status"] != "200" || ev.Tags["endpoint_family"] != "trust_artifact" {
		t.Fatalf("expected parsed HTTP tags, got %#v", ev.Tags)
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

func TestNormalizeGDSEventDMZControlPlaneMappings(t *testing.T) {
	tests := []struct {
		name       string
		logMessage string
		expected   string
		category   string
		risk       string
	}{
		{"agent auth success", "gds_audit_event: agent_auth_success", "gds_agent_auth_success", "access_control", "LOW"},
		{"mtls identity success", "gds_audit_event: mtls_client_identity_success", "gds_mtls_client_identity_success", "access_control", "LOW"},
		{"mtls metrics read", "gds_audit_event: mtls_metrics_read", "gds_client_pull_success", "access_control", "LOW"},
		{"trustlist read", "gds_audit_event: trustlist_artifact_read", "gds_client_pull_success", "pki_trust_sync", "LOW"},
		{"trustlist signature read", "gds_audit_event: trustlist_artifact_sig_read", "gds_client_pull_success", "pki_trust_sync", "LOW"},
		{"artifact regenerated", "gds_trust_list_published: artifact_regenerated", "gds_trust_list_published", "pki_trust_sync", "MEDIUM"},
		{"certificate drift read", "gds_audit_event: certificate_drift_read", "gds_certificate_drift_read", "pki_validation", "LOW"},
		{"certificate telemetry read", "gds_audit_event: certificate_telemetry_read", "gds_certificate_telemetry_read", "pki_validation", "LOW"},
		{"db connected", "gds_db_connected", "gds_db_connected", "system_health", "LOW"},
		{"db snapshot", "gds_db_snapshot", "gds_db_snapshot", "system_health", "LOW"},
		{"heartbeat", "gds_heartbeat", "gds_heartbeat", "system_health", "LOW"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			raw := []byte(fmt.Sprintf(`{"log_message":%q}`, tt.logMessage))
			ev, err := NormalizeGDSEvent(raw)
			if err != nil {
				t.Fatalf("NormalizeGDSEvent returned error: %v", err)
			}
			if ev.Message != tt.expected || ev.EventCategory != tt.category || ev.Severity != "info" {
				t.Fatalf("unexpected classification: %s %s %s", ev.Message, ev.EventCategory, ev.Severity)
			}
			if ev.Tags["gds_action"] != extractExpectedAction(tt.logMessage) {
				t.Fatalf("unexpected gds_action tag: %#v", ev.Tags["gds_action"])
			}
			if ev.Tags["risk_level"] != tt.risk {
				t.Fatalf("unexpected risk_level tag: %#v", ev.Tags["risk_level"])
			}
			if ev.Tags["gds_family"] == "" || ev.Tags["log_message"] != tt.logMessage || ev.Tags["parser_version"] != "v3.2.gds_pack_mapping" {
				t.Fatalf("expected parsed tags and original log message, got %#v", ev.Tags)
			}
		})
	}
}

func TestNormalizeGDSEventDMZUnknownAction(t *testing.T) {
	raw := []byte(`{"log_message":"gds_audit_event: unknown_new_event"}`)
	ev, err := NormalizeGDSEvent(raw)
	if err != nil {
		t.Fatalf("NormalizeGDSEvent returned error: %v", err)
	}
	if ev.Message != "gds_event_unknown" || ev.EventCategory != "operator_action" || ev.Severity != "info" {
		t.Fatalf("unexpected unknown classification: %s %s %s", ev.Message, ev.EventCategory, ev.Severity)
	}
	if ev.Tags["gds_action"] != "unknown_new_event" || ev.Tags["risk_level"] != "LOW" {
		t.Fatalf("unexpected unknown tags: %#v", ev.Tags)
	}
}

func TestNormalizeGDSEventDMZExtractsLogMessageFromRawVariants(t *testing.T) {
	tests := []struct {
		name       string
		payload    string
		expected   string
		expectedFM string
	}{
		{
			name:       "raw object",
			payload:    `{"raw":{"log_message":"gds_audit_event: trustlist_artifact_read"}}`,
			expected:   "gds_client_pull_success",
			expectedFM: "gds_audit_event",
		},
		{
			name:       "raw json string",
			payload:    `{"raw":"{\"log_message\":\"gds_audit_event: trustlist_artifact_sig_read\"}"}`,
			expected:   "gds_client_pull_success",
			expectedFM: "gds_audit_event",
		},
		{
			name:       "raw plain gds string",
			payload:    `{"raw":"gds_heartbeat"}`,
			expected:   "gds_heartbeat",
			expectedFM: "gds_runtime",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ev, err := NormalizeGDSEvent([]byte(tt.payload))
			if err != nil {
				t.Fatalf("NormalizeGDSEvent returned error: %v", err)
			}
			if ev.Message != tt.expected {
				t.Fatalf("unexpected message: %s", ev.Message)
			}
			if ev.Tags["gds_family"] != tt.expectedFM {
				t.Fatalf("unexpected gds_family: %#v", ev.Tags["gds_family"])
			}
		})
	}
}

func TestNormalizeGDSEventDMZDirectFamilyAction(t *testing.T) {
	tests := []struct {
		name     string
		family   string
		action   string
		message  string
		category string
	}{
		{"mtls success", "gds_audit_event", "mtls_client_identity_success", "gds_mtls_client_identity_success", "access_control"},
		{"agent auth success", "gds_audit_event", "agent_auth_success", "gds_agent_auth_success", "access_control"},
		{"trustlist read", "gds_audit_event", "trustlist_artifact_read", "gds_client_pull_success", "pki_trust_sync"},
		{"trustlist sig read", "gds_audit_event", "trustlist_artifact_sig_read", "gds_client_pull_success", "pki_trust_sync"},
		{"artifact regenerated", "gds_trust_list_published", "artifact_regenerated", "gds_trust_list_published", "pki_trust_sync"},
		{"db snapshot", "gds_runtime", "gds_db_snapshot", "gds_db_snapshot", "system_health"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			raw := []byte(fmt.Sprintf(`{"gds_family":%q,"gds_action":%q}`, tt.family, tt.action))
			ev, err := NormalizeGDSEvent(raw)
			if err != nil {
				t.Fatalf("NormalizeGDSEvent returned error: %v", err)
			}
			if ev.Message != tt.message || ev.EventCategory != tt.category {
				t.Fatalf("unexpected direct action mapping: got (%s,%s), want (%s,%s)", ev.Message, ev.EventCategory, tt.message, tt.category)
			}
			if ev.Tags["gds_family"] != tt.family || ev.Tags["gds_action"] != tt.action {
				t.Fatalf("expected family/action tags, got %#v", ev.Tags)
			}
		})
	}
}

func TestNormalizeGDSEventCompactActionFallbackShapes(t *testing.T) {
	tests := []struct {
		name    string
		payload string
		message string
	}{
		{
			name:    "top level gds action with unknown message",
			payload: `{"message":"gds_event_unknown","gds_action":"agent_auth_success","gds_family":"gds_audit_event"}`,
			message: "gds_agent_auth_success",
		},
		{
			name:    "raw object gds action",
			payload: `{"message":"gds_event_unknown","raw":{"gds_action":"mtls_client_identity_success","gds_family":"gds_audit_event"}}`,
			message: "gds_mtls_client_identity_success",
		},
		{
			name:    "raw string log message",
			payload: `{"message":"gds_event_unknown","raw":"{\"gds_action\":\"trustlist_artifact_sig_read\",\"gds_family\":\"gds_audit_event\"}"}`,
			message: "gds_client_pull_success",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ev, err := NormalizeGDSEvent([]byte(tt.payload))
			if err != nil {
				t.Fatalf("NormalizeGDSEvent returned error: %v", err)
			}
			if ev.Message != tt.message {
				t.Fatalf("expected %s, got %s", tt.message, ev.Message)
			}
			if ev.Tags["risk_level"] != "LOW" {
				t.Fatalf("expected LOW risk, got %#v", ev.Tags["risk_level"])
			}
		})
	}
}

func extractExpectedAction(logMessage string) string {
	parts := strings.SplitN(logMessage, ":", 2)
	if len(parts) == 2 {
		return strings.TrimSpace(parts[1])
	}
	return strings.TrimSpace(logMessage)
}

func TestNormalizeGDSEventCanonicalMappingsByEventType(t *testing.T) {
	tests := []struct {
		name      string
		eventType string
		message   string
		category  string
	}{
		{"gds_client_registered", "application_register", "gds_client_registered", "pki_lifecycle"},
		{"gds_enrollment_request_request_created", "certificate_request_created", "gds_enrollment_request", "pki_lifecycle"},
		{"gds_enrollment_request_renewal_requested", "certificate_renewal_requested", "gds_enrollment_request", "pki_lifecycle"},
		{"gds_enrollment_approved_csr_validated", "csr_validated", "gds_enrollment_approved", "pki_lifecycle"},
		{"gds_enrollment_approved_component_complete", "component_enrollment_completed", "gds_enrollment_approved", "pki_lifecycle"},
		{"gds_enrollment_failed_csr_rejected", "csr_rejected", "gds_enrollment_failed", "pki_lifecycle"},
		{"gds_enrollment_failed_issue_failed", "certificate_issue_failed", "gds_enrollment_failed", "pki_lifecycle"},
		{"gds_enrollment_failed_renewal_failed", "certificate_renewal_failed", "gds_enrollment_failed", "pki_lifecycle"},
		{"gds_certificate_issued", "certificate_issued", "gds_certificate_issued", "certificate_lifecycle"},
		{"gds_certificate_renewed", "certificate_renewal_packaged", "gds_certificate_renewed", "certificate_lifecycle"},
		{"gds_certificate_renewed_schema", "labshock_gds_component_renewal_result_v1", "gds_certificate_renewed", "certificate_lifecycle"},
		{"gds_certificate_revoked", "certificate_revoked", "gds_certificate_revoked", "certificate_lifecycle"},
		{"gds_certificate_revoked_crl_refreshed", "certificate_revocation_crl_refreshed", "gds_certificate_revoked", "certificate_lifecycle"},
		{"gds_certificate_revoked_package", "package_revoked", "gds_certificate_revoked", "certificate_lifecycle"},
		{"gds_trust_list_updated", "trustlist_build", "gds_trust_list_updated", "pki_trust_sync"},
		{"gds_trust_list_published_artifact", "artifact_regenerated", "gds_trust_list_published", "pki_trust_sync"},
		{"gds_trust_list_published_rebuild", "trustlist_artifact_rebuild", "gds_trust_list_published", "pki_trust_sync"},
		{"gds_client_pull_success_trustlist_read", "trustlist_artifact_read", "gds_client_pull_success", "pki_trust_sync"},
		{"gds_client_pull_success_material_read", "component_trust_material_read", "gds_client_pull_success", "pki_trust_sync"},
		{"gds_client_pull_success_manifest_read", "package_manifest_read", "gds_client_pull_success", "pki_trust_sync"},
		{"gds_client_pull_success_package_read", "certificate_package_read", "gds_client_pull_success", "pki_trust_sync"},
		{"gds_client_pull_success_component_trust_material_read", "component_trust_material_read", "gds_client_pull_success", "pki_trust_sync"},
		{"gds_vault_unsealed_detected", "vault_unsealed_detected", "gds_vault_unsealed_detected", "system_health"},
		{"gds_certificate_telemetry_read", "certificate_telemetry_read", "gds_certificate_telemetry_read", "pki_validation"},
		{"gds_trust_list_published_artifact_regenerated", "artifact_regenerated", "gds_trust_list_published", "pki_trust_sync"},
		{"gds_unauthorized_request_agent_auth_failure", "agent_auth_failure", "gds_unauthorized_request", "security"},
		{"gds_unauthorized_request_agent_unauthorized", "agent_unauthorized_pull", "gds_unauthorized_request", "security"},
		{"gds_unauthorized_request_mtls_failure", "mtls_client_identity_failure", "gds_unauthorized_request", "security"},
		{"gds_db_connected", "gds_db_connected", "gds_db_connected", "system_health"},
		{"gds_db_disconnected", "gds_db_disconnected", "gds_db_disconnected", "error"},
		{"gds_heartbeat", "gds_heartbeat", "gds_heartbeat", "system_health"},
		{"application_heartbeat", "application_heartbeat", "gds_heartbeat", "system_health"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			raw := []byte(fmt.Sprintf(`{"event_type":%q,"reported_at":"2026-05-18T13:06:00Z"}`, tt.eventType))
			ev, err := NormalizeGDSEvent(raw)
			if err != nil {
				t.Fatalf("NormalizeGDSEvent returned error: %v", err)
			}
			if ev.Message != tt.message || ev.EventCategory != tt.category {
				t.Fatalf("unexpected mapping: got (%s,%s) want (%s,%s)", ev.Message, ev.EventCategory, tt.message, tt.category)
			}
		})
	}
}

func TestNormalizeGDSEventCanonicalMappingsByHeuristics(t *testing.T) {
	tests := []struct {
		name     string
		payload  string
		message  string
		category string
	}{
		{
			name:     "startup bootstrap line",
			payload:  `{"msg":"gds bootstrap starting"}`,
			message:  "gds_started",
			category: "system_health",
		},
		{
			name:     "startup health transition ok",
			payload:  `{"msg":"health transition to ok"}`,
			message:  "gds_started",
			category: "system_health",
		},
		{
			name:     "enrollment endpoint request",
			payload:  `{"msg":"api request to /enrollment endpoint accepted"}`,
			message:  "gds_enrollment_request",
			category: "pki_lifecycle",
		},
		{
			name:     "enrollment approved from package creation after csr",
			payload:  `{"msg":"csr validated and package created"}`,
			message:  "gds_enrollment_approved",
			category: "pki_lifecycle",
		},
		{
			name:     "certificate expired telemetry state",
			payload:  `{"msg":"certificate telemetry expiry_state=expired"}`,
			message:  "gds_certificate_expired",
			category: "pki_validation",
		},
		{
			name:     "certificate expired drift report",
			payload:  `{"msg":"db drift report for certificate"}`,
			message:  "gds_certificate_expired",
			category: "pki_validation",
		},
		{
			name:     "trust list pull failed nginx 500",
			payload:  `{"msg":"nginx returned 500 on trustlist artifact endpoint"}`,
			message:  "gds_trust_list_pull_failed",
			category: "pki_trust_sync",
		},
		{
			name:     "trust list pull failed status code",
			payload:  `{"msg":"artifact endpoint failure","status_code":503}`,
			message:  "gds_trust_list_pull_failed",
			category: "pki_trust_sync",
		},
		{
			name:     "client pull failed by error_code",
			payload:  `{"msg":"api error","error_code":"upstream_error"}`,
			message:  "gds_client_pull_failed",
			category: "security",
		},
		{
			name:     "db connected preflight success",
			payload:  `{"msg":"startup preflight success"}`,
			message:  "gds_db_connected",
			category: "system_health",
		},
		{
			name:     "db disconnected preflight timeout",
			payload:  `{"msg":"startup preflight timeout error"}`,
			message:  "gds_db_disconnected",
			category: "error",
		},
		{
			name:     "heartbeat poll result",
			payload:  `{"msg":"periodic health poll result"}`,
			message:  "gds_heartbeat",
			category: "system_health",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ev, err := NormalizeGDSEvent([]byte(tt.payload))
			if err != nil {
				t.Fatalf("NormalizeGDSEvent returned error: %v", err)
			}
			if ev.Message != tt.message || ev.EventCategory != tt.category {
				t.Fatalf("unexpected mapping: got (%s,%s) want (%s,%s)", ev.Message, ev.EventCategory, tt.message, tt.category)
			}
		})
	}
}
