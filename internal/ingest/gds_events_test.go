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
	if ev.Tags["splunk_sourcetype"] != "labshock:dmz:gds" || ev.Tags["parser_version"] != "v3.gds_dmz_normalization" {
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
	if ev.Tags["parser_version"] != "v3.gds_dmz_normalization" {
		t.Fatalf("expected parser version v3, got %#v", ev.Tags["parser_version"])
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
	if ev.Message != "gds_unauthorized_request" || ev.EventCategory != "access_control" || ev.Severity != "warning" {
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
	if ev.Message != "gds_db_disconnected" || ev.EventCategory != "system_health" || ev.Severity != "error" {
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
	if ev.Message != "gds_db_connected" || ev.EventCategory != "system_health" || ev.Severity != "info" {
		t.Fatalf("unexpected DB snapshot classification: %s %s %s", ev.Message, ev.EventCategory, ev.Severity)
	}
	if ev.Tags["gds_action"] != "gds_db_snapshot" {
		t.Fatalf("DB snapshot should preserve action tag: %#v", ev.Tags)
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
		{"gds_db_disconnected", "gds_db_disconnected", "system_health", "error", true},
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
		{"certificate drift read", "gds_audit_event: certificate_drift_read", "gds_client_pull_success", "pki_validation", "LOW"},
		{"certificate telemetry read", "gds_audit_event: certificate_telemetry_read", "gds_client_pull_success", "pki_validation", "LOW"},
		{"db connected", "gds_db_connected", "gds_db_connected", "system_health", "LOW"},
		{"db snapshot", "gds_db_snapshot", "gds_db_connected", "system_health", "LOW"},
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
				if ev.Tags["gds_family"] == "" || ev.Tags["log_message"] != tt.logMessage || ev.Tags["parser_version"] != "v3.gds_dmz_normalization" {
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
	if ev.Message != "gds_event_unknown" || ev.EventCategory != "system" || ev.Severity != "info" {
		t.Fatalf("unexpected unknown classification: %s %s %s", ev.Message, ev.EventCategory, ev.Severity)
	}
	if ev.Tags["gds_action"] != "unknown_new_event" || ev.Tags["risk_level"] != "MEDIUM" {
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
		{"gds_client_registered", "application_register", "gds_client_registered", "access_control"},
		{"gds_enrollment_request_request_created", "certificate_request_created", "gds_enrollment_request", "certificate_lifecycle"},
		{"gds_enrollment_request_renewal_requested", "certificate_renewal_requested", "gds_enrollment_request", "certificate_lifecycle"},
		{"gds_enrollment_approved_csr_validated", "csr_validated", "gds_enrollment_approved", "certificate_lifecycle"},
		{"gds_enrollment_approved_component_complete", "component_enrollment_completed", "gds_enrollment_approved", "certificate_lifecycle"},
		{"gds_enrollment_failed_csr_rejected", "csr_rejected", "gds_enrollment_failed", "certificate_lifecycle"},
		{"gds_enrollment_failed_issue_failed", "certificate_issue_failed", "gds_enrollment_failed", "certificate_lifecycle"},
		{"gds_enrollment_failed_renewal_failed", "certificate_renewal_failed", "gds_enrollment_failed", "certificate_lifecycle"},
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
		{"gds_unauthorized_request_agent_auth_failure", "agent_auth_failure", "gds_unauthorized_request", "access_control"},
		{"gds_unauthorized_request_agent_unauthorized", "agent_unauthorized_pull", "gds_unauthorized_request", "access_control"},
		{"gds_unauthorized_request_mtls_failure", "mtls_client_identity_failure", "gds_unauthorized_request", "access_control"},
		{"gds_db_connected", "gds_db_connected", "gds_db_connected", "system_health"},
		{"gds_db_disconnected", "gds_db_disconnected", "gds_db_disconnected", "system_health"},
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
			category: "certificate_lifecycle",
		},
		{
			name:     "enrollment approved from package creation after csr",
			payload:  `{"msg":"csr validated and package created"}`,
			message:  "gds_enrollment_approved",
			category: "certificate_lifecycle",
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
			category: "access_control",
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
			category: "system_health",
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
