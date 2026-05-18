package ingest

import (
	"strings"
	"testing"
)

func TestNormalizeOPCUADMZTrustPullSuccess(t *testing.T) {
	raw := []byte(`{
		"source_type":"opcua_dmz_gateway",
		"sourcetype":"labshock:dmz:opcua_gateway",
		"zone":"DMZ",
		"asset_name":"opcua_dmz_gateway",
		"asset_ip":"192.168.10.20",
		"protocol":"opcua",
		"source":"opcua_dmz_gateway",
		"message":"opcua_dmz_gds_trust_pull_success",
		"event_category":"pki_trust_sync",
		"severity":"info",
		"raw":{
			"event_type":"trust_pull_completed",
			"target":"dmz-gateway-client",
			"application_uri":"urn:dataprotect:opcua:dmz-gateway-client",
			"status":"completed"
		}
	}`)
	ev, err := NormalizeOPCUADMZEvent(raw)
	if err != nil {
		t.Fatalf("NormalizeOPCUADMZEvent returned error: %v", err)
	}
	if ev.SourceType != "opcua_dmz_gateway" || ev.Source != "opcua_dmz_gateway" || ev.AssetIP != "192.168.10.20" || ev.Protocol != "opcua" {
		t.Fatalf("unexpected identity: %#v", ev)
	}
	if ev.Message != "opcua_dmz_gds_trust_pull_success" || ev.EventCategory != "pki_trust_sync" || ev.Severity != "info" {
		t.Fatalf("unexpected classification: %s %s %s", ev.Message, ev.EventCategory, ev.Severity)
	}
	if ev.Tags["splunk_sourcetype"] != "labshock:dmz:opcua_gateway" || ev.Tags["parser_version"] != "v1.opcua_dmz_normalization" || ev.Tags["risk_level"] != "LOW" {
		t.Fatalf("unexpected tags: %#v", ev.Tags)
	}
	if ev.Tags["alert_candidate"] != nil {
		t.Fatalf("info trust pull success should not be alert candidate: %#v", ev.Tags)
	}
}

func TestNormalizeOPCUADMZSouthboundConnectFailed(t *testing.T) {
	raw := []byte(`{
		"source_type":"opcua_dmz_gateway",
		"raw":{
			"event_type":"southbound_connect_failed",
			"endpoint":"opc.tcp://192.168.1.62:4840",
			"status_name":"BadSecurityChecksFailed"
		}
	}`)
	ev, err := NormalizeOPCUADMZEvent(raw)
	if err != nil {
		t.Fatalf("NormalizeOPCUADMZEvent returned error: %v", err)
	}
	if ev.Message != "opcua_dmz_southbound_connect_failed" || ev.EventCategory != "opcua_session" || ev.Severity != "warning" {
		t.Fatalf("unexpected classification: %s %s %s", ev.Message, ev.EventCategory, ev.Severity)
	}
	if ev.Tags["alert_candidate"] != true || ev.Tags["risk_level"] != "MEDIUM" {
		t.Fatalf("expected warning alert candidate with medium risk, got %#v", ev.Tags)
	}
	if !strings.Contains(ev.Raw, "BadSecurityChecksFailed") || !strings.Contains(ev.Raw, "opc.tcp://192.168.1.62:4840") {
		t.Fatalf("expected safe raw fields preserved, got %s", ev.Raw)
	}
}

func TestNormalizeOPCUADMZPKIFailure(t *testing.T) {
	ev, err := NormalizeOPCUADMZEvent([]byte(`{"message":"opcua_dmz_pki_load_failed","raw":{"cert_path":"/etc/pki/client.crt","key_path":"/etc/pki/client.key"}}`))
	if err != nil {
		t.Fatalf("NormalizeOPCUADMZEvent returned error: %v", err)
	}
	if ev.EventCategory != "pki_validation" || ev.Severity != "critical" || ev.Tags["risk_level"] != "HIGH" || ev.Tags["alert_candidate"] != true {
		t.Fatalf("unexpected pki failure classification: %#v %#v", ev, ev.Tags)
	}
	if !strings.Contains(ev.Raw, "cert_path") || !strings.Contains(ev.Raw, "key_path") {
		t.Fatalf("expected path metadata preserved, got %s", ev.Raw)
	}
}

func TestNormalizeOPCUADMZStartupAndHeartbeat(t *testing.T) {
	tests := []struct {
		payload string
		message string
	}{
		{`{"raw":{"event_type":"started"}}`, "opcua_dmz_started"},
		{`{"raw":{"event_type":"heartbeat"}}`, "opcua_dmz_heartbeat"},
	}
	for _, tt := range tests {
		t.Run(tt.message, func(t *testing.T) {
			ev, err := NormalizeOPCUADMZEvent([]byte(tt.payload))
			if err != nil {
				t.Fatalf("NormalizeOPCUADMZEvent returned error: %v", err)
			}
			if ev.Message != tt.message || ev.EventCategory != "system_health" || ev.Severity != "info" {
				t.Fatalf("unexpected classification: %s %s %s", ev.Message, ev.EventCategory, ev.Severity)
			}
		})
	}
}

func TestNormalizeOPCUADMZManyAcceptsArrayJSONLAndText(t *testing.T) {
	events, err := NormalizeOPCUADMZEventsMany([]byte(`[
		{"raw":{"event_type":"trust_pull_completed"}},
		{"raw":{"event_type":"southbound_connect_failed"}}
	]`))
	if err != nil {
		t.Fatalf("array payload failed: %v", err)
	}
	if len(events) != 2 {
		t.Fatalf("expected 2 events, got %d", len(events))
	}

	events, err = NormalizeOPCUADMZEventsMany([]byte("{\"raw\":{\"event_type\":\"heartbeat\"}}\nplain southbound connect failed line\n"))
	if err != nil {
		t.Fatalf("jsonl/text payload failed: %v", err)
	}
	if len(events) != 2 || events[1].Message != "opcua_dmz_southbound_connect_failed" {
		t.Fatalf("unexpected jsonl/text events: %#v", events)
	}
}

func TestNormalizeOPCUADMZRedactsSensitiveFields(t *testing.T) {
	raw := []byte(`{
		"raw":{
			"event_type":"pki_load_failed",
			"token":"Bearer abc",
			"password":"secret",
			"role_id":"role",
			"secret_id":"sid",
			"private_key":"-----BEGIN PRIVATE KEY-----abc",
			"certificate_pem":"-----BEGIN CERTIFICATE-----abc",
			"csr":"-----BEGIN CERTIFICATE REQUEST-----abc",
			"crl_body":"abc",
			"ca_chain":"abc",
			"signature":"abc",
			"cert_path":"/safe/client.crt",
			"key_path":"/safe/client.key",
			"private_key_found":true
		}
	}`)
	ev, err := NormalizeOPCUADMZEvent(raw)
	if err != nil {
		t.Fatalf("NormalizeOPCUADMZEvent returned error: %v", err)
	}
	for _, forbidden := range []string{"Bearer abc", "password", "role", "sid", "BEGIN PRIVATE KEY", "BEGIN CERTIFICATE", "CERTIFICATE REQUEST", "ca_chain", "signature"} {
		if strings.Contains(ev.Raw, forbidden) {
			t.Fatalf("sensitive value/key %q leaked in raw: %s", forbidden, ev.Raw)
		}
	}
	if !strings.Contains(ev.Raw, "cert_path") || !strings.Contains(ev.Raw, "key_path") || !strings.Contains(ev.Raw, "private_key_found") {
		t.Fatalf("safe metadata should remain, got %s", ev.Raw)
	}
}
