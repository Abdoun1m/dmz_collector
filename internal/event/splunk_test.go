package event

import "testing"

func TestBuildSplunkPayloadUsesCanonicalFallback(t *testing.T) {
	payload := BuildSplunkPayload(Event{
		Timestamp:  "2026-05-16T16:00:00Z",
		Source:     "event-source",
		SourceType: "firewall",
		Tags: map[string]any{
			"siem_index_hint":    "ot-gds-agent",
			"splunk_sourcetype": "labshock:ot:unknown",
		},
	}, "labshock_dmz_collector", "ot_security")

	if payload.Sourcetype != "labshock:net:firewall" {
		t.Fatalf("expected canonical firewall sourcetype, got %q", payload.Sourcetype)
	}
	if payload.Index != "ot_security" {
		t.Fatalf("expected default ot_security index, got %q", payload.Index)
	}
	if payload.Source != "labshock_dmz_collector" {
		t.Fatalf("expected configured source, got %q", payload.Source)
	}
}