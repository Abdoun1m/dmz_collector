package event

import "testing"

func TestBuildSplunkPayloadUsesCanonicalFallback(t *testing.T) {
	payload := BuildSplunkPayload(Event{
		Timestamp:  "2026-05-16T16:00:00Z",
		SourceType: "firewall",
		Tags: map[string]any{
			"splunk_sourcetype": "labshock:ot:unknown",
		},
	}, "labshock", "ot_security")

	if payload.Sourcetype != "labshock:net:firewall" {
		t.Fatalf("expected canonical firewall sourcetype, got %q", payload.Sourcetype)
	}
}