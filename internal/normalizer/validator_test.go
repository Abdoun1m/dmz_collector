package normalizer

import (
	"testing"
	"time"

	"github.com/Abdoun1m/dmz_collector/internal/event"
)

func TestValidateAndNormalizeFirewallCanonicalization(t *testing.T) {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	ev, err := ValidateAndNormalize(event.Event{
		Timestamp:     now,
		ReceivedAt:    now,
		SourceType:    "opnsense",
		Message:       "firewall_pass",
		Raw:           "<134>1 firewall",
		EventCategory: "security",
		Tags:          map[string]any{},
	})
	if err != nil {
		t.Fatalf("ValidateAndNormalize returned error: %v", err)
	}
	if ev.SourceType != "firewall" {
		t.Fatalf("expected source_type firewall, got %q", ev.SourceType)
	}
	if ev.Tags["splunk_sourcetype"] != "labshock:net:firewall" {
		t.Fatalf("expected firewall sourcetype, got %#v", ev.Tags["splunk_sourcetype"])
	}
	if ev.Tags["firewall_vendor"] != "opnsense" {
		t.Fatalf("expected firewall vendor opnsense, got %#v", ev.Tags["firewall_vendor"])
	}
	if ev.Tags["siem_index_hint"] != "ot_security" {
		t.Fatalf("expected siem_index_hint ot_security, got %#v", ev.Tags["siem_index_hint"])
	}
}

func TestValidateAndNormalizeGDSAgentCanonicalization(t *testing.T) {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	ev, err := ValidateAndNormalize(event.Event{
		Timestamp:  now,
		ReceivedAt: now,
		SourceType: "gds-agent",
		Tags:       map[string]any{},
	})
	if err != nil {
		t.Fatalf("ValidateAndNormalize returned error: %v", err)
	}
	if ev.SourceType != "gds_agent" {
		t.Fatalf("expected source_type gds_agent, got %q", ev.SourceType)
	}
}