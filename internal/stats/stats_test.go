package stats

import (
	"testing"
	"time"

	"github.com/Abdoun1m/dmz_collector/internal/event"
)

func TestSummaryGroupsFirewallUnderCanonicalType(t *testing.T) {
	s := New()
	stamp := time.Now().UTC().Format(time.RFC3339Nano)
	s.Add(event.Event{
		Timestamp:     stamp,
		ReceivedAt:    stamp,
		SourceType:    "opnsense",
		Severity:      "warning",
		EventCategory: "security",
		AssetName:     "opnsense-fw",
		AssetIP:       "192.168.10.1",
		Tags: map[string]any{
			"splunk_sourcetype": "labshock:net:firewall",
		},
	})

	summary := s.Summary()
	bySourceType, ok := summary["by_source_type"].(map[string]int64)
	if !ok {
		t.Fatalf("expected by_source_type map, got %#v", summary["by_source_type"])
	}
	if bySourceType["firewall"] != 1 {
		t.Fatalf("expected firewall count 1, got %#v", bySourceType)
	}
	if _, exists := bySourceType["opnsense"]; exists {
		t.Fatalf("expected opnsense to be normalized away, got %#v", bySourceType)
	}
}