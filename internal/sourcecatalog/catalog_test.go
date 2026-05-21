package sourcecatalog

import (
	"testing"
	"time"

	"github.com/Abdoun1m/dmz_collector/internal/config"
	"github.com/Abdoun1m/dmz_collector/internal/event"
)

func TestObserveEventNormalizesFirewallForSources(t *testing.T) {
	c := New("http://ot.example")
	stamp := time.Now().UTC().Format(time.RFC3339Nano)
	c.ObserveEvent(event.Event{
		ID:            "evt-1",
		Timestamp:     stamp,
		ReceivedAt:    stamp,
		SourceType:    "opnsense",
		AssetIP:       "192.168.10.1",
		AssetName:     "opnsense-fw",
		EventCategory: "security",
		Tags:          map[string]any{},
	})

	snap := c.Snapshot(VisibilityOptions{})
	if snap.TotalSources != 1 {
		t.Fatalf("expected 1 source, got %d", snap.TotalSources)
	}
	if len(snap.Sources) != 1 {
		t.Fatalf("expected 1 source record, got %d", len(snap.Sources))
	}
	if snap.Sources[0].SourceType != "firewall" {
		t.Fatalf("expected source_type firewall, got %q", snap.Sources[0].SourceType)
	}
	summary := c.Summary(VisibilityOptions{})
	if summary.BySourceType["firewall"] != 1 {
		t.Fatalf("expected firewall source_type summary count 1, got %#v", summary.BySourceType)
	}
	if summary.BySourceType["opnsense"] != 0 {
		t.Fatalf("expected opnsense not to be counted separately, got %#v", summary.BySourceType)
	}
}

func TestSeedConfiguredSourcesMapsDMZServices(t *testing.T) {
	c := New("http://ot.example")
	c.SeedConfiguredSources(config.DefaultSources())
	defaultSnap := c.Snapshot(VisibilityOptions{})
	for _, rec := range defaultSnap.Sources {
		if rec.Name == "InfluxDB" || rec.Name == "OT Collector" || rec.Name == "Firewall Future" {
			t.Fatalf("did not expect internal source in default snapshot: %#v", rec)
		}
	}
	snap := c.Snapshot(VisibilityOptions{IncludeInternal: true, IncludeDisabled: true, IncludeDirectSIEM: true})
	var influx SourceRecord
	for _, rec := range snap.Sources {
		switch rec.Name {
		case "InfluxDB":
			influx = rec
		case "OT Collector", "Firewall Future":
			t.Fatalf("did not expect support-only source in visible catalog: %#v", rec)
		}
	}
	if influx.SourceType != "influxdb" || influx.Group != "DMZ Services" || influx.Zone != "DMZ" {
		t.Fatalf("unexpected InfluxDB record: %#v", influx)
	}
	visible := c.Snapshot(VisibilityOptions{IncludeInternal: true, IncludeDisabled: true, IncludeDirectSIEM: true})
	if visible.VisibleSources == 0 {
		t.Fatal("expected visible sources when internal services are included")
	}
}
