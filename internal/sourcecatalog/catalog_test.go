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

	snap := c.Snapshot()
	if snap.TotalSources != 1 {
		t.Fatalf("expected 1 source, got %d", snap.TotalSources)
	}
	if len(snap.Sources) != 1 {
		t.Fatalf("expected 1 source record, got %d", len(snap.Sources))
	}
	if snap.Sources[0].SourceType != "firewall" {
		t.Fatalf("expected source_type firewall, got %q", snap.Sources[0].SourceType)
	}
	summary := c.Summary()
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
	snap := c.Snapshot()
	var influx, collector SourceRecord
	for _, rec := range snap.Sources {
		switch rec.Name {
		case "InfluxDB":
			influx = rec
		case "OT Collector":
			collector = rec
		}
	}
	if influx.SourceType != "influxdb" || influx.Group != "DMZ Services" || influx.Zone != "DMZ" {
		t.Fatalf("unexpected InfluxDB record: %#v", influx)
	}
	if collector.SourceType != "collector" || collector.Group != "DMZ Services" || collector.Zone != "DMZ" {
		t.Fatalf("unexpected OT Collector record: %#v", collector)
	}
}