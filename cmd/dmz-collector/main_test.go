package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/Abdoun1m/dmz_collector/internal/config"
	"github.com/Abdoun1m/dmz_collector/internal/event"
	"github.com/Abdoun1m/dmz_collector/internal/sourcecatalog"
	"github.com/Abdoun1m/dmz_collector/internal/storage"
)

func newTestApp(t *testing.T) *App {
	t.Helper()
	base := t.TempDir()
	store := storage.NewJSONLStore(filepath.Join(base, "events.jsonl"))
	app := &App{
		cfg: config.Config{},
		store: store,
		stats: nil,
		sourceCatalog: sourcecatalog.New("http://ot.example"),
	}
	return app
}


func mockOTConfigServer(t *testing.T, payload any) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/config/sources" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(payload)
	}))
}

func TestSourcesFetchesOTConfigAndMergesDiscoveredData(t *testing.T) {
	otServer := mockOTConfigServer(t, []sourcecatalog.OTConfiguredSource{
		{ID: "plc1", Name: "PLC1", Type: "plc", IP: "192.168.1.20", Protocol: "syslog", Impact: "high", Zone: "L1/L2", Enabled: true, ForwardEnabled: true},
		{ID: "gds1", Name: "OT GDS Agent", Type: "gds-agent", IP: "192.168.1.30", Protocol: "http", Impact: "high", Zone: "OT", Enabled: true, ForwardEnabled: true},
	})
	defer otServer.Close()

	app := newTestApp(t)
	app.cfg.OTBaseURL = otServer.URL
	app.sourceCatalog.SetOTURL(otServer.URL)
	stamp := time.Now().UTC().Format(time.RFC3339Nano)
	app.sourceCatalog.ObserveEvent(event.Event{
		ID:            "evt-plc1",
		Timestamp:     stamp,
		ReceivedAt:    stamp,
		SourceType:    "plc",
		AssetIP:       "192.168.1.20",
		AssetName:     "PLC1",
		Severity:      "warning",
		EventCategory: "security",
		Message:       "alarm",
		Tags:          map[string]any{"splunk_sourcetype": "labshock:ot:plc"},
	})

	items := app.Sources()["sources"].([]sourcecatalog.SourceRecord)
	var plc1, gds sourcecatalog.SourceRecord
	for _, item := range items {
		switch item.ID {
		case "plc1":
			plc1 = item
		case "gds1":
			gds = item
		}
	}
	if plc1.ID != "plc1" || plc1.Name != "PLC1" || plc1.SourceType != "plc" || plc1.AssetIP != "192.168.1.20" || plc1.AssetName != "PLC1" || plc1.Impact != "high" || !plc1.Configured || !plc1.Discovered {
		t.Fatalf("unexpected PLC1 record: %#v", plc1)
	}
	if gds.SourceType != "gds_agent" || gds.SourceKey != "gds_agent:192.168.1.30" || !gds.Configured {
		t.Fatalf("unexpected GDS record: %#v", gds)
	}
}

func TestSourceDetailReturnsRecentEvents(t *testing.T) {
	app := newTestApp(t)
	app.sourceCatalog.MergeConfiguredSources([]sourcecatalog.OTConfiguredSource{
		{ID: "fw1", Name: "OPNsense OT Firewall", Type: "firewall", IP: "192.168.1.254", Protocol: "syslog", Impact: "high", Zone: "OT", Enabled: true, ForwardEnabled: true},
	})
	stamp := time.Now().UTC().Format(time.RFC3339Nano)
	for i, msg := range []string{"firewall_pass", "firewall_block"} {
		id := fmt.Sprintf("fw-evt-%d", i+1)
		app.store.Append(event.Event{
			ID:            id,
			Timestamp:     stamp,
			ReceivedAt:    stamp,
			SourceType:    "opnsense",
			AssetIP:       "192.168.1.254",
			AssetName:     "OPNsense OT Firewall",
			Severity:      "warning",
			EventCategory: "security",
			Message:       msg,
			Tags:          map[string]any{"splunk_sourcetype": "labshock:net:firewall"},
		})
		app.sourceCatalog.ObserveEvent(event.Event{
			ID:            id,
			Timestamp:     stamp,
			ReceivedAt:    stamp,
			SourceType:    "firewall",
			AssetIP:       "192.168.1.254",
			AssetName:     "OPNsense OT Firewall",
			Severity:      "warning",
			EventCategory: "security",
			Message:       msg,
			Tags:          map[string]any{"splunk_sourcetype": "labshock:net:firewall"},
		})
	}

	detail, ok := app.SourceDetail("firewall", "192.168.1.254", 5)
	if !ok {
		t.Fatal("expected firewall detail to exist")
	}
	recent := detail["recent_events"].([]map[string]any)
	if len(recent) == 0 {
		t.Fatal("expected recent events for firewall detail")
	}
	if recent[len(recent)-1]["message"] == "" {
		t.Fatalf("expected recent events to contain messages, got %#v", recent)
	}
}


func TestSourcesSummaryConfiguredCounts(t *testing.T) {
	otServer := mockOTConfigServer(t, []sourcecatalog.OTConfiguredSource{
		{ID: "plc1", Name: "PLC1", Type: "plc", IP: "192.168.1.20", Protocol: "syslog", Impact: "high", Zone: "L1/L2", Enabled: true, ForwardEnabled: true},
		{ID: "plc2", Name: "PLC2", Type: "plc", IP: "192.168.1.21", Protocol: "syslog", Impact: "high", Zone: "L1/L2", Enabled: true, ForwardEnabled: true},
		{ID: "plc3", Name: "PLC3", Type: "plc", IP: "192.168.1.22", Protocol: "syslog", Impact: "high", Zone: "L1/L2", Enabled: true, ForwardEnabled: true},
		{ID: "plc4", Name: "PLC4", Type: "plc", IP: "192.168.1.23", Protocol: "syslog", Impact: "high", Zone: "L1/L2", Enabled: true, ForwardEnabled: true},
		{ID: "plc5", Name: "PLC5", Type: "plc", IP: "192.168.1.24", Protocol: "syslog", Impact: "high", Zone: "L1/L2", Enabled: true, ForwardEnabled: true},
	})
	defer otServer.Close()

	app := newTestApp(t)
	app.cfg.OTBaseURL = otServer.URL
	app.sourceCatalog.SetOTURL(otServer.URL)
	summary := app.SourcesSummary()
	byGroup := summary["by_group"].(map[string]sourcecatalog.GroupSummary)
	if byGroup["PLCs"].ConfiguredCount != 5 {
		t.Fatalf("expected PLCs configured count 5, got %#v", byGroup["PLCs"])
	}
}