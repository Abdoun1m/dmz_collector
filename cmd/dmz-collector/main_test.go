package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/Abdoun1m/dmz_collector/internal/api"
	"github.com/Abdoun1m/dmz_collector/internal/buffer"
	"github.com/Abdoun1m/dmz_collector/internal/config"
	"github.com/Abdoun1m/dmz_collector/internal/event"
	"github.com/Abdoun1m/dmz_collector/internal/forwarder"
	"github.com/Abdoun1m/dmz_collector/internal/sourcecatalog"
	"github.com/Abdoun1m/dmz_collector/internal/stats"
	"github.com/Abdoun1m/dmz_collector/internal/storage"
)

func newTestApp(t *testing.T) *App {
	t.Helper()
	base := t.TempDir()
	store := storage.NewJSONLStore(filepath.Join(base, "events.jsonl"))
	fwdStore, err := config.NewForwardingStore(filepath.Join(base, "forwarding.json"), config.Config{})
	if err != nil {
		t.Fatalf("failed to create forwarding store: %v", err)
	}
	app := &App{
		cfg:           config.Config{},
		store:         store,
		spool:         buffer.NewSpool(filepath.Join(base, "spool", "events.jsonl")),
		queue:         buffer.NewQueue(100),
		stats:         stats.New(),
		streamHub:     api.NewStreamHub(),
		fwdStore:      fwdStore,
		splunkFwd:     forwarder.NewSplunkHECForwarder(false, 2*time.Second),
		sourceCatalog: sourcecatalog.New("http://ot.example"),
		seenIDs:       map[string]struct{}{},
		inflight:      map[string]struct{}{},
		offsetByID:    map[string]int64{},
		startedAt:     time.Now().UTC().Format(time.RFC3339Nano),
	}
	return app
}

type hecCapture struct {
	mu      sync.Mutex
	bodies  []map[string]any
	requests int
}

func newMockHECServer(t *testing.T, status int) (*httptest.Server, *hecCapture) {
	t.Helper()
	capture := &hecCapture{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capture.mu.Lock()
		defer capture.mu.Unlock()
		capture.requests++
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		capture.bodies = append(capture.bodies, body)
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(map[string]any{"text": "Success", "code": 0})
	}))
	return server, capture
}

func waitForRequests(t *testing.T, capture *hecCapture, want int, timeout time.Duration) []map[string]any {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		capture.mu.Lock()
		requests := capture.requests
		bodies := append([]map[string]any(nil), capture.bodies...)
		capture.mu.Unlock()
		if requests >= want {
			return bodies
		}
		time.Sleep(20 * time.Millisecond)
	}
	capture.mu.Lock()
	bodies := append([]map[string]any(nil), capture.bodies...)
	capture.mu.Unlock()
	t.Fatalf("timed out waiting for %d hec requests", want)
	return bodies
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
		{ID: "plc2", Name: "PLC2", Type: "plc", IP: "192.168.1.21", Protocol: "syslog", Impact: "high", Zone: "L1/L2", Enabled: true, ForwardEnabled: true},
		{ID: "plc3", Name: "PLC3", Type: "plc", IP: "192.168.1.22", Protocol: "syslog", Impact: "high", Zone: "L1/L2", Enabled: true, ForwardEnabled: true},
		{ID: "plc4", Name: "PLC4", Type: "plc", IP: "192.168.1.23", Protocol: "syslog", Impact: "high", Zone: "L1/L2", Enabled: true, ForwardEnabled: true},
		{ID: "plc5", Name: "PLC5", Type: "plc", IP: "192.168.1.24", Protocol: "syslog", Impact: "high", Zone: "L1/L2", Enabled: true, ForwardEnabled: true},
		{ID: "fuxa1", Name: "FUXA SCADA", Type: "scada", IP: "192.168.1.40", Protocol: "http", Impact: "medium", Zone: "L2", Enabled: true, ForwardEnabled: true},
		{ID: "opcua1", Name: "OPC UA Server", Type: "opcua", IP: "192.168.1.50", Protocol: "opcua", Impact: "medium", Zone: "L2", Enabled: true, ForwardEnabled: true},
		{ID: "gds1", Name: "OT GDS Agent", Type: "gds-agent", IP: "192.168.1.30", Protocol: "http", Impact: "high", Zone: "OT", Enabled: true, ForwardEnabled: true},
		{ID: "ews1", Name: "EWS", Type: "ews", IP: "192.168.1.60", Protocol: "syslog", Impact: "medium", Zone: "L2", Enabled: true, ForwardEnabled: true},
		{ID: "fw1", Name: "OPNsense OT Firewall", Type: "firewall", IP: "192.168.1.254", Protocol: "syslog", Impact: "high", Zone: "OT", Enabled: true, ForwardEnabled: true},
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

	sources := app.Sources()
	items := sources["sources"].([]sourcecatalog.SourceRecord)
	if sources["visible_sources"] != 10 {
		t.Fatalf("expected 10 visible sources, got %#v", sources["visible_sources"])
	}
	if sources["hidden_sources"] == 0 {
		t.Fatalf("expected hidden internal sources, got %#v", sources)
	}
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
	for _, item := range items {
		if item.Group == "DMZ Services" {
			t.Fatalf("did not expect DMZ Services in default sources: %#v", item)
		}
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
	if _, ok := byGroup["DMZ Services"]; ok {
		t.Fatalf("did not expect DMZ Services in default summary: %#v", byGroup["DMZ Services"])
	}
}

func TestInternalSourcesOnlyExposeDMZSupportSources(t *testing.T) {
	otServer := mockOTConfigServer(t, []sourcecatalog.OTConfiguredSource{
		{ID: "plc1", Name: "PLC1", Type: "plc", IP: "192.168.1.20", Protocol: "syslog", Impact: "high", Zone: "L1/L2", Enabled: true, ForwardEnabled: true},
		{ID: "plc2", Name: "PLC2", Type: "plc", IP: "192.168.1.21", Protocol: "syslog", Impact: "high", Zone: "L1/L2", Enabled: true, ForwardEnabled: true},
		{ID: "plc3", Name: "PLC3", Type: "plc", IP: "192.168.1.22", Protocol: "syslog", Impact: "high", Zone: "L1/L2", Enabled: true, ForwardEnabled: true},
		{ID: "plc4", Name: "PLC4", Type: "plc", IP: "192.168.1.23", Protocol: "syslog", Impact: "high", Zone: "L1/L2", Enabled: true, ForwardEnabled: true},
		{ID: "plc5", Name: "PLC5", Type: "plc", IP: "192.168.1.24", Protocol: "syslog", Impact: "high", Zone: "L1/L2", Enabled: true, ForwardEnabled: true},
		{ID: "fuxa1", Name: "FUXA SCADA", Type: "scada", IP: "192.168.1.40", Protocol: "http", Impact: "medium", Zone: "L2", Enabled: true, ForwardEnabled: true},
		{ID: "opcua1", Name: "OPC UA Server", Type: "opcua", IP: "192.168.1.50", Protocol: "opcua", Impact: "medium", Zone: "L2", Enabled: true, ForwardEnabled: true},
		{ID: "gds1", Name: "OT GDS Agent", Type: "gds-agent", IP: "192.168.1.30", Protocol: "http", Impact: "high", Zone: "OT", Enabled: true, ForwardEnabled: true},
		{ID: "ews1", Name: "EWS", Type: "ews", IP: "192.168.1.60", Protocol: "syslog", Impact: "medium", Zone: "L2", Enabled: true, ForwardEnabled: true},
		{ID: "fw1", Name: "OPNsense OT Firewall", Type: "firewall", IP: "192.168.1.254", Protocol: "syslog", Impact: "high", Zone: "OT", Enabled: true, ForwardEnabled: true},
		{ID: "idsfuture", Name: "Future IDS", Type: "ids", IP: "192.168.1.70", Protocol: "syslog", Impact: "high", Zone: "DMZ", Enabled: true, ForwardEnabled: true},
	})
	defer otServer.Close()

	app := newTestApp(t)
	app.cfg.OTBaseURL = otServer.URL
	app.sourceCatalog.SetOTURL(otServer.URL)
	app.initSources()
	internal := app.InternalSources()
	items := internal["sources"].([]sourcecatalog.SourceRecord)
	if len(items) == 0 {
		t.Fatal("expected internal sources")
	}
	for _, item := range items {
		switch item.Name {
		case "OT Collector", "DMZ Collector", "InfluxDB", "OPC UA DMZ Gateway", "Vault", "Vault Agent", "LabShock GDS", "PostgreSQL GDS", "Jump Host", "Firewall Future", "IDS Future":
		default:
			t.Fatalf("unexpected record in internal sources: %#v", item)
		}
		if item.Name == "PLC1" || item.Name == "PLC2" || item.Name == "PLC3" || item.Name == "PLC4" || item.Name == "PLC5" || item.Name == "OPNsense OT Firewall" || item.Name == "OT GDS Agent" || item.Name == "OPC UA Server" || item.Name == "EWS" || item.Name == "FUXA SCADA" {
			t.Fatalf("unexpected operational source in internal sources: %#v", item)
		}
	}
	if _, ok := internal["sources"].([]sourcecatalog.SourceRecord); !ok {
		t.Fatal("expected source list in internal sources response")
	}
}

func TestIngestStoresLocallyWithoutSplunk(t *testing.T) {
	app := newTestApp(t)
	app.cfg.Splunk = config.SplunkConfig{Enabled: false, URL: "http://127.0.0.1:65535/services/collector", Token: "test", Index: "ot_security", Source: "labshock_dmz_collector", VerifyTLS: false}
	app.streamHub = api.NewStreamHub()
	evt := event.Event{
		ID:            "no-splunk-1",
		Timestamp:     time.Now().UTC().Format(time.RFC3339Nano),
		ReceivedAt:    time.Now().UTC().Format(time.RFC3339Nano),
		SourceType:    "gds-agent",
		AssetIP:       "192.168.1.30",
		AssetName:     "OT GDS Agent",
		Severity:      "warning",
		EventCategory: "security",
		Message:       "local only",
		Tags:          map[string]any{"splunk_sourcetype": "labshock:ot:gds"},
	}
	if err := app.IngestSingle(evt); err != nil {
		t.Fatalf("ingest failed: %v", err)
	}
	stored, err := app.ReadEvents(storage.EventQuery{Limit: 10})
	if err != nil {
		t.Fatalf("failed to read stored events: %v", err)
	}
	if len(stored) != 1 {
		t.Fatalf("expected one stored event, got %d", len(stored))
	}
	if got := app.StatsSummary()["splunk_success_count"].(int64); got != 0 {
		t.Fatalf("expected no splunk sends, got %d", got)
	}
	if got := app.StatsSummary()["splunk_failed_count"].(int64); got != 0 {
		t.Fatalf("expected no splunk failures, got %d", got)
	}
}

func TestIngestForwardsToSplunkAsync(t *testing.T) {
	hecServer, capture := newMockHECServer(t, http.StatusOK)
	defer hecServer.Close()

	app := newTestApp(t)
	app.cfg.Splunk = config.SplunkConfig{Enabled: true, URL: hecServer.URL, Token: "11111111-2222-3333-4444-555555555555", Index: "ot_security", Source: "labshock_dmz_collector", VerifyTLS: false}
	app.streamHub = api.NewStreamHub()
	evt := event.Event{
		ID:            "splunk-async-1",
		Timestamp:     time.Now().UTC().Format(time.RFC3339Nano),
		ReceivedAt:    time.Now().UTC().Format(time.RFC3339Nano),
		SourceType:    "gds-agent",
		AssetIP:       "192.168.1.30",
		AssetName:     "OT GDS Agent",
		Severity:      "warning",
		EventCategory: "security",
		Message:       "forward to splunk",
		Tags:          map[string]any{"splunk_sourcetype": "labshock:ot:gds"},
	}
	if err := app.IngestSingle(evt); err != nil {
		t.Fatalf("ingest failed: %v", err)
	}
	bodies := waitForRequests(t, capture, 1, 3*time.Second)
	if len(bodies) != 1 {
		t.Fatalf("expected one hec payload, got %d", len(bodies))
	}
	payload := bodies[0]
	if payload["index"] != "ot_security" {
		t.Fatalf("expected ot_security index, got %#v", payload["index"])
	}
	if payload["sourcetype"] != "labshock:ot:gds" {
		t.Fatalf("expected labshock:ot:gds sourcetype, got %#v", payload["sourcetype"])
	}
	eventBody, ok := payload["event"].(map[string]any)
	if !ok {
		t.Fatalf("expected event object, got %#v", payload["event"])
	}
	if eventBody["id"] != "splunk-async-1" || eventBody["source_type"] != "gds_agent" || eventBody["asset_ip"] != "192.168.1.30" || eventBody["message"] != "forward to splunk" {
		t.Fatalf("unexpected event body: %#v", eventBody)
	}
	statsSummary := app.StatsSummary()
	if got := statsSummary["splunk_success_count"].(int64); got != 1 {
		t.Fatalf("expected one splunk success, got %d", got)
	}
	if got := statsSummary["splunk_failed_count"].(int64); got != 0 {
		t.Fatalf("expected zero splunk failures, got %d", got)
	}
}

func TestIngestRecordsSplunkFailure(t *testing.T) {
	app := newTestApp(t)
	app.cfg.Splunk = config.SplunkConfig{Enabled: true, URL: "http://127.0.0.1:65534/services/collector", Token: "test", Index: "ot_security", Source: "labshock_dmz_collector", VerifyTLS: false}
	app.streamHub = api.NewStreamHub()
	evt := event.Event{
		ID:            "splunk-fail-1",
		Timestamp:     time.Now().UTC().Format(time.RFC3339Nano),
		ReceivedAt:    time.Now().UTC().Format(time.RFC3339Nano),
		SourceType:    "firewall",
		AssetIP:       "192.168.10.1",
		AssetName:     "OPNsense OT Firewall",
		Severity:      "warning",
		EventCategory: "security",
		Message:       "forward failure",
		Tags:          map[string]any{"splunk_sourcetype": "labshock:net:firewall"},
	}
	if err := app.IngestSingle(evt); err != nil {
		t.Fatalf("ingest failed: %v", err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if app.StatsSummary()["splunk_failed_count"].(int64) == 1 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	statsSummary := app.StatsSummary()
	if got := statsSummary["splunk_failed_count"].(int64); got != 1 {
		t.Fatalf("expected one splunk failure, got %d", got)
	}
	if got := statsSummary["splunk_last_error"].(string); got == "" {
		t.Fatalf("expected last splunk error to be recorded, got empty string")
	}
	if got := statsSummary["splunk_last_event_id"].(string); got != "splunk-fail-1" {
		t.Fatalf("expected last splunk event id, got %q", got)
	}
}

func TestInternalPayloadSourcetypesStayCanonical(t *testing.T) {
	hecServer, capture := newMockHECServer(t, http.StatusOK)
	defer hecServer.Close()

	app := newTestApp(t)
	app.cfg.Splunk = config.SplunkConfig{Enabled: true, URL: hecServer.URL, Token: "test", Index: "ot_security", Source: "labshock_dmz_collector", VerifyTLS: false}
	app.streamHub = api.NewStreamHub()
	tests := []struct {
		name         string
		event        event.Event
		expectedType string
	}{
		{
			name: "firewall",
			event: event.Event{ID: "fw-1", Timestamp: time.Now().UTC().Format(time.RFC3339Nano), ReceivedAt: time.Now().UTC().Format(time.RFC3339Nano), SourceType: "opnsense", AssetIP: "192.168.10.1", AssetName: "OPNsense OT Firewall", Severity: "warning", EventCategory: "security", Message: "fw", Tags: map[string]any{"splunk_sourcetype": "labshock:net:firewall"}},
			expectedType: "labshock:net:firewall",
		},
		{
			name: "gds",
			event: event.Event{ID: "gds-1", Timestamp: time.Now().UTC().Format(time.RFC3339Nano), ReceivedAt: time.Now().UTC().Format(time.RFC3339Nano), SourceType: "gds-agent", AssetIP: "192.168.1.30", AssetName: "OT GDS Agent", Severity: "warning", EventCategory: "security", Message: "gds", Tags: map[string]any{"splunk_sourcetype": "labshock:ot:gds"}},
			expectedType: "labshock:ot:gds",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			capture.mu.Lock()
			capture.requests = 0
			capture.bodies = nil
			capture.mu.Unlock()
			if err := app.IngestSingle(tt.event); err != nil {
				t.Fatalf("ingest failed: %v", err)
			}
			bodies := waitForRequests(t, capture, 1, 3*time.Second)
			payload := bodies[0]
			if payload["index"] != "ot_security" {
				t.Fatalf("expected ot_security index, got %#v", payload["index"])
			}
			if payload["sourcetype"] != tt.expectedType {
				t.Fatalf("expected %s sourcetype, got %#v", tt.expectedType, payload["sourcetype"])
			}
		})
	}
}

func TestSelfTelemetryUsesDMZSourcetypeAndSchema(t *testing.T) {
	hecServer, capture := newMockHECServer(t, http.StatusOK)
	defer hecServer.Close()

	app := newTestApp(t)
	app.cfg.Splunk = config.SplunkConfig{Enabled: true, URL: hecServer.URL, Token: "test", Index: "ot_security", Source: "labshock_dmz_collector", VerifyTLS: false}
	app.streamHub = api.NewStreamHub()

	if err := app.emitSelfTelemetry("dmz_collector_hec_failure", "critical", "error", map[string]any{
		"queue_depth":       int64(7),
		"spool_event_count": int64(7),
		"hec_error":         "connection refused",
	}); err != nil {
		t.Fatalf("self telemetry failed: %v", err)
	}

	bodies := waitForRequests(t, capture, 1, 3*time.Second)
	payload := bodies[0]
	if payload["index"] != "ot_security" {
		t.Fatalf("expected ot_security index, got %#v", payload["index"])
	}
	if payload["sourcetype"] != "labshock:dmz:dmz_collector" {
		t.Fatalf("expected dmz collector sourcetype, got %#v", payload["sourcetype"])
	}
	eventBody, ok := payload["event"].(map[string]any)
	if !ok {
		t.Fatalf("expected event object, got %#v", payload["event"])
	}
	if eventBody["zone"] != "DMZ" || eventBody["source_type"] != "dmz_collector" || eventBody["message"] != "dmz_collector_hec_failure" {
		t.Fatalf("unexpected self telemetry body: %#v", eventBody)
	}
	tags, ok := eventBody["tags"].(map[string]any)
	if !ok {
		t.Fatalf("expected tags object, got %#v", eventBody["tags"])
	}
	if tags["normalized"] != true || tags["parser_version"] != "v2.logs_by_sources_md" || tags["alert_candidate"] != true {
		t.Fatalf("unexpected self telemetry tags: %#v", tags)
	}
}
