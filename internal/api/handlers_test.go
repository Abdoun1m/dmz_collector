package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/Abdoun1m/dmz_collector/internal/config"
	"github.com/Abdoun1m/dmz_collector/internal/event"
	"github.com/Abdoun1m/dmz_collector/internal/storage"
)

type statsCoreStub struct{}

func (statsCoreStub) IngestBatch([]event.Event) (int, int, int, []string)  { return 0, 0, 0, nil }
func (statsCoreStub) IngestSingle(event.Event) error                       { return nil }
func (statsCoreStub) ReadEvents(storage.EventQuery) ([]event.Event, error) { return nil, nil }
func (statsCoreStub) ReadEventByID(string) (event.Event, bool, error) {
	return event.Event{}, false, nil
}
func (statsCoreStub) Stats() map[string]any { return map[string]any{"ignored": true} }
func (statsCoreStub) StatsSummary() map[string]any {
	return map[string]any{
		"total_events":           int64(1),
		"source_count":           1,
		"critical_count":         int64(0),
		"warning_count":          int64(0),
		"latest_event_timestamp": "2026-05-16T16:00:00Z",
		"queue":                  map[string]any{"queued": 0, "forwarded": 0, "failed": 0, "last_success": "", "last_failure": "", "paused": false},
	}
}
func (statsCoreStub) StatsTimeline() []map[string]any                           { return nil }
func (statsCoreStub) Sources() map[string]any                                   { return nil }
func (statsCoreStub) SourcesWithOptions(bool, bool, bool) map[string]any        { return nil }
func (statsCoreStub) SourcesSummary() map[string]any                            { return nil }
func (statsCoreStub) SourcesSummaryWithOptions(bool, bool, bool) map[string]any { return nil }
func (statsCoreStub) InternalSources() map[string]any                           { return nil }
func (statsCoreStub) SourceDetail(string, string, int) (map[string]any, bool)   { return nil, false }
func (statsCoreStub) ForwardingStatus() config.ForwardingStatus                 { return config.ForwardingStatus{} }
func (statsCoreStub) ForwardingConfig() config.ForwardingConfig                 { return config.ForwardingConfig{} }
func (statsCoreStub) UpdateForwardingConfig(config.ForwardingConfig) error      { return nil }
func (statsCoreStub) TestForwarding() (map[string]any, error)                   { return nil, nil }
func (statsCoreStub) TestSplunk() (map[string]any, error)                       { return nil, nil }
func (statsCoreStub) FlushForwarding() map[string]any                           { return nil }
func (statsCoreStub) QueueStatus() map[string]any                               { return nil }
func (statsCoreStub) Health() map[string]any                                    { return nil }

func TestHandleStatsSummaryAlias(t *testing.T) {
	a := &API{core: statsCoreStub{}}

	assertStatsResponse := func(path string) map[string]any {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		rr := httptest.NewRecorder()
		a.handleStatsSummary(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("expected HTTP 200 for %s, got %d", path, rr.Code)
		}
		var out map[string]any
		if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
			t.Fatalf("failed to decode response for %s: %v", path, err)
		}
		return out
	}

	statsBody := assertStatsResponse("/stats")
	summaryBody := assertStatsResponse("/stats/summary")
	if !reflect.DeepEqual(statsBody, summaryBody) {
		t.Fatalf("expected /stats and /stats/summary to match, got %#v vs %#v", statsBody, summaryBody)
	}
}

type sourceQueryStub struct{}

func (sourceQueryStub) IngestBatch([]event.Event) (int, int, int, []string)  { return 0, 0, 0, nil }
func (sourceQueryStub) IngestSingle(event.Event) error                       { return nil }
func (sourceQueryStub) ReadEvents(storage.EventQuery) ([]event.Event, error) { return nil, nil }
func (sourceQueryStub) ReadEventByID(string) (event.Event, bool, error) {
	return event.Event{}, false, nil
}
func (sourceQueryStub) Stats() map[string]any           { return nil }
func (sourceQueryStub) StatsSummary() map[string]any    { return nil }
func (sourceQueryStub) StatsTimeline() []map[string]any { return nil }
func (sourceQueryStub) Sources() map[string]any         { return nil }
func (sourceQueryStub) SourcesWithOptions(includeInternal, includeDisabled, includeDirectSIEM bool) map[string]any {
	return map[string]any{"include_internal": includeInternal, "include_disabled": includeDisabled, "include_direct_siem": includeDirectSIEM}
}
func (sourceQueryStub) SourcesSummary() map[string]any { return nil }
func (sourceQueryStub) SourcesSummaryWithOptions(includeInternal, includeDisabled, includeDirectSIEM bool) map[string]any {
	return map[string]any{"include_internal": includeInternal, "include_disabled": includeDisabled, "include_direct_siem": includeDirectSIEM}
}
func (sourceQueryStub) InternalSources() map[string]any                         { return map[string]any{"internal": true} }
func (sourceQueryStub) SourceDetail(string, string, int) (map[string]any, bool) { return nil, false }
func (sourceQueryStub) ForwardingStatus() config.ForwardingStatus               { return config.ForwardingStatus{} }
func (sourceQueryStub) ForwardingConfig() config.ForwardingConfig               { return config.ForwardingConfig{} }
func (sourceQueryStub) UpdateForwardingConfig(config.ForwardingConfig) error    { return nil }
func (sourceQueryStub) TestForwarding() (map[string]any, error)                 { return nil, nil }
func (sourceQueryStub) TestSplunk() (map[string]any, error)                     { return nil, nil }
func (sourceQueryStub) FlushForwarding() map[string]any                         { return nil }
func (sourceQueryStub) QueueStatus() map[string]any                             { return nil }
func (sourceQueryStub) Health() map[string]any                                  { return nil }

func TestHandleSourcesQueryFlags(t *testing.T) {
	a := &API{core: sourceQueryStub{}}
	req := httptest.NewRequest(http.MethodGet, "/sources?include_internal=true&include_disabled=true&include_direct_siem=true", nil)
	rr := httptest.NewRecorder()
	a.handleSources(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected HTTP 200, got %d", rr.Code)
	}
	var out map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if out["include_internal"] != true || out["include_disabled"] != true || out["include_direct_siem"] != true {
		t.Fatalf("unexpected include flags: %#v", out)
	}
}

type ingestBatchCaptureStub struct {
	statsCoreStub
	events []event.Event
}

func (s *ingestBatchCaptureStub) IngestBatch(events []event.Event) (int, int, int, []string) {
	s.events = append([]event.Event(nil), events...)
	return len(events), 0, len(events), []string{}
}

func TestHandleOPCUADMZEvents(t *testing.T) {
	core := &ingestBatchCaptureStub{}
	a := &API{core: core}
	body := []byte(`[
		{"raw":{"event_type":"trust_pull_completed"}},
		{"raw":{"event_type":"southbound_connect_failed"}}
	]`)
	req := httptest.NewRequest(http.MethodPost, "/opcua-dmz/events", bytes.NewReader(body))
	rr := httptest.NewRecorder()
	a.handleOPCUADMZEvents(rr, req)
	if rr.Code != http.StatusAccepted {
		t.Fatalf("expected HTTP 202, got %d: %s", rr.Code, rr.Body.String())
	}
	var out map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if out["accepted"].(float64) != 2 || out["queued"].(float64) != 2 {
		t.Fatalf("unexpected response: %#v", out)
	}
	if len(core.events) != 2 || core.events[0].SourceType != "opcua_dmz_gateway" || core.events[1].Message != "opcua_dmz_southbound_connect_failed" {
		t.Fatalf("unexpected normalized events: %#v", core.events)
	}
}
