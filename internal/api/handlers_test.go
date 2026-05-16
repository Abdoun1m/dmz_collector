package api

import (
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

func (statsCoreStub) IngestBatch([]event.Event) (int, int, int, []string) { return 0, 0, 0, nil }
func (statsCoreStub) IngestSingle(event.Event) error                      { return nil }
func (statsCoreStub) ReadEvents(storage.EventQuery) ([]event.Event, error) { return nil, nil }
func (statsCoreStub) ReadEventByID(string) (event.Event, bool, error)      { return event.Event{}, false, nil }
func (statsCoreStub) Stats() map[string]any                                { return map[string]any{"ignored": true} }
func (statsCoreStub) StatsSummary() map[string]any {
	return map[string]any{
		"total_events":   int64(1),
		"source_count":   1,
		"critical_count": int64(0),
		"warning_count":  int64(0),
		"latest_event_timestamp": "2026-05-16T16:00:00Z",
		"queue": map[string]any{"queued": 0, "forwarded": 0, "failed": 0, "last_success": "", "last_failure": "", "paused": false},
	}
}
func (statsCoreStub) StatsTimeline() []map[string]any                      { return nil }
func (statsCoreStub) Sources() map[string]any                              { return nil }
func (statsCoreStub) SourcesSummary() map[string]any                       { return nil }
func (statsCoreStub) SourceDetail(string, string, int) (map[string]any, bool) { return nil, false }
func (statsCoreStub) ForwardingStatus() config.ForwardingStatus            { return config.ForwardingStatus{} }
func (statsCoreStub) ForwardingConfig() config.ForwardingConfig            { return config.ForwardingConfig{} }
func (statsCoreStub) UpdateForwardingConfig(config.ForwardingConfig) error { return nil }
func (statsCoreStub) TestForwarding() (map[string]any, error)              { return nil, nil }
func (statsCoreStub) FlushForwarding() map[string]any                      { return nil }
func (statsCoreStub) QueueStatus() map[string]any                          { return nil }
func (statsCoreStub) Health() map[string]any                               { return nil }

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