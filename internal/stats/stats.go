package stats

import (
	"sort"
	"sync"
	"time"

	"github.com/Abdoun1m/dmz_collector/internal/event"
)

type SourceInfo struct {
	AssetName  string `json:"asset_name"`
	AssetIP    string `json:"asset_ip"`
	SourceType string `json:"source_type"`
	EventCount int64  `json:"event_count"`
	LastSeen   string `json:"last_seen"`
}

type Stats struct {
	mu sync.RWMutex

	totalReceived int64
	securityCount int64
	highValue     int64

	bySource     map[string]int64
	bySeverity   map[string]int64
	byCategory   map[string]int64
	bySourcetype map[string]int64
	byAsset      map[string]int64
	timeline     map[string]int64
	sources      map[string]SourceInfo
	rateSecond   int64
	rateCount    int64
	rateEPS      int64
	latestEventTimestamp string
}

func New() *Stats {
	return &Stats{
		bySource:     map[string]int64{},
		bySeverity:   map[string]int64{},
		byCategory:   map[string]int64{},
		bySourcetype: map[string]int64{},
		byAsset:      map[string]int64{},
		timeline:     map[string]int64{},
		sources:      map[string]SourceInfo{},
	}
}

func (s *Stats) Add(e event.Event) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.totalReceived++
	s.bySource[e.SourceType]++
	s.bySeverity[e.Severity]++
	s.byCategory[e.EventCategory]++
	if v, ok := e.Tags["splunk_sourcetype"].(string); ok {
		s.bySourcetype[v]++
	}
	s.byAsset[e.AssetName]++
	s.timeline[bucket(e.ReceivedAt)]++
	if e.EventCategory == "security" {
		s.securityCount++
	}
	if hv, ok := e.Tags["high_value"].(bool); ok && hv {
		s.highValue++
	}
	key := e.AssetIP
	if key == "" {
		key = e.AssetName
	}
	src := s.sources[key]
	src.AssetName = e.AssetName
	src.AssetIP = e.AssetIP
	src.SourceType = e.SourceType
	src.EventCount++
	src.LastSeen = e.ReceivedAt
	s.sources[key] = src
	if e.ReceivedAt != "" {
		if s.latestEventTimestamp == "" || e.ReceivedAt > s.latestEventTimestamp {
			s.latestEventTimestamp = e.ReceivedAt
		}
	}
	s.bumpRateLocked()
}

func (s *Stats) Summary() map[string]any {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return map[string]any{
		"total_received":    s.totalReceived,
		"security_events":   s.securityCount,
		"high_value_events": s.highValue,
		"event_rate_per_second": s.rateEPS,
		"by_source_type":    clone(s.bySource),
		"by_severity":       clone(s.bySeverity),
		"by_category":       clone(s.byCategory),
		"top_source":        topOne(s.bySource),
		"top_sourcetype":    topOne(s.bySourcetype),
	}
}

func (s *Stats) TotalReceived() int64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.totalReceived
}

func (s *Stats) SeverityCount(level string) int64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.bySeverity[level]
}

func (s *Stats) LatestEventTimestamp() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.latestEventTimestamp
}

func (s *Stats) SourceCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.sources)
}

func (s *Stats) bumpRateLocked() {
	now := time.Now().Unix()
	if s.rateSecond != now {
		s.rateSecond = now
		s.rateEPS = s.rateCount
		s.rateCount = 0
	}
	s.rateCount++
}

func (s *Stats) Timeline() []map[string]any {
	s.mu.RLock()
	defer s.mu.RUnlock()
	keys := make([]string, 0, len(s.timeline))
	for k := range s.timeline {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]map[string]any, 0, len(keys))
	for _, k := range keys {
		out = append(out, map[string]any{"timestamp": k, "count": s.timeline[k]})
	}
	return out
}

func (s *Stats) Sources() []SourceInfo {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]SourceInfo, 0, len(s.sources))
	for _, v := range s.sources {
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].EventCount > out[j].EventCount })
	return out
}

func clone(in map[string]int64) map[string]int64 {
	out := make(map[string]int64, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func topOne(m map[string]int64) map[string]any {
	key := ""
	val := int64(0)
	for k, v := range m {
		if v > val || key == "" {
			key = k
			val = v
		}
	}
	return map[string]any{"name": key, "count": val}
}

func bucket(ts string) string {
	t, err := time.Parse(time.RFC3339Nano, ts)
	if err != nil {
		t = time.Now().UTC()
	}
	return t.UTC().Format("2006-01-02T15:04:00Z")
}
