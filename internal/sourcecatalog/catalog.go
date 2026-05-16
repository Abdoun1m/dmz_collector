package sourcecatalog

import (
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Abdoun1m/dmz_collector/internal/config"
	"github.com/Abdoun1m/dmz_collector/internal/event"
	"github.com/Abdoun1m/dmz_collector/internal/sourceutil"
)

type OTConfiguredSource struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	Type          string `json:"type"`
	IP            string `json:"ip"`
	Protocol      string `json:"protocol"`
	Impact        string `json:"impact"`
	Zone          string `json:"zone"`
	Enabled       bool   `json:"enabled"`
	ForwardEnabled bool  `json:"forward_enabled"`
	Notes         string `json:"notes"`
}

type TopMessage struct {
	Message string `json:"message"`
	Count   int64  `json:"count"`
}

type SourceRecord struct {
	SourceKey        string                 `json:"source_key"`
	ID               string                 `json:"id"`
	Name             string                 `json:"name"`
	SourceType       string                 `json:"source_type"`
	AssetIP          string                 `json:"asset_ip"`
	AssetName        string                 `json:"asset_name"`
	Protocol         string                 `json:"protocol"`
	Impact           string                 `json:"impact"`
	Zone             string                 `json:"zone"`
	Enabled          bool                   `json:"enabled"`
	ForwardEnabled   bool                   `json:"forward_enabled"`
	Configured       bool                   `json:"configured"`
	Discovered       bool                   `json:"discovered"`
	FirstSeen        *string                `json:"first_seen"`
	LastSeen         *string                `json:"last_seen"`
	EventCount       int64                  `json:"event_count"`
	SeverityCounts    map[string]int64       `json:"severity_counts"`
	CategoryCounts    map[string]int64       `json:"category_counts"`
	TopMessages      []TopMessage           `json:"top_messages"`
	SIEMIndexHint    *string                `json:"siem_index_hint"`
	SplunkSourcetype *string                `json:"splunk_sourcetype"`
	LastEvent        map[string]any         `json:"last_event"`
	Group            string                 `json:"group"`
	Notes            string                 `json:"notes,omitempty"`
}

type GroupSummary struct {
	SourceCount      int64            `json:"source_count"`
	ConfiguredCount  int64            `json:"configured_count"`
	DiscoveredCount  int64            `json:"discovered_count"`
	EventCount       int64            `json:"event_count"`
	SeverityCounts   map[string]int64 `json:"severity_counts"`
	CategoryCounts   map[string]int64 `json:"category_counts"`
}

type SourceSnapshot struct {
	GeneratedAt       string         `json:"generated_at"`
	SourceOfTruth     string         `json:"source_of_truth"`
	OTCollectorURL    string         `json:"ot_collector_url"`
	TotalSources      int            `json:"total_sources"`
	ConfiguredSources  int            `json:"configured_sources"`
	DiscoveredSources  int            `json:"discovered_sources"`
	Sources           []SourceRecord `json:"sources"`
}

type SourceSummary struct {
	GeneratedAt   string                  `json:"generated_at"`
	ByGroup       map[string]GroupSummary `json:"by_group"`
	BySourceType  map[string]int64        `json:"by_source_type"`
	ByZone        map[string]int64        `json:"by_zone"`
	BySeverity    map[string]int64        `json:"by_severity"`
	ByCategory    map[string]int64        `json:"by_category"`
}

type SourceDetail struct {
	Source       *SourceRecord    `json:"source"`
	RecentEvents []map[string]any `json:"recent_events"`
}

type Catalog struct {
	mu            sync.RWMutex
	otURL         string
	generatedAt   string
	records       map[string]*sourceState
	seenEventIDs  map[string]struct{}
}

type sourceState struct {
	SourceRecord
	messageCounts map[string]int64
	recentEvents  []map[string]any
}

func New(otURL string) *Catalog {
	return &Catalog{
		otURL:        strings.TrimRight(otURL, "/"),
		generatedAt:  time.Now().UTC().Format(time.RFC3339Nano),
		records:      map[string]*sourceState{},
		seenEventIDs: map[string]struct{}{},
	}
}

func (c *Catalog) SetOTURL(otURL string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.otURL = strings.TrimRight(otURL, "/")
}

func (c *Catalog) SeedConfiguredSources(items []config.SourceStatus) {
	converted := make([]OTConfiguredSource, 0, len(items))
	for _, item := range items {
		canonicalType := sourceutil.NormalizeSourceType(item.Type)
		converted = append(converted, OTConfiguredSource{
			ID:             item.Type,
			Name:           item.Name,
			Type:           canonicalType,
			IP:             item.Endpoint,
			Zone:           configuredZoneForType(canonicalType),
			Enabled:        item.Enabled,
			ForwardEnabled: true,
		})
	}
	c.MergeConfiguredSources(converted)
}

func (c *Catalog) MergeConfiguredSources(items []OTConfiguredSource) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, item := range items {
		c.mergeConfiguredLocked(item)
	}
	c.generatedAt = time.Now().UTC().Format(time.RFC3339Nano)
}

func (c *Catalog) ObserveEvent(ev event.Event) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	ev.SourceType = sourceutil.NormalizeSourceType(ev.SourceType)
	if ev.ID != "" {
		if _, exists := c.seenEventIDs[ev.ID]; exists {
			return false
		}
		c.seenEventIDs[ev.ID] = struct{}{}
	}
	key := sourceKey(ev.SourceType, ev.AssetIP, ev.ID)
	state := c.ensureStateLocked(key)
	canonicalType := sourceutil.NormalizeSourceType(ev.SourceType)
	state.SourceKey = key
	if state.ID == "" {
		state.ID = firstNonEmpty(ev.ID, ev.Source, ev.AssetName, ev.AssetIP, key)
	}
	if state.Name == "" || !state.Configured {
		state.Name = firstNonEmpty(ev.AssetName, ev.Source, ev.AssetIP, state.Name, state.ID)
	}
	state.SourceType = canonicalType
	if state.AssetIP == "" {
		state.AssetIP = ev.AssetIP
	}
	if state.AssetName == "" {
		state.AssetName = ev.AssetName
	}
	if state.Protocol == "" {
		state.Protocol = ev.Protocol
	}
	if state.Zone == "" {
		state.Zone = ev.Zone
	}
	if state.FirstSeen == nil {
		v := ev.ReceivedAt
		state.FirstSeen = &v
	}
	lastSeen := ev.ReceivedAt
	state.LastSeen = &lastSeen
	state.EventCount++
	state.SeverityCounts[strings.ToLower(strings.TrimSpace(ev.Severity))]++
	state.CategoryCounts[strings.ToLower(strings.TrimSpace(ev.EventCategory))]++
	msg := strings.TrimSpace(ev.Message)
	if msg != "" {
		state.messageCounts[msg]++
	}
	if hint, ok := ev.Tags["siem_index_hint"].(string); ok && strings.TrimSpace(hint) != "" {
		h := strings.TrimSpace(hint)
		state.SIEMIndexHint = &h
	} else if canonicalType == "firewall" {
		h := "ot_security"
		state.SIEMIndexHint = &h
	}
	if sc, ok := ev.Tags["splunk_sourcetype"].(string); ok && strings.TrimSpace(sc) != "" {
		s := strings.TrimSpace(sc)
		if !strings.EqualFold(s, "labshock:ot:unknown") {
			state.SplunkSourcetype = &s
		} else {
			s := sourceutil.SplunkSourcetypeFor(canonicalType)
			state.SplunkSourcetype = &s
		}
	} else {
		s := sourceutil.SplunkSourcetypeFor(canonicalType)
		state.SplunkSourcetype = &s
	}
	state.LastEvent = redactEventForUI(ev)
	state.Group = sourceutil.GroupForSourceType(canonicalType)
	state.Discovered = true
	c.generatedAt = time.Now().UTC().Format(time.RFC3339Nano)
	return true
}

func (c *Catalog) BootstrapEvents(events []event.Event) {
	for _, ev := range events {
		c.ObserveEvent(ev)
	}
}

func (c *Catalog) Snapshot() SourceSnapshot {
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := make([]SourceRecord, 0, len(c.records))
	configured := 0
	discovered := 0
	for _, state := range c.records {
		rec := state.snapshot()
		out = append(out, rec)
		if rec.Configured {
			configured++
		}
		if rec.Discovered {
			discovered++
		}
	}
	sortSources(out)
	return SourceSnapshot{
		GeneratedAt:      c.generatedAt,
		SourceOfTruth:    "ot_collector",
		OTCollectorURL:   c.otURL,
		TotalSources:     len(out),
		ConfiguredSources: configured,
		DiscoveredSources: discovered,
		Sources:          out,
	}
}

func (c *Catalog) Summary() SourceSummary {
	c.mu.RLock()
	defer c.mu.RUnlock()
	byGroup := map[string]GroupSummary{}
	bySourceType := map[string]int64{}
	byZone := map[string]int64{}
	bySeverity := map[string]int64{}
	byCategory := map[string]int64{}
	for _, state := range c.records {
		rec := state.snapshot()
		g := byGroup[rec.Group]
		g.SourceCount++
		if rec.Configured {
			g.ConfiguredCount++
		}
		if rec.Discovered {
			g.DiscoveredCount++
		}
		g.EventCount += rec.EventCount
		g.SeverityCounts = mergeCounts(g.SeverityCounts, rec.SeverityCounts)
		g.CategoryCounts = mergeCounts(g.CategoryCounts, rec.CategoryCounts)
		byGroup[rec.Group] = g
		bySourceType[rec.SourceType] += rec.EventCount
		byZone[rec.Zone] += rec.EventCount
		bySeverity = mergeCounts(bySeverity, rec.SeverityCounts)
		byCategory = mergeCounts(byCategory, rec.CategoryCounts)
	}
	return SourceSummary{
		GeneratedAt:  c.generatedAt,
		ByGroup:      byGroup,
		BySourceType: bySourceType,
		ByZone:       byZone,
		BySeverity:   bySeverity,
		ByCategory:   byCategory,
	}
}

func (c *Catalog) Detail(sourceType, assetIP string, limit int) (SourceDetail, bool) {
	if limit <= 0 {
		limit = 50
	}
	key := sourceKey(sourceutil.NormalizeSourceType(sourceType), assetIP, "")
	c.mu.RLock()
	defer c.mu.RUnlock()
	state, ok := c.records[key]
	if !ok {
		return SourceDetail{}, false
	}
	rec := state.snapshot()
	recent := state.recentEvents
	if len(recent) > limit {
		recent = recent[len(recent)-limit:]
	}
	out := make([]map[string]any, 0, len(recent))
	for _, ev := range recent {
		out = append(out, cloneMap(ev))
	}
	return SourceDetail{Source: &rec, RecentEvents: out}, true
}

func (c *Catalog) Count() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.records)
}

func (c *Catalog) mergeConfiguredLocked(item OTConfiguredSource) {
	canonicalType := sourceutil.NormalizeSourceType(item.Type)
	key := sourceKey(canonicalType, item.IP, item.ID)
	state := c.ensureStateLocked(key)
	state.SourceKey = key
	state.ID = firstNonEmpty(item.ID, state.ID, key)
	state.Name = firstNonEmpty(item.Name, state.Name, item.ID)
	state.SourceType = canonicalType
	state.AssetIP = firstNonEmpty(item.IP, state.AssetIP)
	state.AssetName = firstNonEmpty(item.Name, state.AssetName)
	state.Protocol = firstNonEmpty(item.Protocol, state.Protocol)
	state.Impact = firstNonEmpty(item.Impact, state.Impact)
	state.Zone = firstNonEmpty(item.Zone, state.Zone)
	state.Enabled = item.Enabled
	state.ForwardEnabled = item.ForwardEnabled
	state.Configured = true
	if state.Group == "" {
		state.Group = sourceutil.GroupForSourceType(canonicalType)
	}
	if state.SeverityCounts == nil {
		state.SeverityCounts = map[string]int64{}
	}
	if state.CategoryCounts == nil {
		state.CategoryCounts = map[string]int64{}
	}
}

func (c *Catalog) ensureStateLocked(key string) *sourceState {
	if state, ok := c.records[key]; ok {
		if state.messageCounts == nil {
			state.messageCounts = map[string]int64{}
		}
		if state.SeverityCounts == nil {
			state.SeverityCounts = map[string]int64{}
		}
		if state.CategoryCounts == nil {
			state.CategoryCounts = map[string]int64{}
		}
		return state
	}
	state := &sourceState{
		SourceRecord: SourceRecord{
			SourceKey:      key,
			SeverityCounts:  map[string]int64{},
			CategoryCounts:  map[string]int64{},
			TopMessages:     []TopMessage{},
			Group:           sourceutil.GroupForSourceType(strings.SplitN(key, ":", 2)[0]),
		},
		messageCounts: map[string]int64{},
	}
	c.records[key] = state
	return state
}

func (s *sourceState) snapshot() SourceRecord {
	rec := s.SourceRecord
	rec.SeverityCounts = cloneCounts(s.SeverityCounts)
	rec.CategoryCounts = cloneCounts(s.CategoryCounts)
	rec.TopMessages = topMessages(s.messageCounts, 5)
	if rec.FirstSeen != nil {
		v := *rec.FirstSeen
		rec.FirstSeen = &v
	}
	if rec.LastSeen != nil {
		v := *rec.LastSeen
		rec.LastSeen = &v
	}
	if rec.SIEMIndexHint != nil {
		v := *rec.SIEMIndexHint
		rec.SIEMIndexHint = &v
	}
	if rec.SplunkSourcetype != nil {
		v := *rec.SplunkSourcetype
		rec.SplunkSourcetype = &v
	}
	rec.LastEvent = cloneMap(rec.LastEvent)
	return rec
}

func sourceKey(sourceType, assetIP, id string) string {
	canonical := sourceutil.NormalizeSourceType(sourceType)
	keyPart := strings.TrimSpace(assetIP)
	if keyPart == "" {
		keyPart = strings.TrimSpace(id)
	}
	if keyPart == "" {
		keyPart = "unknown"
	}
	return canonical + ":" + keyPart
}

func configuredZoneForType(sourceType string) string {
	switch sourceutil.NormalizeSourceType(sourceType) {
	case "influxdb", "opcua_gateway", "collector", "vault", "firewall", "ids":
		return "DMZ"
	default:
		return "DMZ"
	}
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func cloneCounts(in map[string]int64) map[string]int64 {
	out := make(map[string]int64, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func mergeCounts(dst map[string]int64, src map[string]int64) map[string]int64 {
	if dst == nil {
		dst = map[string]int64{}
	}
	for k, v := range src {
		dst[k] += v
	}
	return dst
}

func topMessages(counts map[string]int64, limit int) []TopMessage {
	if len(counts) == 0 {
		return []TopMessage{}
	}
	type pair struct {
		msg string
		ct  int64
	}
	pairs := make([]pair, 0, len(counts))
	for msg, ct := range counts {
		pairs = append(pairs, pair{msg: msg, ct: ct})
	}
	sort.Slice(pairs, func(i, j int) bool {
		if pairs[i].ct == pairs[j].ct {
			return pairs[i].msg < pairs[j].msg
		}
		return pairs[i].ct > pairs[j].ct
	})
	if limit <= 0 || limit > len(pairs) {
		limit = len(pairs)
	}
	out := make([]TopMessage, 0, limit)
	for i := 0; i < limit; i++ {
		out = append(out, TopMessage{Message: pairs[i].msg, Count: pairs[i].ct})
	}
	return out
}

func sortSources(in []SourceRecord) {
	sort.Slice(in, func(i, j int) bool {
		if in[i].Group != in[j].Group {
			return in[i].Group < in[j].Group
		}
		if in[i].SourceType != in[j].SourceType {
			return in[i].SourceType < in[j].SourceType
		}
		if in[i].Name != in[j].Name {
			return in[i].Name < in[j].Name
		}
		if in[i].AssetIP != in[j].AssetIP {
			return in[i].AssetIP < in[j].AssetIP
		}
		return in[i].ID < in[j].ID
	})
}

func redactEventForUI(ev event.Event) map[string]any {
	out := ev.ToMap()
	out["raw"] = "[redacted]"
	if tags, ok := out["tags"].(map[string]any); ok {
		out["tags"] = redactMap(tags)
	}
	return out
}

func redactMap(in map[string]any) map[string]any {
	out := make(map[string]any, len(in))
	for k, v := range in {
		if looksSensitiveKey(k) {
			out[k] = "[redacted]"
			continue
		}
		switch tv := v.(type) {
		case string:
			if looksSensitiveValue(tv) {
				out[k] = "[redacted]"
			} else {
				out[k] = tv
			}
		case map[string]any:
			out[k] = redactMap(tv)
		default:
			out[k] = tv
		}
	}
	return out
}

func looksSensitiveKey(key string) bool {
	lower := strings.ToLower(key)
	for _, needle := range []string{"token", "secret", "password", "private", "key", "cert", "certificate", "crl", "role_id", "secret_id", "vault"} {
		if strings.Contains(lower, needle) {
			return true
		}
	}
	return false
}

func looksSensitiveValue(value string) bool {
	lower := strings.ToLower(value)
	for _, needle := range []string{"-----begin", "-----end", "token", "secret", "password", "private key", "certificate", "crl"} {
		if strings.Contains(lower, needle) {
			return true
		}
	}
	return false
}

func cloneMap(in map[string]any) map[string]any {
	if in == nil {
		return nil
	}
	out := make(map[string]any, len(in))
	for k, v := range in {
		switch tv := v.(type) {
		case map[string]any:
			out[k] = cloneMap(tv)
		case []any:
			copied := make([]any, len(tv))
			copy(copied, tv)
			out[k] = copied
		default:
			out[k] = tv
		}
	}
	return out
}
