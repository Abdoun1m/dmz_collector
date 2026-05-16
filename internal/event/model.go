package event

import (
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/Abdoun1m/dmz_collector/internal/sourceutil"
)

type Event struct {
	ID            string         `json:"id"`
	Timestamp     string         `json:"timestamp"`
	ReceivedAt    string         `json:"received_at"`
	Zone          string         `json:"zone"`
	Source        string         `json:"source"`
	SourceType    string         `json:"source_type"`
	AssetName     string         `json:"asset_name"`
	AssetIP       string         `json:"asset_ip"`
	Severity      string         `json:"severity"`
	Protocol      string         `json:"protocol"`
	EventCategory string         `json:"event_category"`
	Message       string         `json:"message"`
	Raw           string         `json:"raw"`
	Tags          map[string]any `json:"tags"`

	ExtraFields map[string]any `json:"-"`
	OriginalRaw json.RawMessage `json:"-"`
}

var knownKeys = map[string]struct{}{
	"id":             {},
	"timestamp":      {},
	"received_at":    {},
	"zone":           {},
	"source":         {},
	"source_type":    {},
	"asset_name":     {},
	"asset_ip":       {},
	"severity":       {},
	"protocol":       {},
	"event_category": {},
	"message":        {},
	"raw":            {},
	"tags":           {},
}

func ParseOne(raw []byte) (Event, error) {
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return Event{}, err
	}
	e := Event{
		ID:            getString(m["id"]),
		Timestamp:     getString(m["timestamp"]),
		ReceivedAt:    getString(m["received_at"]),
		Zone:          getString(m["zone"]),
		Source:        getString(m["source"]),
		SourceType:    getString(m["source_type"]),
		AssetName:     getString(m["asset_name"]),
		AssetIP:       getString(m["asset_ip"]),
		Severity:      strings.ToLower(getString(m["severity"])),
		Protocol:      getString(m["protocol"]),
		EventCategory: strings.ToLower(getString(m["event_category"])),
		Message:       getString(m["message"]),
		Raw:           getString(m["raw"]),
		Tags:          map[string]any{},
		ExtraFields:   map[string]any{},
		OriginalRaw:   append(json.RawMessage(nil), raw...),
	}
	e.SourceType = sourceutil.NormalizeSourceType(e.SourceType)

	if tags, ok := m["tags"].(map[string]any); ok {
		e.Tags = tags
	}

	for k, v := range m {
		if _, ok := knownKeys[k]; ok {
			continue
		}
		e.ExtraFields[k] = v
	}
	e.EnsureDefaults()
	return e, nil
}

func ParseMany(raw []byte) ([]Event, error) {
	var arr []json.RawMessage
	if err := json.Unmarshal(raw, &arr); err == nil {
		out := make([]Event, 0, len(arr))
		for _, item := range arr {
			e, perr := ParseOne(item)
			if perr != nil {
				return nil, perr
			}
			out = append(out, e)
		}
		return out, nil
	}
	e, err := ParseOne(raw)
	if err != nil {
		return nil, err
	}
	return []Event{e}, nil
}

func (e *Event) EnsureDefaults() {
	if e.Tags == nil {
		e.Tags = map[string]any{}
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if e.Timestamp == "" {
		e.Timestamp = now
	}
	if e.ReceivedAt == "" {
		e.ReceivedAt = now
	}
	if e.Zone == "" {
		e.Zone = "OT"
	}
	if e.SourceType == "" {
		e.SourceType = "unknown"
	}
	if e.Source == "" {
		e.Source = "unknown"
	}
	if e.Severity == "" {
		e.Severity = "info"
	}
	if e.Protocol == "" {
		e.Protocol = "syslog"
	}
	if e.EventCategory == "" {
		e.EventCategory = "unknown"
	}
	if e.ID == "" {
		// include raw in deterministic id to better deduplicate retried payloads
		sum := sha1.Sum([]byte(fmt.Sprintf("%s|%s|%s|%s|%s|%s", e.Timestamp, e.SourceType, e.AssetIP, e.Message, e.Raw, e.EventCategory)))
		e.ID = "dmz-" + hex.EncodeToString(sum[:8])
	}
}

func (e Event) ToMap() map[string]any {
	out := map[string]any{
		"id":             e.ID,
		"timestamp":      e.Timestamp,
		"received_at":    e.ReceivedAt,
		"zone":           e.Zone,
		"source":         e.Source,
		"source_type":    e.SourceType,
		"asset_name":     e.AssetName,
		"asset_ip":       e.AssetIP,
		"severity":       e.Severity,
		"protocol":       e.Protocol,
		"event_category": e.EventCategory,
		"message":        e.Message,
		"raw":            e.Raw,
		"tags":           e.Tags,
	}
	for k, v := range e.ExtraFields {
		if _, exists := out[k]; exists {
			continue
		}
		out[k] = v
	}
	return out
}

func (e Event) MarshalJSON() ([]byte, error) {
	return json.Marshal(e.ToMap())
}

func (e *Event) UnmarshalJSON(data []byte) error {
	parsed, err := ParseOne(data)
	if err != nil {
		return err
	}
	*e = parsed
	return nil
}

func getString(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case json.Number:
		return t.String()
	case nil:
		return ""
	default:
		return fmt.Sprintf("%v", t)
	}
}
