package event

import (
	"encoding/json"
	"time"

	"github.com/Abdoun1m/dmz_collector/internal/sourceutil"
)

type SplunkPayload struct {
	Time       float64 `json:"time"`
	Host       string  `json:"host"`
	Source     string  `json:"source"`
	Sourcetype string  `json:"sourcetype"`
	Index      string  `json:"index"`
	Event      any     `json:"event"`
}

func BuildSplunkPayload(evt Event, source string, defaultIndex string) SplunkPayload {
	t := time.Now().UTC()
	if parsed, err := time.Parse(time.RFC3339Nano, evt.Timestamp); err == nil {
		t = parsed.UTC()
	} else if parsed, err := time.Parse(time.RFC3339, evt.Timestamp); err == nil {
		t = parsed.UTC()
	}
	index := defaultIndex
	if v, ok := evt.Tags["siem_index_hint"]; ok {
		if s, ok := v.(string); ok && s != "" {
			index = s
		}
	}
	sourcetype := sourceutil.SplunkSourcetypeFor(evt.SourceType)
	if v, ok := evt.Tags["splunk_sourcetype"]; ok {
		if s, ok := v.(string); ok && s != "" && s != "labshock:ot:unknown" {
			sourcetype = s
		}
	}
	host := evt.AssetName
	if host == "" {
		host = evt.AssetIP
	}
	return SplunkPayload{
		Time:       float64(t.UnixNano()) / 1e9,
		Host:       host,
		Source:     source,
		Sourcetype: sourcetype,
		Index:      index,
		Event:      evt.ToMap(),
	}
}

func MarshalSplunkBatch(events []Event, source string, defaultIndex string) ([]byte, error) {
	payloads := make([]SplunkPayload, 0, len(events))
	for _, e := range events {
		payloads = append(payloads, BuildSplunkPayload(e, source, defaultIndex))
	}
	return json.Marshal(payloads)
}

