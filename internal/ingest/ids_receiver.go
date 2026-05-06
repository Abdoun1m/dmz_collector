package ingest

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/Abdoun1m/dmz_collector/internal/event"
)

type idsAlert struct {
	Timestamp string `json:"timestamp"`
	EventType string `json:"event_type"`
	SrcIP     string `json:"src_ip"`
	DestIP    string `json:"dest_ip"`
	Alert     struct {
		Signature string `json:"signature"`
		Severity  int    `json:"severity"`
		Category  string `json:"category"`
	} `json:"alert"`
}

func NormalizeIDSAlert(raw []byte) (event.Event, error) {
	var in idsAlert
	if err := json.Unmarshal(raw, &in); err != nil {
		return event.Event{}, err
	}
	ts := in.Timestamp
	if ts == "" {
		ts = time.Now().UTC().Format(time.RFC3339Nano)
	}
	sev := "warning"
	if in.Alert.Severity <= 1 {
		sev = "critical"
	} else if in.Alert.Severity == 2 {
		sev = "error"
	}
	msg := strings.TrimSpace(in.Alert.Signature)
	if msg == "" {
		msg = "ids alert"
	}
	ev := event.Event{
		Timestamp:     ts,
		ReceivedAt:    time.Now().UTC().Format(time.RFC3339Nano),
		Zone:          "DMZ",
		SourceType:    "ids",
		AssetName:     "suricata",
		AssetIP:       in.SrcIP,
		Severity:      sev,
		Protocol:      "http",
		EventCategory: "security",
		Message:       msg,
		Raw:           string(raw),
		Tags: map[string]any{
			"event_type":     in.EventType,
			"src_ip":         in.SrcIP,
			"dest_ip":        in.DestIP,
			"signature":      in.Alert.Signature,
			"alert_category": in.Alert.Category,
			"alert_severity": fmt.Sprintf("%d", in.Alert.Severity),
		},
	}
	ev.EnsureDefaults()
	ev.OriginalRaw = append(ev.OriginalRaw, raw...)
	return ev, nil
}

