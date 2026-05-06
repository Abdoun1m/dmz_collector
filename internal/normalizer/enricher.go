package normalizer

import (
	"strings"
	"time"

	"github.com/Abdoun1m/dmz_collector/internal/event"
)

func EnrichDMZ(e event.Event) event.Event {
	if e.Tags == nil {
		e.Tags = map[string]any{}
	}
	e.Tags["dmz_collector"] = "dmz_collector"
	e.Tags["dmz_received_at"] = time.Now().UTC().Format(time.RFC3339Nano)
	e.Tags["purdue_zone"] = inferPurdueZone(e)
	e.Tags["splunk_sourcetype"] = sourcetypeFor(e.SourceType)
	e.Tags["siem_index_hint"] = indexHintFor(e)
	if isHighValue(e) {
		e.Tags["high_value"] = true
	}
	return e
}

func inferPurdueZone(e event.Event) string {
	switch strings.ToLower(e.SourceType) {
	case "plc":
		return "level1"
	case "scada", "opcua", "ews":
		return "level2"
	case "firewall", "ids":
		return "dmz"
	default:
		return "ot"
	}
}

func sourcetypeFor(sourceType string) string {
	switch strings.ToLower(sourceType) {
	case "plc":
		return "labshock:ot:plc"
	case "scada":
		return "labshock:ot:scada"
	case "opcua":
		return "labshock:ot:opcua"
	case "ews":
		return "labshock:ot:ews"
	case "firewall":
		return "labshock:net:firewall"
	case "ids":
		return "labshock:ids:alert"
	default:
		return "labshock:ot:unknown"
	}
}

func indexHintFor(e event.Event) string {
	st := strings.ToLower(e.SourceType)
	cat := strings.ToLower(e.EventCategory)
	sev := strings.ToLower(e.Severity)

	if st == "ids" || st == "firewall" {
		return "ot_security"
	}
	if cat == "security" || sev == "critical" || sev == "error" {
		return "ot_security"
	}
	if cat == "operator_action" || cat == "operator_read" || cat == "operator_write" {
		return "ot_operations"
	}
	if cat == "runtime" || cat == "system" || cat == "network" || cat == "communication" {
		return "ot_telemetry"
	}
	return "ot_security"
}

func isHighValue(e event.Event) bool {
	cat := strings.ToLower(e.EventCategory)
	st := strings.ToLower(e.SourceType)
	sev := strings.ToLower(e.Severity)
	if cat == "operator_write" || cat == "security" {
		return true
	}
	if sev == "critical" || sev == "error" {
		return true
	}
	if st == "ids" || st == "firewall" {
		return true
	}
	if v, ok := e.Tags["sensitive_action"]; ok {
		switch t := v.(type) {
		case bool:
			return t
		case string:
			return strings.EqualFold(t, "true")
		}
	}
	return false
}

