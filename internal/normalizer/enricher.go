package normalizer

import (
	"strings"
	"time"

	"github.com/Abdoun1m/dmz_collector/internal/event"
	"github.com/Abdoun1m/dmz_collector/internal/sourceutil"
)

func EnrichDMZ(e event.Event) event.Event {
	if e.Tags == nil {
		e.Tags = map[string]any{}
	}
	e.Tags["dmz_collector"] = "dmz_collector"
	e.Tags["dmz_received_at"] = time.Now().UTC().Format(time.RFC3339Nano)
	e.Tags["purdue_zone"] = inferPurdueZone(e)
	if current, ok := e.Tags["splunk_sourcetype"].(string); !ok || strings.TrimSpace(current) == "" || strings.EqualFold(strings.TrimSpace(current), "labshock:ot:unknown") {
		e.Tags["splunk_sourcetype"] = sourceutil.SplunkSourcetypeFor(e.SourceType)
	}
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
	case "firewall", "ids", "dmz_collector", "vault", "vault_agent", "influxdb", "opcua_dmz_gateway", "gds", "postgres_gds", "jumphost":
		return "dmz"
	default:
		return "ot"
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
	if v, ok := e.Tags["alert_candidate"]; ok {
		switch t := v.(type) {
		case bool:
			if t {
				return true
			}
		case string:
			if strings.EqualFold(t, "true") {
				return true
			}
		}
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
