package normalizer

import (
	"fmt"
	"strings"
	"time"

	"github.com/Abdoun1m/dmz_collector/internal/event"
	"github.com/Abdoun1m/dmz_collector/internal/sourceutil"
)

func ValidateAndNormalize(e event.Event) (event.Event, error) {
	originalSourceType := strings.ToLower(strings.TrimSpace(e.SourceType))
	e.SourceType = sourceutil.NormalizeSourceType(e.SourceType)
	e.EnsureDefaults()

	if _, err := parseRFC3339Any(e.Timestamp); err != nil {
		return event.Event{}, fmt.Errorf("invalid timestamp: %w", err)
	}
	if _, err := parseRFC3339Any(e.ReceivedAt); err != nil {
		e.ReceivedAt = time.Now().UTC().Format(time.RFC3339Nano)
	}

	e.Severity = strings.ToLower(strings.TrimSpace(e.Severity))
	e.EventCategory = strings.ToLower(strings.TrimSpace(e.EventCategory))
	if e.Tags == nil {
		e.Tags = map[string]any{}
	}
	applySourceSpecificNormalization(&e, originalSourceType)
	return e, nil
}

func applySourceSpecificNormalization(e *event.Event, originalSourceType string) {
	if e == nil {
		return
	}
	if e.Tags == nil {
		e.Tags = map[string]any{}
	}
	switch e.SourceType {
	case "firewall":
		e.Tags["firewall_vendor"] = "opnsense"
		e.Tags["splunk_sourcetype"] = sourceutil.SplunkSourcetypeFor("firewall")
		e.Tags["siem_index_hint"] = "ot_security"
		if firewallCategory(e.Message, e.Raw, e.Tags, originalSourceType) == "security" {
			e.EventCategory = "security"
		} else {
			e.EventCategory = "network"
		}
	case "gds_agent", "plc", "opcua", "scada", "ews", "ids":
		if current, ok := e.Tags["splunk_sourcetype"].(string); !ok || strings.TrimSpace(current) == "" || strings.EqualFold(strings.TrimSpace(current), "labshock:ot:unknown") {
			e.Tags["splunk_sourcetype"] = sourceutil.SplunkSourcetypeFor(e.SourceType)
		}
	}
}

func firewallCategory(message, raw string, tags map[string]any, sourceType string) string {
	blob := strings.ToLower(strings.Join([]string{message, raw, sourceType, tagString(tags, "action"), tagString(tags, "firewall_action")}, " "))
	if strings.Contains(blob, "drop") || strings.Contains(blob, "block") || strings.Contains(blob, "deny") || strings.Contains(blob, "reject") || strings.Contains(blob, "alert") {
		return "security"
	}
	return "network"
}

func tagString(tags map[string]any, key string) string {
	if tags == nil {
		return ""
	}
	if v, ok := tags[key]; ok {
		return strings.ToLower(strings.TrimSpace(fmt.Sprintf("%v", v)))
	}
	return ""
}

func parseRFC3339Any(v string) (time.Time, error) {
	if t, err := time.Parse(time.RFC3339Nano, v); err == nil {
		return t, nil
	}
	return time.Parse(time.RFC3339, v)
}

