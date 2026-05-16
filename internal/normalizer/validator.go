package normalizer

import (
	"fmt"
	"strings"
	"time"

	"github.com/Abdoun1m/dmz_collector/internal/event"
)

func ValidateAndNormalize(e event.Event) (event.Event, error) {
	e.EnsureDefaults()

	if _, err := parseRFC3339Any(e.Timestamp); err != nil {
		return event.Event{}, fmt.Errorf("invalid timestamp: %w", err)
	}
	if _, err := parseRFC3339Any(e.ReceivedAt); err != nil {
		e.ReceivedAt = time.Now().UTC().Format(time.RFC3339Nano)
	}

	e.SourceType = strings.ToLower(strings.TrimSpace(e.SourceType))
	// normalize common aliases to canonical form
	switch e.SourceType {
	case "gds-agent", "gds_agent":
		e.SourceType = "gds_agent"
	case "opnsense":
		e.SourceType = "firewall"
	case "fuxa", "fuxa-ui":
		// map FUXA to scada for SIEM purposes
		e.SourceType = "scada"
	}
	e.Severity = strings.ToLower(strings.TrimSpace(e.Severity))
	e.EventCategory = strings.ToLower(strings.TrimSpace(e.EventCategory))
	if e.Tags == nil {
		e.Tags = map[string]any{}
	}
	return e, nil
}

func parseRFC3339Any(v string) (time.Time, error) {
	if t, err := time.Parse(time.RFC3339Nano, v); err == nil {
		return t, nil
	}
	return time.Parse(time.RFC3339, v)
}

