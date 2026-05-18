package ingest

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/Abdoun1m/dmz_collector/internal/event"
)

const (
	opcuaDMZAssetName     = "opcua_dmz_gateway"
	opcuaDMZAssetIP       = "192.168.10.20"
	opcuaDMZSourceType    = "opcua_dmz_gateway"
	opcuaDMZSource        = "opcua_dmz_gateway"
	opcuaDMZProtocol      = "opcua"
	opcuaDMZSourcetype    = "labshock:dmz:opcua_gateway"
	opcuaDMZParserVersion = "v1.opcua_dmz_normalization"
)

type opcuaDMZClassification struct {
	Message        string
	Category       string
	Severity       string
	RiskLevel      string
	AlertCandidate bool
}

func NormalizeOPCUADMZEventsMany(raw []byte) ([]event.Event, error) {
	raw = bytes.TrimSpace(raw)
	raw = unwrapJSONStringPayload(raw)
	if len(raw) == 0 {
		return nil, fmt.Errorf("empty opcua dmz payload")
	}

	if raw[0] == '[' {
		var rows []json.RawMessage
		if err := json.Unmarshal(raw, &rows); err == nil {
			out := make([]event.Event, 0, len(rows))
			for _, row := range rows {
				ev, err := NormalizeOPCUADMZEvent(row)
				if err != nil {
					return nil, err
				}
				out = append(out, ev)
			}
			return out, nil
		}
	}

	if raw[0] == '{' {
		ev, err := NormalizeOPCUADMZEvent(raw)
		if err == nil {
			return []event.Event{ev}, nil
		}
		if !bytes.Contains(raw, []byte{'\n'}) {
			return nil, err
		}
	}

	var out []event.Event
	scanner := bufio.NewScanner(bytes.NewReader(raw))
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		ev, err := NormalizeOPCUADMZEvent([]byte(line))
		if err != nil {
			ev = normalizeOPCUADMZTextLine(line)
		}
		out = append(out, ev)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no opcua dmz events found")
	}
	return out, nil
}

func NormalizeOPCUADMZEvent(raw []byte) (event.Event, error) {
	var rec map[string]any
	if err := json.Unmarshal(raw, &rec); err != nil {
		return event.Event{}, err
	}
	rec = redactOPCUADMZValue(rec).(map[string]any)
	rawFields := opcuaDMZRawFields(rec)

	message := normalizeOPCUADMZMessage(firstString(rec, "message"))
	eventType := normalizeOPCUADMZEventType(firstString(rawFields, "event_type", "type", "event", "action"))
	if message == "" {
		message = messageForOPCUADMZEventType(eventType)
	}
	if message == "" {
		message = "opcua_dmz_event_unknown"
	}

	class := classifyOPCUADMZMessage(message)
	category := validOPCUADMZCategory(firstString(rec, "event_category"))
	if category == "" {
		category = class.Category
	}
	severity := validOPCUADMZSeverity(firstString(rec, "severity"))
	if severity == "" {
		severity = class.Severity
	}
	class.Message = message
	class.Category = category
	class.Severity = severity
	class.RiskLevel = riskForOPCUADMZ(severity, category)
	class.AlertCandidate = opcuaDMZAlertCandidate(message, category, severity)

	return buildOPCUADMZEvent(rec, rawFields, class), nil
}

func normalizeOPCUADMZTextLine(line string) event.Event {
	rec := map[string]any{
		"message": "opcua_dmz_event_unknown",
		"raw": map[string]any{
			"detail": line,
		},
	}
	lower := strings.ToLower(line)
	switch {
	case strings.Contains(lower, "heartbeat"):
		rec["message"] = "opcua_dmz_heartbeat"
	case strings.Contains(lower, "started"):
		rec["message"] = "opcua_dmz_started"
	case strings.Contains(lower, "southbound") && strings.Contains(lower, "connect") && strings.Contains(lower, "fail"):
		rec["message"] = "opcua_dmz_southbound_connect_failed"
	case strings.Contains(lower, "pki") && strings.Contains(lower, "fail"):
		rec["message"] = "opcua_dmz_pki_load_failed"
	}
	ev, err := NormalizeOPCUADMZEvent(mustJSON(rec))
	if err != nil {
		return event.Event{}
	}
	return ev
}

func buildOPCUADMZEvent(rec, rawFields map[string]any, class opcuaDMZClassification) event.Event {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	ts := firstString(rec, "timestamp")
	if ts == "" {
		ts = firstString(rawFields, "generated_at", "ts", "created_at")
	}
	if ts == "" {
		ts = now
	}

	safeRaw := safeOPCUADMZRawFields(rawFields)
	if len(safeRaw) == 0 {
		safeRaw = map[string]any{"event_type": strings.TrimPrefix(class.Message, "opcua_dmz_")}
	}
	rawJSON, _ := json.Marshal(safeRaw)

	tags := map[string]any{}
	if incoming := mapAny(rec["tags"]); len(incoming) > 0 {
		for k, v := range redactOPCUADMZValue(incoming).(map[string]any) {
			tags[k] = v
		}
	}
	tags["component"] = opcuaDMZAssetName
	tags["zone"] = "DMZ"
	tags["purdue_zone"] = "dmz"
	tags["dmz_collector"] = "dmz_collector"
	tags["collector_decision_hint"] = "store_forward"
	tags["normalized"] = true
	tags["normalization_source"] = "opcua_dmz_gateway_sender"
	tags["parser_version"] = opcuaDMZParserVersion
	tags["splunk_sourcetype"] = opcuaDMZSourcetype
	tags["siem_index_hint"] = "ot_security"
	tags["risk_level"] = class.RiskLevel
	if class.AlertCandidate {
		tags["alert_candidate"] = true
	}
	for _, key := range []string{"event_type", "application_uri", "target", "runtime_side", "endpoint", "status", "status_name", "status_code", "security_policy", "security_mode", "namespace_uri"} {
		if v, ok := safeRaw[key]; ok {
			tags[key] = v
		}
	}

	ev := event.Event{
		Timestamp:     ts,
		ReceivedAt:    now,
		Zone:          "DMZ",
		Source:        opcuaDMZSource,
		SourceType:    opcuaDMZSourceType,
		AssetName:     opcuaDMZAssetName,
		AssetIP:       opcuaDMZAssetIP,
		Severity:      class.Severity,
		Protocol:      opcuaDMZProtocol,
		EventCategory: class.Category,
		Message:       class.Message,
		Raw:           string(rawJSON),
		Tags:          tags,
		ExtraFields:   map[string]any{},
	}
	for k, v := range safeRaw {
		ev.ExtraFields[k] = v
	}
	ev.EnsureDefaults()
	return ev
}

func opcuaDMZRawFields(rec map[string]any) map[string]any {
	raw := mapAny(rec["raw"])
	if len(raw) > 0 {
		return raw
	}
	if rawText := strings.TrimSpace(stringAny(rec["raw"])); rawText != "" {
		var rawObj map[string]any
		if err := json.Unmarshal([]byte(rawText), &rawObj); err == nil {
			return rawObj
		}
		return map[string]any{"detail": rawText}
	}
	out := map[string]any{}
	for _, key := range opcuaDMZSafeRawKeys {
		if v, ok := rec[key]; ok {
			out[key] = v
		}
	}
	return out
}

var opcuaDMZSafeRawKeys = []string{
	"event_type", "component", "generated_at", "application_uri", "target", "runtime_side",
	"endpoint", "ot_endpoint", "ot_username", "influx_host", "influx_port", "status",
	"status_name", "status_code", "security_policy", "security_mode", "namespace_uri",
	"trust_index", "trust_path", "cert_path", "key_path", "certificate_found",
	"private_key_found", "southbound_initialized", "southbound_connected", "poll_interval_ms",
	"health_interval_seconds", "detail",
}

func safeOPCUADMZRawFields(raw map[string]any) map[string]any {
	redacted := redactOPCUADMZValue(raw).(map[string]any)
	out := map[string]any{}
	for _, key := range opcuaDMZSafeRawKeys {
		if v, ok := redacted[key]; ok && v != nil {
			out[key] = v
		}
	}
	return compactGDSMap(out)
}

func classifyOPCUADMZMessage(message string) opcuaDMZClassification {
	switch normalizeOPCUADMZMessage(message) {
	case "opcua_dmz_started", "opcua_dmz_stopped", "opcua_dmz_heartbeat", "opcua_dmz_northbound_started", "opcua_dmz_southbound_initialized":
		return opcuaDMZClassification{Category: "system_health", Severity: "info"}
	case "opcua_dmz_northbound_failed", "opcua_dmz_influx_unavailable", "opcua_dmz_client_alloc_failed":
		return opcuaDMZClassification{Category: "error", Severity: "critical"}
	case "opcua_dmz_influx_write_failed":
		return opcuaDMZClassification{Category: "error", Severity: "warning"}
	case "opcua_dmz_southbound_connected":
		return opcuaDMZClassification{Category: "opcua_session", Severity: "info"}
	case "opcua_dmz_southbound_connect_failed", "opcua_dmz_southbound_poll_failed", "opcua_dmz_namespace_failed":
		return opcuaDMZClassification{Category: "opcua_session", Severity: "warning"}
	case "opcua_dmz_pki_load_failed", "opcua_dmz_trust_load_failed", "opcua_dmz_security_config_failed":
		return opcuaDMZClassification{Category: "pki_validation", Severity: "critical"}
	case "opcua_dmz_gds_bootstrap_failed":
		return opcuaDMZClassification{Category: "pki_trust_sync", Severity: "critical"}
	case "opcua_dmz_gds_trust_update_detected", "opcua_dmz_gds_trust_pull_success", "opcua_dmz_gds_trust_applied":
		return opcuaDMZClassification{Category: "pki_trust_sync", Severity: "info"}
	case "opcua_dmz_gds_trust_pull_failed", "opcua_dmz_gds_trust_apply_failed":
		return opcuaDMZClassification{Category: "pki_trust_sync", Severity: "warning"}
	case "opcua_dmz_gds_certificate_enrolled", "opcua_dmz_gds_certificate_renewed", "opcua_dmz_gds_certificate_applied":
		return opcuaDMZClassification{Category: "certificate_lifecycle", Severity: "info"}
	case "opcua_dmz_gds_certificate_renewal_due", "opcua_dmz_gds_certificate_renewal_failed":
		return opcuaDMZClassification{Category: "certificate_lifecycle", Severity: "warning"}
	default:
		return opcuaDMZClassification{Category: "system_health", Severity: "info"}
	}
}

func messageForOPCUADMZEventType(eventType string) string {
	switch normalizeOPCUADMZEventType(eventType) {
	case "started", "gateway_started":
		return "opcua_dmz_started"
	case "stopped", "gateway_stopped":
		return "opcua_dmz_stopped"
	case "heartbeat", "gateway_heartbeat":
		return "opcua_dmz_heartbeat"
	case "northbound_started":
		return "opcua_dmz_northbound_started"
	case "northbound_failed":
		return "opcua_dmz_northbound_failed"
	case "influx_unavailable":
		return "opcua_dmz_influx_unavailable"
	case "influx_write_failed":
		return "opcua_dmz_influx_write_failed"
	case "southbound_initialized":
		return "opcua_dmz_southbound_initialized"
	case "southbound_connected":
		return "opcua_dmz_southbound_connected"
	case "southbound_connect_failed":
		return "opcua_dmz_southbound_connect_failed"
	case "southbound_poll_failed":
		return "opcua_dmz_southbound_poll_failed"
	case "namespace_failed":
		return "opcua_dmz_namespace_failed"
	case "client_alloc_failed":
		return "opcua_dmz_client_alloc_failed"
	case "pki_load_failed":
		return "opcua_dmz_pki_load_failed"
	case "trust_load_failed":
		return "opcua_dmz_trust_load_failed"
	case "security_config_failed":
		return "opcua_dmz_security_config_failed"
	case "gds_bootstrap_failed", "bootstrap_failed":
		return "opcua_dmz_gds_bootstrap_failed"
	case "trust_update_detected":
		return "opcua_dmz_gds_trust_update_detected"
	case "trust_pull_completed", "trust_pull_success":
		return "opcua_dmz_gds_trust_pull_success"
	case "trust_pull_failed":
		return "opcua_dmz_gds_trust_pull_failed"
	case "trust_applied":
		return "opcua_dmz_gds_trust_applied"
	case "trust_apply_failed":
		return "opcua_dmz_gds_trust_apply_failed"
	case "certificate_enrolled":
		return "opcua_dmz_gds_certificate_enrolled"
	case "certificate_renewal_due":
		return "opcua_dmz_gds_certificate_renewal_due"
	case "certificate_renewed":
		return "opcua_dmz_gds_certificate_renewed"
	case "certificate_applied":
		return "opcua_dmz_gds_certificate_applied"
	case "certificate_renewal_failed":
		return "opcua_dmz_gds_certificate_renewal_failed"
	default:
		if strings.HasPrefix(eventType, "opcua_dmz_") {
			return eventType
		}
		return ""
	}
}

func normalizeOPCUADMZMessage(v string) string {
	msg := strings.ToLower(strings.TrimSpace(strings.ReplaceAll(v, "-", "_")))
	if strings.HasPrefix(msg, "opcua_dmz_") {
		return msg
	}
	return ""
}

func normalizeOPCUADMZEventType(v string) string {
	return strings.ToLower(strings.TrimSpace(strings.ReplaceAll(v, "-", "_")))
}

func validOPCUADMZCategory(v string) string {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "system_health", "opcua_session", "pki_validation", "pki_trust_sync", "certificate_lifecycle", "error", "security", "access_control":
		return strings.ToLower(strings.TrimSpace(v))
	default:
		return ""
	}
}

func validOPCUADMZSeverity(v string) string {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "info", "warning", "error", "critical":
		return strings.ToLower(strings.TrimSpace(v))
	case "warn":
		return "warning"
	default:
		return ""
	}
}

func riskForOPCUADMZ(severity, category string) string {
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case "critical", "error":
		return "HIGH"
	case "warning":
		return "MEDIUM"
	}
	switch strings.ToLower(strings.TrimSpace(category)) {
	case "security", "access_control":
		return "MEDIUM"
	default:
		return "LOW"
	}
}

func opcuaDMZAlertCandidate(message, category, severity string) bool {
	sev := strings.ToLower(severity)
	cat := strings.ToLower(category)
	msg := strings.ToLower(message)
	if sev == "warning" || sev == "error" || sev == "critical" {
		return true
	}
	if cat == "security" || cat == "access_control" || cat == "pki_validation" {
		return true
	}
	return strings.Contains(msg, "failed") || strings.Contains(msg, "unavailable") || strings.Contains(msg, "bootstrap_failed")
}

func redactOPCUADMZValue(v any) any {
	switch t := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, item := range t {
			if isOPCUADMZSensitiveKey(k) {
				out[k] = "[REDACTED]"
				continue
			}
			out[k] = redactOPCUADMZValue(item)
		}
		return out
	case []any:
		out := make([]any, 0, len(t))
		for _, item := range t {
			out = append(out, redactOPCUADMZValue(item))
		}
		return out
	case string:
		if looksLikeOPCUADMZSecret(t) {
			return "[REDACTED]"
		}
		return t
	default:
		return v
	}
}

func isOPCUADMZSensitiveKey(key string) bool {
	k := strings.ToLower(strings.TrimSpace(key))
	collapsed := strings.NewReplacer("-", "_", ".", "_").Replace(k)
	allowedPaths := map[string]struct{}{
		"cert_path":         {},
		"key_path":          {},
		"trust_path":        {},
		"private_key_found": {},
	}
	if _, ok := allowedPaths[collapsed]; ok {
		return false
	}
	sensitiveExact := []string{"token", "authorization", "password", "secret", "secret_id", "role_id", "private_key", "privatekey", "pem", "csr", "crl", "certificate_pem", "certificate_body", "cert_body", "crl_body", "ca_chain", "signature"}
	for _, item := range sensitiveExact {
		if collapsed == item {
			return true
		}
	}
	sensitiveContains := []string{"token", "authorization", "password", "secret", "secret_id", "role_id", "private_key", "privatekey", "certificate_pem", "certificate_body", "cert_body", "crl_body", "ca_chain"}
	for _, item := range sensitiveContains {
		if strings.Contains(collapsed, item) {
			return true
		}
	}
	return false
}

func looksLikeOPCUADMZSecret(value string) bool {
	lower := strings.ToLower(value)
	if strings.Contains(lower, "-----begin ") || strings.Contains(lower, "-----end ") {
		return true
	}
	return strings.Contains(lower, "bearer ") && len(value) > len("bearer ")
}

func mustJSON(v any) []byte {
	b, _ := json.Marshal(v)
	return b
}
