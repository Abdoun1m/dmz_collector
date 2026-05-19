package ingest

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/Abdoun1m/dmz_collector/internal/event"
)

const (
	gdsAssetName  = "labshock_gds"
	gdsAssetIP    = "192.168.10.30"
	gdsSourcetype = "labshock:dmz:gds"
)

var gdsKVPattern = regexp.MustCompile(`([A-Za-z_][A-Za-z0-9_]*)=("[^"]*"|\S+)`)

type gdsClassification struct {
	Message        string
	Category       string
	Severity       string
	RiskLevel      string
	AlertCandidate bool
}

type gdsDMZControlPlane struct {
	LogMessage string
	Family     string
	Action     string
	Class      gdsClassification
}

func NormalizeGDSEventsMany(raw []byte) ([]event.Event, error) {
	raw = bytes.TrimSpace(raw)
	raw = unwrapJSONStringPayload(raw)
	if len(raw) == 0 {
		return nil, fmt.Errorf("empty gds payload")
	}

	if raw[0] == '[' {
		var rows []json.RawMessage
		if err := json.Unmarshal(raw, &rows); err == nil {
			out := make([]event.Event, 0, len(rows))
			for _, row := range rows {
				ev, err := NormalizeGDSEvent(row)
				if err != nil {
					return nil, err
				}
				if ev.Message != "" {
					out = append(out, ev)
				}
			}
			if len(out) == 0 {
				return nil, fmt.Errorf("no gds events found")
			}
			return out, nil
		}
	}

	if raw[0] == '{' {
		ev, err := NormalizeGDSEvent(raw)
		if err == nil {
			if ev.Message == "" {
				return nil, fmt.Errorf("gds event suppressed")
			}
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
		ev, err := NormalizeGDSEvent([]byte(line))
		if err != nil {
			ev = normalizeGDSTextLine(line)
		}
		if ev.Message != "" {
			out = append(out, ev)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no gds events found")
	}
	return out, nil
}

func NormalizeGDSEvent(raw []byte) (event.Event, error) {
	var rec map[string]any
	if err := json.Unmarshal(raw, &rec); err != nil {
		return event.Event{}, err
	}
	if isGDSOPCUAFacadeEvent(rec) {
		return buildGDSOPCUAFacadeEvent(rec), nil
	}
	rec = redactMap(rec)
	if dmz, ok := normalizeGDSDMZControlPlane(rec); ok {
		return buildGDSDMZControlPlaneEvent(rec, dmz), nil
	}
	if ev, ok := normalizeGDSHealth(rec); ok {
		return ev, nil
	}

	msgText := strings.TrimSpace(firstString(rec, "log_message", "msg", "message", "log", "detail", "details"))
	eventType := normalizeGDSEventType(firstString(rec, "event_type", "type", "event", "action", "gds_action", "name"))
	if eventType == "" {
		eventType = eventTypeFromMessage(msgText)
	}

	class := classifyGDSEvent(eventType, rec, msgText)
	if class.Message == "" {
		return event.Event{}, nil
	}
	return buildGDSEvent(rec, class, eventType, msgText), nil
}

func normalizeGDSHealth(rec map[string]any) (event.Event, bool) {
	checks := mapAny(rec["checks"])
	if len(checks) == 0 {
		return event.Event{}, false
	}
	postgres := mapAny(checks["postgres"])
	if len(postgres) == 0 {
		return event.Event{}, false
	}
	ok := boolValue(postgres["ok"])
	class := gdsClassification{Message: "gds_db_connected", Category: "system_health", Severity: "info", RiskLevel: "LOW"}
	if !ok {
		class = gdsClassification{Message: "gds_db_disconnected", Category: "error", Severity: "critical", RiskLevel: "HIGH", AlertCandidate: true}
	}
	rec["event_type"] = class.Message
	if detail := stringAny(postgres["detail"]); detail != "" {
		rec["error"] = detail
	}
	return buildGDSEvent(rec, class, class.Message, ""), true
}

func normalizeGDSTextLine(line string) event.Event {
	rec := map[string]any{
		"line": line,
	}
	for k, v := range parseGDSAccessLine(line) {
		rec[k] = v
	}
	for k, v := range parseGDSKeyValues(line) {
		rec[k] = v
	}
	if strings.Contains(line, "[gds-entrypoint]") {
		rec["logger"] = "gds-entrypoint"
	}
	msg := strings.TrimSpace(line)
	class := classifyGDSEvent(eventTypeFromMessage(msg), rec, msg)
	if class.Message == "" {
		return event.Event{}
	}
	return buildGDSEvent(redactMap(rec), class, stringAny(rec["event_type"]), msg)
}

func buildGDSEvent(rec map[string]any, class gdsClassification, eventType, msgText string) event.Event {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	ts := firstString(rec, "created_at", "generated_at", "reported_at", "ts", "timestamp", "time")
	if ts == "" {
		ts = now
	}
	logMessage := strings.TrimSpace(msgText)
	if logMessage == "" {
		logMessage = strings.TrimSpace(eventType)
	}
	family, action := splitGDSFamilyAction(logMessage)
	if explicitFamily := strings.TrimSpace(firstString(rec, "gds_family")); explicitFamily != "" {
		family = explicitFamily
	}
	if explicitAction := strings.TrimSpace(firstString(rec, "gds_action")); explicitAction != "" {
		action = explicitAction
	}
	if strings.TrimSpace(msgText) == "" && family != "" && action != "" {
		logMessage = family + ": " + action
	}
	safe := gdsSafeFields(rec)
	if eventType != "" {
		safe["event_type"] = eventType
	}
	if logMessage != "" {
		safe["log_message"] = logMessage
		safe["gds_family"] = family
		safe["gds_action"] = action
	}
	rawJSON, _ := json.Marshal(compactGDSMap(safe))

	tags := map[string]any{
		"component":               "gds",
		"zone":                    "DMZ",
		"collector_decision_hint": "store_forward",
		"risk_level":              class.RiskLevel,
		"normalized":              true,
		"normalization_source":    "logs_by_sources_md",
		"parser_version":          "v3.2.gds_pack_mapping",
		"splunk_sourcetype":       gdsSourcetype,
		"siem_index_hint":         "ot_security",
		"gds_family":              family,
		"gds_action":              action,
		"log_message":             logMessage,
	}
	for k, v := range safe {
		if _, exists := tags[k]; !exists {
			tags[k] = v
		}
	}
	if class.AlertCandidate {
		tags["alert_candidate"] = true
	}

	ev := event.Event{
		Timestamp:     ts,
		ReceivedAt:    now,
		Zone:          "DMZ",
		Source:        "gds_events",
		SourceType:    "gds",
		AssetName:     gdsAssetName,
		AssetIP:       gdsAssetIP,
		Severity:      class.Severity,
		Protocol:      "gds_event",
		EventCategory: class.Category,
		Message:       class.Message,
		Raw:           string(rawJSON),
		Tags:          compactGDSMap(tags),
		ExtraFields: map[string]any{
			"gds_family": family,
			"gds_action": action,
			"risk_level": class.RiskLevel,
		},
	}
	ev.EnsureDefaults()
	return ev
}

func isGDSOPCUAFacadeEvent(rec map[string]any) bool {
	tags := mapAny(rec["tags"])
	msg := strings.ToLower(strings.TrimSpace(firstString(rec, "message")))
	return strings.EqualFold(firstString(rec, "source_type"), "gds") && strings.EqualFold(firstString(rec, "source"), "gds_opcua_facade") ||
		strings.EqualFold(stringAny(tags["component"]), "gds_opcua_facade") ||
		strings.EqualFold(stringAny(tags["parser_version"]), "v3.3.gds_opcua_facade") ||
		strings.HasPrefix(msg, "gds_opcua_")
}

func buildGDSOPCUAFacadeEvent(rec map[string]any) event.Event {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	ts := firstString(rec, "timestamp", "created_at", "generated_at", "reported_at", "ts", "time")
	if ts == "" {
		ts = now
	}
	rawFields := mapAny(rec["raw"])
	if len(rawFields) == 0 {
		rawFields = map[string]any{}
	}
	rawFields = redactGDSOPCUAFacadeValue(rawFields).(map[string]any)

	message := strings.ToLower(strings.TrimSpace(firstString(rec, "message")))
	if !strings.HasPrefix(message, "gds_opcua_") {
		message = strings.ToLower(strings.TrimSpace(firstString(rawFields, "event_type", "message")))
	}
	if !strings.HasPrefix(message, "gds_opcua_") {
		message = "gds_opcua_method_called"
	}
	class := classifyGDSOPCUAFacadeMessage(message)

	tags := map[string]any{}
	if incoming := mapAny(rec["tags"]); len(incoming) > 0 {
		for k, v := range redactGDSOPCUAFacadeValue(incoming).(map[string]any) {
			tags[k] = v
		}
	}
	tags["component"] = "gds_opcua_facade"
	tags["source_type"] = "gds"
	tags["purdue_zone"] = "dmz"
	tags["zone"] = "DMZ"
	tags["normalized"] = true
	tags["parser_version"] = "v3.3.gds_opcua_facade"
	tags["facade_version"] = "v3.3.gds_opcua_facade"
	tags["normalization_source"] = "gds_opcua_facade"
	tags["splunk_sourcetype"] = gdsSourcetype
	tags["siem_index_hint"] = "ot_security"
	tags["collector_decision_hint"] = "store_forward"
	tags["risk_level"] = class.RiskLevel

	for _, key := range []string{"method_name", "method_class", "application_uri", "decision", "reason", "result_code", "duration_ms", "correlation_id", "opcua_session_id"} {
		copySafeField(tags, rawFields, key, key)
	}
	if class.AlertCandidate {
		tags["alert_candidate"] = true
	}

	rawJSON, _ := json.Marshal(compactGDSMap(rawFields))
	ev := event.Event{
		Timestamp:     ts,
		ReceivedAt:    now,
		Zone:          "DMZ",
		Source:        "gds_opcua_facade",
		SourceType:    "gds",
		AssetName:     gdsAssetName,
		AssetIP:       gdsAssetIP,
		Severity:      class.Severity,
		Protocol:      "opcua",
		EventCategory: class.Category,
		Message:       message,
		Raw:           string(rawJSON),
		Tags:          compactGDSMap(tags),
		ExtraFields:   map[string]any{"risk_level": class.RiskLevel},
	}
	for _, key := range []string{"method_name", "method_class", "application_uri", "decision", "reason", "result_code", "duration_ms", "correlation_id", "opcua_session_id"} {
		if v, ok := rawFields[key]; ok {
			ev.ExtraFields[key] = v
		}
	}
	ev.EnsureDefaults()
	return ev
}

func classifyGDSOPCUAFacadeMessage(message string) gdsClassification {
	switch strings.ToLower(strings.TrimSpace(message)) {
	case "gds_opcua_method_called":
		return gdsClassification{Message: message, Category: "access_control", Severity: "info", RiskLevel: "LOW"}
	case "gds_opcua_method_allowed":
		return gdsClassification{Message: message, Category: "access_control", Severity: "info", RiskLevel: "LOW"}
	case "gds_opcua_method_denied":
		return gdsClassification{Message: message, Category: "access_control", Severity: "warning", RiskLevel: "HIGH", AlertCandidate: true}
	case "gds_opcua_invalid_input":
		return gdsClassification{Message: message, Category: "access_control", Severity: "warning", RiskLevel: "MEDIUM", AlertCandidate: true}
	case "gds_opcua_rate_limited":
		return gdsClassification{Message: message, Category: "access_control", Severity: "warning", RiskLevel: "MEDIUM", AlertCandidate: true}
	case "gds_opcua_internal_api_failed":
		return gdsClassification{Message: message, Category: "error", Severity: "error", RiskLevel: "HIGH", AlertCandidate: true}
	case "gds_opcua_sensitive_material_blocked":
		return gdsClassification{Message: message, Category: "data_protection", Severity: "critical", RiskLevel: "CRITICAL", AlertCandidate: true}
	case "gds_opcua_method_completed":
		return gdsClassification{Message: message, Category: "system_health", Severity: "info", RiskLevel: "LOW"}
	default:
		return gdsClassification{Message: message, Category: "access_control", Severity: "info", RiskLevel: "LOW"}
	}
}

func normalizeGDSDMZControlPlane(rec map[string]any) (gdsDMZControlPlane, bool) {
	if !isDMZGDSControlPlane(rec) {
		return gdsDMZControlPlane{}, false
	}

	logMessage := strings.TrimSpace(extractGDSLogMessage(rec))
	if logMessage == "" {
		return gdsDMZControlPlane{}, false
	}

	family, action := splitGDSFamilyAction(logMessage)
	class := classifyGDSDMZAction(action)

	return gdsDMZControlPlane{
		LogMessage: logMessage,
		Family:     family,
		Action:     action,
		Class:      class,
	}, true
}

func buildGDSDMZControlPlaneEvent(rec map[string]any, dmz gdsDMZControlPlane) event.Event {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	ts := firstString(rec, "created_at", "generated_at", "reported_at", "ts", "timestamp", "time")
	if ts == "" {
		ts = now
	}

	rawPayload := extractOriginalGDSRaw(rec)
	rawJSON, _ := json.Marshal(rawPayload)

	tags := map[string]any{
		"log_message":             dmz.LogMessage,
		"gds_family":              dmz.Family,
		"gds_action":              dmz.Action,
		"risk_level":              dmz.Class.RiskLevel,
		"component":               "gds",
		"purdue_zone":             "dmz",
		"collector_decision_hint": "store_forward",
		"normalized":              true,
		"normalization_source":    "logs_by_sources_md",
		"parser_version":          "v3.2.gds_pack_mapping",
		"splunk_sourcetype":       gdsSourcetype,
		"siem_index_hint":         "ot_security",
	}

	ev := event.Event{
		Timestamp:     ts,
		ReceivedAt:    now,
		Zone:          "DMZ",
		Source:        "gds_events",
		SourceType:    "gds",
		AssetName:     gdsAssetName,
		AssetIP:       gdsAssetIP,
		Severity:      dmz.Class.Severity,
		Protocol:      "gds_event",
		EventCategory: dmz.Class.Category,
		Message:       dmz.Class.Message,
		Raw:           string(rawJSON),
		Tags:          compactGDSMap(tags),
		ExtraFields: map[string]any{
			"gds_family": dmz.Family,
			"gds_action": dmz.Action,
			"risk_level": dmz.Class.RiskLevel,
		},
	}
	ev.EnsureDefaults()
	return ev
}

func isDMZGDSControlPlane(rec map[string]any) bool {
	matches := []bool{
		strings.EqualFold(strings.TrimSpace(firstString(rec, "source_type")), "gds"),
		strings.EqualFold(strings.TrimSpace(firstString(rec, "source")), "gds_events"),
		strings.EqualFold(strings.TrimSpace(firstString(rec, "asset_name")), gdsAssetName),
		strings.EqualFold(strings.TrimSpace(firstString(rec, "sourcetype")), gdsSourcetype),
	}
	for _, match := range matches {
		if match {
			return true
		}
	}

	logMessage := strings.TrimSpace(extractGDSLogMessage(rec))
	return strings.HasPrefix(strings.ToLower(logMessage), "gds_")
}

func extractGDSLogMessage(rec map[string]any) string {
	if message := strings.TrimSpace(firstString(rec, "log_message")); message != "" {
		return message
	}

	raw := rec["raw"]
	if rawMap := mapAny(raw); len(rawMap) > 0 {
		if message := strings.TrimSpace(firstString(rawMap, "log_message")); message != "" {
			return message
		}
	}

	rawText := strings.TrimSpace(stringAny(raw))
	if rawText != "" {
		if parsed := parseGDSRawText(rawText); parsed != "" {
			return parsed
		}
	}

	return ""
}

func parseGDSRawText(rawText string) string {
	var rawObj map[string]any
	if err := json.Unmarshal([]byte(rawText), &rawObj); err == nil {
		if message := strings.TrimSpace(firstString(rawObj, "log_message")); message != "" {
			return message
		}
	}

	if strings.HasPrefix(strings.ToLower(rawText), "gds_") {
		return rawText
	}

	return ""
}

func unwrapJSONStringPayload(raw []byte) []byte {
	var text string
	if err := json.Unmarshal(raw, &text); err != nil {
		return raw
	}
	trimmed := strings.TrimSpace(text)
	if trimmed == "" {
		return raw
	}
	return []byte(trimmed)
}

func splitGDSFamilyAction(logMessage string) (string, string) {
	if idx := strings.Index(logMessage, ":"); idx >= 0 {
		family := strings.TrimSpace(logMessage[:idx])
		action := strings.TrimSpace(logMessage[idx+1:])
		if family == "" {
			family = "gds_runtime"
		}
		if action == "" {
			action = "unknown"
		}
		return family, action
	}
	return "gds_runtime", strings.TrimSpace(logMessage)
}

func classifyGDSDMZAction(action string) gdsClassification {
	switch strings.ToLower(strings.TrimSpace(action)) {
	case "agent_auth_success":
		return gdsClassification{Message: "gds_agent_auth_success", Category: "access_control", Severity: "info", RiskLevel: "LOW"}
	case "mtls_client_identity_success":
		return gdsClassification{Message: "gds_mtls_client_identity_success", Category: "access_control", Severity: "info", RiskLevel: "LOW"}
	case "mtls_metrics_read":
		return gdsClassification{Message: "gds_client_pull_success", Category: "access_control", Severity: "info", RiskLevel: "LOW"}
	case "trustlist_artifact_read":
		return gdsClassification{Message: "gds_client_pull_success", Category: "pki_trust_sync", Severity: "info", RiskLevel: "LOW"}
	case "trustlist_artifact_sig_read":
		return gdsClassification{Message: "gds_client_pull_success", Category: "pki_trust_sync", Severity: "info", RiskLevel: "LOW"}
	case "artifact_regenerated":
		return gdsClassification{Message: "gds_trust_list_published", Category: "pki_trust_sync", Severity: "info", RiskLevel: "MEDIUM", AlertCandidate: false}
	case "trustlist_build":
		return gdsClassification{Message: "gds_trust_list_updated", Category: "pki_trust_sync", Severity: "info", RiskLevel: "LOW"}
	case "certificate_drift_read":
		return gdsClassification{Message: "gds_certificate_drift_read", Category: "pki_validation", Severity: "info", RiskLevel: "LOW"}
	case "certificate_telemetry_read":
		return gdsClassification{Message: "gds_certificate_telemetry_read", Category: "pki_validation", Severity: "info", RiskLevel: "LOW"}
	case "component_status_read":
		return gdsClassification{Message: "gds_component_status_read", Category: "operator_action", Severity: "info", RiskLevel: "LOW"}
	case "signing_trust_anchor_read":
		return gdsClassification{Message: "gds_trust_anchor_read", Category: "pki_trust_sync", Severity: "info", RiskLevel: "LOW"}
	case "component_trust_material_read":
		return gdsClassification{Message: "gds_client_pull_success", Category: "pki_trust_sync", Severity: "info", RiskLevel: "LOW"}
	case "vault_unsealed_detected":
		return gdsClassification{Message: "gds_vault_unsealed_detected", Category: "system_health", Severity: "info", RiskLevel: "MEDIUM"}
	case "gds_db_connected":
		return gdsClassification{Message: "gds_db_connected", Category: "system_health", Severity: "info", RiskLevel: "LOW"}
	case "gds_db_snapshot":
		return gdsClassification{Message: "gds_db_snapshot", Category: "system_health", Severity: "info", RiskLevel: "LOW"}
	case "gds_db_disconnected":
		return gdsClassification{Message: "gds_db_disconnected", Category: "error", Severity: "critical", RiskLevel: "HIGH", AlertCandidate: true}
	case "gds_heartbeat":
		return gdsClassification{Message: "gds_heartbeat", Category: "system_health", Severity: "info", RiskLevel: "LOW"}
	default:
		return gdsClassification{Message: "gds_event_unknown", Category: "operator_action", Severity: "info", RiskLevel: "LOW"}
	}
}

func parseGDSAccessLine(line string) map[string]any {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" {
		return map[string]any{}
	}
	parts := strings.Fields(trimmed)
	if len(parts) < 3 {
		return map[string]any{}
	}
	method := strings.ToUpper(parts[0])
	if method != "GET" && method != "POST" && method != "PUT" && method != "PATCH" && method != "DELETE" && method != "HEAD" && method != "OPTIONS" {
		return map[string]any{}
	}
	path := parts[1]
	status := ""
	for i := len(parts) - 1; i >= 0; i-- {
		if len(parts[i]) == 3 && parts[i][0] >= '1' && parts[i][0] <= '5' {
			status = parts[i]
			break
		}
	}
	if status == "" {
		return map[string]any{}
	}
	endpointFamily := endpointFamilyForPath(path)
	out := map[string]any{
		"http_method":     method,
		"http_path":       path,
		"http_status":     status,
		"endpoint_family": endpointFamily,
	}
	return out
}

func endpointFamilyForPath(path string) string {
	lower := strings.ToLower(strings.TrimSpace(path))
	switch {
	case strings.Contains(lower, "/api/v1/enrollments/") || strings.Contains(lower, "/api/v1/certificates/renew"):
		return "enrollment"
	case strings.Contains(lower, "/api/v1/trustlists/") && strings.Contains(lower, "/artifact.sig"):
		return "trust_artifact_signature"
	case strings.Contains(lower, "/api/v1/trustlists/") && strings.Contains(lower, "/artifact"):
		return "trust_artifact"
	case strings.Contains(lower, "/api/v1/certificates/telemetry"):
		return "certificate_telemetry"
	case strings.Contains(lower, "/api/v1/certificates/drift"):
		return "certificate_drift"
	case strings.Contains(lower, "/api/v1/components/status"):
		return "components_status"
	default:
		return "api"
	}
}

func extractOriginalGDSRaw(rec map[string]any) any {
	if raw, ok := rec["raw"]; ok {
		switch t := raw.(type) {
		case string:
			trimmed := strings.TrimSpace(t)
			if trimmed != "" {
				var rawObj map[string]any
				if err := json.Unmarshal([]byte(trimmed), &rawObj); err == nil {
					return compactGDSMap(rawObj)
				}
			}
			if msg := parseGDSRawText(trimmed); msg != "" {
				return map[string]any{"log_message": msg}
			}
			return map[string]any{"log_message": trimmed}
		case map[string]any:
			return compactGDSMap(t)
		}
	}

	if msg := strings.TrimSpace(firstString(rec, "log_message")); msg != "" {
		return map[string]any{"log_message": msg}
	}

	return map[string]any{}
}

func classifyGDSEvent(eventType string, rec map[string]any, msgText string) gdsClassification {
	et := strings.ToLower(strings.TrimSpace(eventType))
	text := strings.ToLower(strings.Join([]string{et, msgText, firstString(rec, "error", "error_code", "reason", "status"), firstString(rec, "http_method"), firstString(rec, "http_path"), firstString(rec, "http_status"), firstString(rec, "endpoint_family")}, " "))
	httpMethod := strings.ToUpper(firstString(rec, "http_method"))
	httpPath := strings.ToLower(firstString(rec, "http_path"))
	httpStatus := firstString(rec, "http_status")
	endpointFamily := strings.ToLower(firstString(rec, "endpoint_family"))

	switch et {
	case "gds_started", "application_started", "bootstrap_started":
		return gdsClassification{"gds_started", "system_health", "info", "LOW", false}
	case "gds_heartbeat", "application_heartbeat":
		return gdsClassification{"gds_heartbeat", "system_health", "info", "LOW", false}
	case "gds_db_snapshot":
		return gdsClassification{"gds_db_snapshot", "system_health", "info", "LOW", false}
	case "gds_db_connected":
		return gdsClassification{"gds_db_connected", "system_health", "info", "LOW", false}
	case "gds_db_disconnected":
		return gdsClassification{"gds_db_disconnected", "error", "critical", "HIGH", true}
	case "application_register":
		return gdsClassification{"gds_client_registered", "pki_lifecycle", "info", "LOW", false}
	case "certificate_request_created", "certificate_renewal_requested":
		return gdsClassification{"gds_enrollment_request", "pki_lifecycle", "info", "LOW", false}
	case "csr_validated", "component_enrollment_completed":
		return gdsClassification{"gds_enrollment_approved", "pki_lifecycle", "info", "LOW", false}
	case "csr_rejected", "certificate_issue_failed", "certificate_renewal_failed":
		return gdsClassification{"gds_enrollment_failed", "pki_lifecycle", "warning", "MEDIUM", true}
	case "certificate_issued":
		return gdsClassification{"gds_certificate_issued", "certificate_lifecycle", "info", "LOW", true}
	case "certificate_renewal_packaged", "labshock_gds_component_renewal_result_v1":
		return gdsClassification{"gds_certificate_renewed", "certificate_lifecycle", "info", "LOW", true}
	case "certificate_revoked", "certificate_revocation_crl_refreshed", "package_revoked":
		return gdsClassification{"gds_certificate_revoked", "certificate_lifecycle", "warning", "MEDIUM", true}
	case "certificate_expired":
		return gdsClassification{"gds_certificate_expired", "pki_validation", "warning", "MEDIUM", true}
	case "trustlist_build":
		return gdsClassification{"gds_trust_list_updated", "pki_trust_sync", "info", "LOW", false}
	case "artifact_regenerated", "trustlist_artifact_rebuild":
		return gdsClassification{"gds_trust_list_published", "pki_trust_sync", "info", "LOW", true}
	case "trustlist_artifact_read", "trustlist_artifact_sig_read", "component_trust_material_read", "package_manifest_read", "certificate_package_read":
		return gdsClassification{"gds_client_pull_success", "pki_trust_sync", "info", "LOW", false}
	case "trustlist_pull_failed":
		return gdsClassification{"gds_trust_list_pull_failed", "pki_trust_sync", "warning", "MEDIUM", true}
	case "agent_auth_failure", "agent_unauthorized_pull", "mtls_client_identity_failure":
		return gdsClassification{"gds_unauthorized_request", "security", "warning", "MEDIUM", true}
	case "agent_auth_success":
		return gdsClassification{"gds_agent_auth_success", "access_control", "info", "LOW", false}
	case "mtls_client_identity_success":
		return gdsClassification{"gds_mtls_client_identity_success", "access_control", "info", "LOW", false}
	case "mtls_metrics_read":
		return gdsClassification{"gds_client_pull_success", "access_control", "info", "LOW", false}
	case "certificate_telemetry_read", "certificate_drift_read":
		if et == "certificate_drift_read" {
			return gdsClassification{"gds_certificate_drift_read", "pki_validation", "info", "LOW", false}
		}
		return gdsClassification{"gds_certificate_telemetry_read", "pki_validation", "info", "LOW", false}
	case "component_status_read":
		return gdsClassification{"gds_component_status_read", "operator_action", "info", "LOW", false}
	case "signing_trust_anchor_read":
		return gdsClassification{"gds_trust_anchor_read", "pki_trust_sync", "info", "LOW", false}
	}

	if httpMethod != "" && httpPath != "" && httpStatus != "" {
		statusCode := strings.TrimSpace(httpStatus)
		if statusCode == "401" || statusCode == "403" {
			return gdsClassification{"gds_unauthorized_request", "security", "warning", "MEDIUM", true}
		}
		if endpointFamily == "enrollment" {
			if httpMethod == "POST" && (strings.Contains(httpPath, "/csr") || strings.Contains(httpPath, "/renew")) && (statusCode == "200" || statusCode == "201" || statusCode == "202") {
				return gdsClassification{"gds_enrollment_request", "pki_lifecycle", "info", "LOW", false}
			}
			if statusCode != "" && statusCode[0] >= '4' {
				return gdsClassification{"gds_enrollment_failed", "pki_lifecycle", "warning", "MEDIUM", true}
			}
		}
		if endpointFamily == "trust_artifact" || endpointFamily == "trust_artifact_signature" || endpointFamily == "certificate_telemetry" || endpointFamily == "certificate_drift" || endpointFamily == "components_status" {
			if statusCode != "" && statusCode[0] >= '4' {
				if endpointFamily == "trust_artifact" || endpointFamily == "trust_artifact_signature" {
					return gdsClassification{"gds_trust_list_pull_failed", "pki_trust_sync", "warning", "MEDIUM", true}
				}
				return gdsClassification{"gds_client_pull_failed", "security", "warning", "MEDIUM", true}
			}
			if statusCode == "200" {
				if endpointFamily == "trust_artifact" || endpointFamily == "trust_artifact_signature" {
					return gdsClassification{"gds_client_pull_success", "pki_trust_sync", "info", "LOW", false}
				}
				return gdsClassification{"gds_client_pull_success", "pki_validation", "info", "LOW", false}
			}
		}
	}

	if strings.Contains(text, "db") && (strings.Contains(text, "disconnected") || strings.Contains(text, "connection refused") || strings.Contains(text, "postgres") && strings.Contains(text, "false")) {
		return gdsClassification{"gds_db_disconnected", "error", "critical", "HIGH", true}
	}
	if strings.Contains(text, "preflight") && (strings.Contains(text, "timeout") || strings.Contains(text, "error") || strings.Contains(text, "failed")) {
		return gdsClassification{"gds_db_disconnected", "error", "critical", "HIGH", true}
	}
	if strings.Contains(text, "preflight") && (strings.Contains(text, "success") || strings.Contains(text, "ok") || strings.Contains(text, "reachable")) {
		return gdsClassification{"gds_db_connected", "system_health", "info", "LOW", false}
	}
	if strings.Contains(text, "health transition") && strings.Contains(text, "ok") {
		return gdsClassification{"gds_started", "system_health", "info", "LOW", false}
	}
	if strings.Contains(text, "application startup complete") || strings.Contains(text, "startup complete") {
		return gdsClassification{"gds_started", "system_health", "info", "LOW", false}
	}
	if strings.Contains(strings.ToLower(firstString(rec, "logger")), "gds") && strings.Contains(text, "started") {
		return gdsClassification{"gds_started", "system_health", "info", "LOW", false}
	}
	if strings.Contains(text, "unauthorized") || strings.Contains(text, "auth failure") || strings.Contains(text, "forbidden") || strings.Contains(text, "mtls") && strings.Contains(text, "failure") {
		return gdsClassification{"gds_unauthorized_request", "security", "warning", "MEDIUM", true}
	}
	if strings.Contains(text, "enrollment") && (strings.Contains(text, "request") || strings.Contains(text, "endpoint") || strings.Contains(text, "/enroll") || strings.Contains(text, "/enrollment") || strings.Contains(text, "csr")) {
		if strings.Contains(text, "failed") || strings.Contains(text, "error") || strings.Contains(text, "rejected") {
			return gdsClassification{"gds_enrollment_failed", "pki_lifecycle", "warning", "MEDIUM", true}
		}
		if strings.Contains(text, "validated") || strings.Contains(text, "created") || strings.Contains(text, "approved") {
			return gdsClassification{"gds_enrollment_approved", "pki_lifecycle", "info", "LOW", false}
		}
		return gdsClassification{"gds_enrollment_request", "pki_lifecycle", "info", "LOW", false}
	}
	if strings.Contains(text, "csr") && strings.Contains(text, "validated") && strings.Contains(text, "package") && strings.Contains(text, "created") {
		return gdsClassification{"gds_enrollment_approved", "pki_lifecycle", "info", "LOW", false}
	}
	if strings.Contains(text, "artifact regenerated") || strings.Contains(text, "trustlist_artifact_rebuild") {
		return gdsClassification{"gds_trust_list_published", "pki_trust_sync", "info", "MEDIUM", false}
	}
	if strings.Contains(text, "trustlist") && strings.Contains(text, "artifact") && (strings.Contains(text, "failed") || strings.Contains(text, "error")) {
		return gdsClassification{"gds_trust_list_pull_failed", "pki_trust_sync", "warning", "MEDIUM", true}
	}
	if strings.Contains(text, "nginx") && (strings.Contains(text, " 4") || strings.Contains(text, " 5")) && (strings.Contains(text, "artifact") || strings.Contains(text, "trustlist") || strings.Contains(text, "package")) {
		return gdsClassification{"gds_trust_list_pull_failed", "pki_trust_sync", "warning", "MEDIUM", true}
	}
	if strings.Contains(text, "expiry_state") && strings.Contains(text, "expired") {
		return gdsClassification{"gds_certificate_expired", "pki_validation", "warning", "MEDIUM", true}
	}
	if strings.Contains(text, "drift") && (strings.Contains(text, "report") || strings.Contains(text, "api") || strings.Contains(text, "db")) {
		return gdsClassification{"gds_certificate_expired", "pki_validation", "warning", "MEDIUM", true}
	}
	if strings.Contains(text, "health") && strings.Contains(text, "poll") {
		return gdsClassification{"gds_heartbeat", "system_health", "info", "LOW", false}
	}
	if strings.TrimSpace(firstString(rec, "error_code")) != "" {
		return gdsClassification{"gds_client_pull_failed", "security", "warning", "MEDIUM", true}
	}
	if strings.Contains(text, "gds bootstrap starting") || strings.Contains(text, "starting uvicorn") || strings.Contains(text, "dmz dependencies reachable") {
		return gdsClassification{"gds_started", "system_health", "info", "LOW", false}
	}
	if strings.Contains(text, "expired") && strings.Contains(text, "cert") {
		return gdsClassification{"gds_certificate_expired", "pki_validation", "warning", "MEDIUM", true}
	}
	if status := statusCode(rec); status >= 400 {
		if strings.Contains(text, "artifact") || strings.Contains(text, "trustlist") || strings.Contains(text, "package") {
			return gdsClassification{"gds_trust_list_pull_failed", "pki_trust_sync", "warning", "MEDIUM", true}
		}
		return gdsClassification{"gds_client_pull_failed", "security", "warning", "MEDIUM", true}
	}
	if class := classifyKnownGDSCompactAction(rec, msgText, et); class.Message != "" {
		return class
	}
	return gdsClassification{"gds_event_unknown", "operator_action", "info", "LOW", false}
}

func classifyKnownGDSCompactAction(rec map[string]any, msgText, eventType string) gdsClassification {
	candidates := []string{
		firstString(rec, "gds_action"),
		firstString(rec, "action"),
		eventType,
		msgText,
		firstString(rec, "log_message"),
	}
	if rawMap := mapAny(rec["raw"]); len(rawMap) > 0 {
		candidates = append(candidates, firstString(rawMap, "gds_action"), firstString(rawMap, "action"), firstString(rawMap, "log_message"))
	}
	if rawText := strings.TrimSpace(stringAny(rec["raw"])); rawText != "" {
		candidates = append(candidates, rawText, parseGDSRawText(rawText))
		var rawObj map[string]any
		if err := json.Unmarshal([]byte(rawText), &rawObj); err == nil {
			candidates = append(candidates, firstString(rawObj, "gds_action"), firstString(rawObj, "action"), firstString(rawObj, "log_message"))
		}
	}
	for _, candidate := range candidates {
		_, action := splitGDSFamilyAction(strings.TrimSpace(candidate))
		if class := classifyGDSDMZAction(action); class.Message != "gds_event_unknown" {
			return class
		}
		if class := classifyGDSDMZAction(candidate); class.Message != "gds_event_unknown" {
			return class
		}
	}
	return gdsClassification{}
}

func gdsSafeFields(rec map[string]any) map[string]any {
	out := map[string]any{}
	copySafeField(out, rec, "event_type", "event_type")
	copySafeField(out, rec, "gds_family", "gds_family")
	copySafeField(out, rec, "gds_action", "gds_action")
	copySafeField(out, rec, "actor", "actor")
	copySafeField(out, rec, "target", "target")
	copySafeField(out, rec, "application_uri", "application_uri")
	copySafeField(out, rec, "runtime_instance_id", "runtime_instance_id")
	copySafeField(out, rec, "package_id", "package_id")
	copySafeField(out, rec, "request_id", "request_id")
	copySafeField(out, rec, "certificate_id", "certificate_id")
	copySafeField(out, rec, "fingerprint_sha256", "fingerprint_sha256")
	copySafeField(out, rec, "certificate_fingerprint_sha256", "certificate_fingerprint_sha256")
	copySafeField(out, rec, "serial_number", "serial_number")
	copySafeField(out, rec, "trustlist_zone", "trustlist_zone")
	copySafeField(out, rec, "trustlist_role", "trustlist_role")
	copySafeField(out, rec, "trustlist_version", "trustlist_version")
	copySafeField(out, rec, "artifact_revision", "artifact_revision")
	copySafeField(out, rec, "artifact_sha256", "artifact_sha256")
	copySafeField(out, rec, "error_code", "error_code")
	copySafeField(out, rec, "correlation_id", "correlation_id")
	copySafeField(out, rec, "source_ip", "source_ip")
	copySafeField(out, rec, "client_ip", "client_ip")
	copySafeField(out, rec, "user_agent", "user_agent")
	copySafeField(out, rec, "http_method", "http_method")
	copySafeField(out, rec, "http_path", "http_path")
	copySafeField(out, rec, "http_status", "http_status")
	copySafeField(out, rec, "endpoint_family", "endpoint_family")
	copySafeField(out, rec, "mtls_verify_status", "mtls_verify_status")
	copySafeField(out, rec, "logger", "logger")
	copySafeField(out, rec, "level", "level")
	copySafeField(out, rec, "status", "status")
	copySafeField(out, rec, "component", "component")
	copySafeField(out, rec, "generated_at", "generated_at")
	copySafeField(out, rec, "created_at", "created_at")
	copySafeField(out, rec, "reported_at", "reported_at")
	copySafeField(out, rec, "table", "table")
	copySafeField(out, rec, "row_count", "row_count")
	copySafeField(out, rec, "latest_id", "latest_id")
	copySafeField(out, rec, "latest_created_at", "latest_created_at")
	copySafeField(out, rec, "latest_updated_at", "latest_updated_at")
	copySafeField(out, rec, "db_connected", "db_connected")
	copySafeField(out, rec, "checks", "checks")
	copySafeField(out, rec, "postgres", "postgres")
	copySafeField(out, rec, "tables", "tables")
	copySafeField(out, rec, "reason", "reason")
	copySafeField(out, rec, "error", "error")
	copySafeField(out, rec, "line", "line")

	if raw := mapAny(rec["raw"]); len(raw) > 0 {
		for _, key := range []string{"event_type", "actor", "target", "application_uri", "runtime_instance_id", "package_id", "request_id", "certificate_id", "fingerprint_sha256", "certificate_fingerprint_sha256", "serial_number", "trustlist_zone", "trustlist_role", "trustlist_version", "artifact_revision", "artifact_sha256", "error_code", "correlation_id", "source_ip", "mtls_verify_status", "status", "component", "generated_at", "created_at", "reported_at", "table", "row_count", "latest_id", "latest_created_at", "latest_updated_at", "db_connected", "checks", "postgres", "tables", "log_message", "gds_action", "gds_family"} {
			copySafeField(out, raw, key, key)
		}
	}

	if details := mapAny(rec["details_json"]); len(details) > 0 {
		redacted := redactMap(details)
		for _, key := range []string{"application_uri", "runtime_instance_id", "package_id", "request_id", "certificate_id", "fingerprint_sha256", "certificate_fingerprint_sha256", "serial_number", "trustlist_zone", "trustlist_role", "trustlist_version", "artifact_revision", "artifact_sha256", "error_code", "correlation_id", "source_ip", "mtls_verify_status", "reason", "status"} {
			copySafeField(out, redacted, key, key)
		}
		out["details_json"] = compactGDSMap(redacted)
	}
	return compactGDSMap(out)
}

func redactMap(in map[string]any) map[string]any {
	out := make(map[string]any, len(in))
	for k, v := range in {
		if isGDSSensitiveKey(k) {
			continue
		}
		switch t := v.(type) {
		case map[string]any:
			out[k] = redactMap(t)
		case []any:
			arr := make([]any, 0, len(t))
			for _, item := range t {
				if m, ok := item.(map[string]any); ok {
					arr = append(arr, redactMap(m))
					continue
				}
				arr = append(arr, item)
			}
			out[k] = arr
		case string:
			if looksLikeGDSSecret(k, t) {
				continue
			}
			out[k] = t
		default:
			out[k] = v
		}
	}
	return out
}

func redactGDSOPCUAFacadeValue(v any) any {
	switch t := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, item := range t {
			if isGDSOPCUAFacadeSensitiveKey(k) {
				out[k] = "[REDACTED]"
				continue
			}
			out[k] = redactGDSOPCUAFacadeValue(item)
		}
		return out
	case []any:
		out := make([]any, 0, len(t))
		for _, item := range t {
			out = append(out, redactGDSOPCUAFacadeValue(item))
		}
		return out
	case string:
		if looksLikeGDSOPCUAFacadeSecret(t) {
			return "[REDACTED]"
		}
		return t
	default:
		return v
	}
}

func isGDSOPCUAFacadeSensitiveKey(key string) bool {
	k := strings.ToLower(strings.TrimSpace(key))
	k = strings.NewReplacer("-", "_", ".", "_").Replace(k)
	switch k {
	case "private_key", "key", "token", "secret", "password", "client_token", "secret_id", "role_id", "accessor", "authorization":
		return true
	default:
		return false
	}
}

func looksLikeGDSOPCUAFacadeSecret(value string) bool {
	lower := strings.ToLower(value)
	return strings.Contains(lower, "-----begin private key-----") ||
		strings.Contains(lower, "-----end private key-----") ||
		strings.HasPrefix(strings.TrimSpace(lower), "bearer ")
}

func isGDSSensitiveKey(key string) bool {
	k := strings.ToLower(strings.TrimSpace(key))
	sensitive := []string{"token", "authorization", "password", "passwd", "private_key", "privatekey", "key_pem", "pem", "csr", "csr_pem", "certificate_pem", "certificate_body", "cert_body", "full_certificate", "cert_pem", "ca_chain", "ca_chain_pem", "crl", "crl_body", "crl_base64", "crl_bundle", "signature", "secret"}
	if strings.Contains(k, "accessor") {
		return false
	}
	for _, item := range sensitive {
		if k == item || strings.Contains(k, item) {
			return true
		}
	}
	return false
}

func looksLikeGDSSecret(key, value string) bool {
	lower := strings.ToLower(value)
	return strings.Contains(lower, "-----begin ") || strings.Contains(lower, "-----end ") || strings.Contains(lower, "private key") || len(value) > 8192 && isGDSSensitiveKey(key)
}

func eventTypeFromMessage(msg string) string {
	text := strings.ToLower(strings.TrimSpace(msg))
	switch {
	case strings.Contains(text, "artifact regenerated"):
		return "artifact_regenerated"
	case strings.Contains(text, "gds bootstrap starting"), strings.Contains(text, "starting uvicorn"), strings.Contains(text, "dmz dependencies reachable"):
		return "gds_started"
	case strings.Contains(text, "unauthorized"), strings.Contains(text, "auth failure"):
		return "agent_auth_failure"
	default:
		return ""
	}
}

func normalizeGDSEventType(v string) string {
	return strings.ToLower(strings.TrimSpace(strings.ReplaceAll(v, "-", "_")))
}

func parseGDSKeyValues(line string) map[string]any {
	out := map[string]any{}
	for _, match := range gdsKVPattern.FindAllStringSubmatch(line, -1) {
		value := strings.Trim(match[2], `"`)
		if isGDSSensitiveKey(match[1]) || looksLikeGDSSecret(match[1], value) {
			continue
		}
		out[match[1]] = value
	}
	return out
}

func copySafeField(out map[string]any, in map[string]any, source, dest string) {
	if in == nil {
		return
	}
	if isGDSSensitiveKey(source) || isGDSSensitiveKey(dest) {
		return
	}
	if v, ok := in[source]; ok && v != nil {
		out[dest] = v
	}
}

func firstString(rec map[string]any, keys ...string) string {
	for _, key := range keys {
		if v := stringAny(rec[key]); strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	if details := mapAny(rec["details_json"]); len(details) > 0 {
		for _, key := range keys {
			if v := stringAny(details[key]); strings.TrimSpace(v) != "" {
				return strings.TrimSpace(v)
			}
		}
	}
	if raw := mapAny(rec["raw"]); len(raw) > 0 {
		for _, key := range keys {
			if v := stringAny(raw[key]); strings.TrimSpace(v) != "" {
				return strings.TrimSpace(v)
			}
		}
	}
	return ""
}

func mapAny(v any) map[string]any {
	if m, ok := v.(map[string]any); ok {
		return m
	}
	return map[string]any{}
}

func stringAny(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case json.Number:
		return t.String()
	case float64:
		if t == float64(int64(t)) {
			return fmt.Sprintf("%d", int64(t))
		}
		return fmt.Sprintf("%v", t)
	case nil:
		return ""
	default:
		return fmt.Sprintf("%v", t)
	}
}

func boolValue(v any) bool {
	switch t := v.(type) {
	case bool:
		return t
	case string:
		return strings.EqualFold(t, "true") || t == "1" || strings.EqualFold(t, "ok")
	default:
		return false
	}
}

func statusCode(rec map[string]any) int {
	v := stringAny(rec["status_code"])
	if v == "" {
		v = stringAny(rec["status"])
	}
	var n int
	_, _ = fmt.Sscanf(v, "%d", &n)
	return n
}

func severityFromRecord(rec map[string]any) string {
	level := strings.ToLower(firstString(rec, "severity", "level"))
	switch level {
	case "critical", "error", "warning", "info", "debug":
		if level == "debug" {
			return "info"
		}
		return level
	case "warn":
		return "warning"
	default:
		return "info"
	}
}

func riskFromSeverity(severity string) string {
	switch strings.ToLower(severity) {
	case "critical":
		return "CRITICAL"
	case "error", "warning":
		return "HIGH"
	default:
		return "LOW"
	}
}

func compactGDSMap(in map[string]any) map[string]any {
	out := make(map[string]any, len(in))
	for k, v := range in {
		if v == nil {
			continue
		}
		switch t := v.(type) {
		case string:
			if strings.TrimSpace(t) != "" {
				out[k] = t
			}
		case map[string]any:
			if compact := compactGDSMap(t); len(compact) > 0 {
				out[k] = compact
			}
		default:
			out[k] = v
		}
	}
	return out
}
