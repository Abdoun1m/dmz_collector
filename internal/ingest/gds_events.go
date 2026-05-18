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

func NormalizeGDSEventsMany(raw []byte) ([]event.Event, error) {
	raw = bytes.TrimSpace(raw)
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
	rec = redactMap(rec)
	if ev, ok := normalizeGDSHealth(rec); ok {
		return ev, nil
	}

	msgText := strings.TrimSpace(firstString(rec, "msg", "message", "log", "detail", "details"))
	eventType := normalizeGDSEventType(firstString(rec, "event_type", "type", "event", "action", "name"))
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
		class = gdsClassification{Message: "gds_db_disconnected", Category: "error", Severity: "critical", RiskLevel: "CRITICAL", AlertCandidate: true}
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
	safe := gdsSafeFields(rec)
	if eventType != "" {
		safe["event_type"] = eventType
	}
	if msgText != "" {
		safe["log_message"] = msgText
	}
	rawJSON, _ := json.Marshal(compactGDSMap(safe))

	tags := map[string]any{
		"component":               "gds",
		"zone":                    "DMZ",
		"collector_decision_hint": "store_forward",
		"risk_level":              class.RiskLevel,
		"normalized":              true,
		"normalization_source":    "logs_by_sources_md",
		"parser_version":          "v2.logs_by_sources_md",
		"splunk_sourcetype":       gdsSourcetype,
		"siem_index_hint":         "ot_security",
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
	}
	ev.EnsureDefaults()
	return ev
}

func classifyGDSEvent(eventType string, rec map[string]any, msgText string) gdsClassification {
	et := strings.ToLower(strings.TrimSpace(eventType))
	text := strings.ToLower(strings.Join([]string{et, msgText, firstString(rec, "error", "error_code", "reason", "status")}, " "))

	switch et {
	case "gds_started", "application_started", "bootstrap_started":
		return gdsClassification{"gds_started", "system_health", "info", "LOW", false}
	case "gds_heartbeat":
		return gdsClassification{"gds_heartbeat", "system_health", "info", "LOW", false}
	case "gds_db_snapshot":
		return gdsClassification{"gds_db_snapshot", "system_health", "info", "LOW", false}
	case "gds_db_connected":
		return gdsClassification{"gds_db_connected", "system_health", "info", "LOW", false}
	case "gds_db_disconnected":
		return gdsClassification{"gds_db_disconnected", "error", "critical", "CRITICAL", true}
	case "application_register":
		return gdsClassification{"gds_client_registered", "pki_lifecycle", "info", "LOW", false}
	case "certificate_request_created", "certificate_renewal_requested":
		return gdsClassification{"gds_enrollment_request", "pki_lifecycle", "info", "LOW", false}
	case "csr_validated", "component_enrollment_completed":
		return gdsClassification{"gds_enrollment_approved", "pki_lifecycle", "info", "LOW", false}
	case "csr_rejected", "certificate_issue_failed", "certificate_renewal_failed":
		return gdsClassification{"gds_enrollment_failed", "pki_lifecycle", "warning", "HIGH", true}
	case "certificate_issued":
		return gdsClassification{"gds_certificate_issued", "certificate_lifecycle", "info", "LOW", true}
	case "certificate_renewal_packaged", "labshock_gds_component_renewal_result_v1":
		return gdsClassification{"gds_certificate_renewed", "certificate_lifecycle", "info", "LOW", true}
	case "certificate_revoked", "certificate_revocation_crl_refreshed", "package_revoked":
		return gdsClassification{"gds_certificate_revoked", "certificate_lifecycle", "warning", "HIGH", true}
	case "certificate_expired":
		return gdsClassification{"gds_certificate_expired", "pki_validation", "warning", "HIGH", true}
	case "trustlist_build":
		return gdsClassification{"gds_trust_list_updated", "pki_trust_sync", "info", "LOW", false}
	case "artifact_regenerated", "trustlist_artifact_rebuild":
		return gdsClassification{"gds_trust_list_published", "pki_trust_sync", "info", "LOW", true}
	case "trustlist_artifact_read", "component_trust_material_read", "package_manifest_read", "certificate_package_read":
		return gdsClassification{"gds_client_pull_success", "pki_trust_sync", "info", "LOW", false}
	case "trustlist_pull_failed":
		return gdsClassification{"gds_trust_list_pull_failed", "pki_trust_sync", "warning", "HIGH", true}
	case "agent_auth_failure", "agent_unauthorized_pull", "mtls_client_identity_failure":
		return gdsClassification{"gds_unauthorized_request", "security", "warning", "HIGH", true}
	}

	if strings.Contains(text, "db") && (strings.Contains(text, "disconnected") || strings.Contains(text, "connection refused") || strings.Contains(text, "postgres") && strings.Contains(text, "false")) {
		return gdsClassification{"gds_db_disconnected", "error", "critical", "CRITICAL", true}
	}
	if strings.Contains(text, "unauthorized") || strings.Contains(text, "auth failure") || strings.Contains(text, "forbidden") || strings.Contains(text, "mtls") && strings.Contains(text, "failure") {
		return gdsClassification{"gds_unauthorized_request", "security", "warning", "HIGH", true}
	}
	if strings.Contains(text, "artifact regenerated") || strings.Contains(text, "trustlist_artifact_rebuild") {
		return gdsClassification{"gds_trust_list_published", "pki_trust_sync", "info", "LOW", true}
	}
	if strings.Contains(text, "gds bootstrap starting") || strings.Contains(text, "starting uvicorn") || strings.Contains(text, "dmz dependencies reachable") {
		return gdsClassification{"gds_started", "system_health", "info", "LOW", false}
	}
	if strings.Contains(text, "expired") && strings.Contains(text, "cert") {
		return gdsClassification{"gds_certificate_expired", "pki_validation", "warning", "HIGH", true}
	}
	if status := statusCode(rec); status >= 400 {
		return gdsClassification{"gds_client_pull_failed", "security", "warning", "HIGH", true}
	}
	return gdsClassification{"gds_event", "operator_action", severityFromRecord(rec), riskFromSeverity(severityFromRecord(rec)), false}
}

func gdsSafeFields(rec map[string]any) map[string]any {
	out := map[string]any{}
	copySafeField(out, rec, "event_type", "event_type")
	copySafeField(out, rec, "actor", "actor")
	copySafeField(out, rec, "target", "target")
	copySafeField(out, rec, "application_uri", "application_uri")
	copySafeField(out, rec, "runtime_instance_id", "runtime_instance_id")
	copySafeField(out, rec, "package_id", "package_id")
	copySafeField(out, rec, "request_id", "request_id")
	copySafeField(out, rec, "certificate_id", "certificate_id")
	copySafeField(out, rec, "fingerprint_sha256", "fingerprint_sha256")
	copySafeField(out, rec, "serial_number", "serial_number")
	copySafeField(out, rec, "trustlist_zone", "trustlist_zone")
	copySafeField(out, rec, "trustlist_role", "trustlist_role")
	copySafeField(out, rec, "trustlist_version", "trustlist_version")
	copySafeField(out, rec, "artifact_revision", "artifact_revision")
	copySafeField(out, rec, "artifact_sha256", "artifact_sha256")
	copySafeField(out, rec, "error_code", "error_code")
	copySafeField(out, rec, "correlation_id", "correlation_id")
	copySafeField(out, rec, "source_ip", "source_ip")
	copySafeField(out, rec, "mtls_verify_status", "mtls_verify_status")
	copySafeField(out, rec, "logger", "logger")
	copySafeField(out, rec, "level", "level")
	copySafeField(out, rec, "status", "status")
	copySafeField(out, rec, "reason", "reason")
	copySafeField(out, rec, "error", "error")
	copySafeField(out, rec, "line", "line")

	if details := mapAny(rec["details_json"]); len(details) > 0 {
		redacted := redactMap(details)
		for _, key := range []string{"application_uri", "runtime_instance_id", "package_id", "request_id", "certificate_id", "fingerprint_sha256", "serial_number", "trustlist_zone", "trustlist_role", "trustlist_version", "artifact_revision", "artifact_sha256", "error_code", "correlation_id", "source_ip", "mtls_verify_status", "reason"} {
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

func isGDSSensitiveKey(key string) bool {
	k := strings.ToLower(strings.TrimSpace(key))
	sensitive := []string{"token", "client_token", "role_id", "secret_id", "password", "passwd", "private_key", "key_pem", "pem", "certificate_pem", "cert_pem", "csr_pem", "ca_chain_pem", "crl_base64", "crl_bundle", "signature", "secret"}
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
