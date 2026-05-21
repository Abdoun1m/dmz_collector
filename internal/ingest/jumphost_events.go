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
	jumphostAssetName     = "labshock_jumphost"
	jumphostAssetIP       = "192.168.10.5"
	jumphostSourceType    = "jumphost"
	jumphostSource        = "jumphost_events"
	jumphostSourcetype    = "labshock:dmz:jumphost"
	jumphostParserVersion = "v1.jumphost_dmz_normalization"
)

var (
	jumphostAcceptedKeyWithCertRe = regexp.MustCompile(`(?i)Accepted publickey for ([^\s]+) from ([^\s]+) port ([0-9]+).*CERT ID ([^\s]+)`)
	jumphostAcceptedKeyRe         = regexp.MustCompile(`(?i)Accepted publickey for ([^\s]+) from ([^\s]+) port ([0-9]+)`)
	jumphostFailedAuthRe          = regexp.MustCompile(`(?i)Failed (?:publickey|password) for (?:invalid user )?([^\s]+) from ([^\s]+) port ([0-9]+)`)
	jumphostInvalidUserRe         = regexp.MustCompile(`(?i)Invalid user ([^\s]+) from ([^\s]+) port ([0-9]+)`)
	jumphostClosedPreauthRe       = regexp.MustCompile(`(?i)Connection closed by ([^\s]+) port ([0-9]+).*preauth`)
	jumphostSessionOpenedRe       = regexp.MustCompile(`(?i)session opened for user ([^\s]+)`)
	jumphostSessionClosedRe       = regexp.MustCompile(`(?i)session closed for user ([^\s]+)`)
	jumphostConnectionFromRe      = regexp.MustCompile(`(?i)Connection from ([^\s]+) port ([0-9]+)`)
)

type jumphostClassification struct {
	Message        string
	Category       string
	Severity       string
	RiskLevel      string
	AlertCandidate bool
}

func NormalizeJumphostEventsMany(raw []byte) ([]event.Event, error) {
	raw = bytes.TrimSpace(raw)
	raw = unwrapJSONStringPayload(raw)
	if len(raw) == 0 {
		return nil, fmt.Errorf("empty jumphost payload")
	}

	if raw[0] == '[' {
		var rows []json.RawMessage
		if err := json.Unmarshal(raw, &rows); err == nil {
			out := make([]event.Event, 0, len(rows))
			for _, row := range rows {
				ev, err := NormalizeJumphostEvent(row)
				if err != nil {
					return nil, err
				}
				out = append(out, ev)
			}
			return out, nil
		}
	}

	if raw[0] == '{' {
		ev, err := NormalizeJumphostEvent(raw)
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
		ev, err := NormalizeJumphostEvent([]byte(line))
		if err != nil {
			ev = normalizeJumphostTextLine(line)
		}
		out = append(out, ev)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no jumphost events found")
	}
	return out, nil
}

func NormalizeJumphostEvent(raw []byte) (event.Event, error) {
	var rec map[string]any
	if err := json.Unmarshal(raw, &rec); err != nil {
		return event.Event{}, err
	}
	rec = redactJumphostValue(rec).(map[string]any)
	rawFields := jumphostRawFields(rec)

	message := normalizeJumphostMessage(firstString(rec, "message", "event_type", "type", "action"))
	if message == "" {
		message = messageFromJumphostText(firstString(rawFields, "message", "msg", "log_message", "detail", "raw"))
	}
	if message == "" {
		message = "jump_event_unknown"
	}

	class := classifyJumphostMessage(message)
	category := validJumphostCategory(firstString(rec, "event_category", "category"))
	if category == "" || message != "jump_event_unknown" {
		category = class.Category
	}
	severity := validJumphostSeverity(firstString(rec, "severity", "level"))
	if severity == "" || message != "jump_event_unknown" {
		severity = class.Severity
	}
	class.Message = message
	class.Category = category
	class.Severity = severity
	class.RiskLevel = riskForJumphost(message, category, severity)
	class.AlertCandidate = jumphostAlertCandidate(message, category, severity)

	return buildJumphostEvent(rec, rawFields, class), nil
}

func NormalizeJumphostSyslog(rec syslogRecord) event.Event {
	rawFields := map[string]any{
		"syslog_message":  rec.Message,
		"syslog_hostname": rec.Hostname,
		"syslog_appname":  rec.AppName,
		"syslog_facility": rec.Facility,
		"syslog_severity": rec.Severity,
		"docker_tag":      rec.DockerTag,
	}
	if strings.TrimSpace(rec.Remote) != "" {
		rawFields["remote_addr"] = rec.Remote
	}
	for k, v := range fieldsFromJumphostSyslogMessage(rec.Message) {
		rawFields[k] = v
	}

	message := messageFromJumphostText(rec.Message)
	if message == "" {
		message = "jump_event_unknown"
	}
	payload := map[string]any{
		"source":  "jumphost_syslog",
		"message": message,
		"raw":     rawFields,
	}
	if isJumphostNoise(rec.Message) {
		payload["low_value"] = true
	}
	ev, err := NormalizeJumphostEvent(mustJSON(payload))
	if err != nil {
		return event.Event{}
	}
	return ev
}

func normalizeJumphostTextLine(line string) event.Event {
	rec := map[string]any{
		"message": messageFromJumphostText(line),
		"raw": map[string]any{
			"detail": line,
		},
	}
	if rec["message"] == "" {
		rec["message"] = "jump_event_unknown"
	}
	ev, err := NormalizeJumphostEvent(mustJSON(rec))
	if err != nil {
		return event.Event{}
	}
	return ev
}

func buildJumphostEvent(rec, rawFields map[string]any, class jumphostClassification) event.Event {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	ts := firstString(rec, "timestamp", "time", "ts", "created_at", "generated_at")
	if ts == "" {
		ts = firstString(rawFields, "timestamp", "time", "ts", "created_at", "generated_at")
	}
	if ts == "" {
		ts = now
	}

	safePayload := compactGDSMap(redactJumphostValue(rec).(map[string]any))
	source := jumphostSource
	if strings.EqualFold(firstString(rec, "source"), "jumphost_syslog") {
		source = "jumphost_syslog"
		safePayload = compactGDSMap(redactJumphostValue(rawFields).(map[string]any))
	}
	rawJSON, _ := json.Marshal(safePayload)

	tags := map[string]any{}
	if incoming := mapAny(rec["tags"]); len(incoming) > 0 {
		for k, v := range redactJumphostValue(incoming).(map[string]any) {
			tags[k] = v
		}
	}
	tags["component"] = "jumphost"
	tags["zone"] = "DMZ"
	tags["purdue_zone"] = "dmz"
	tags["dmz_collector"] = "dmz_collector"
	tags["collector_decision_hint"] = "store_forward"
	tags["normalized"] = true
	tags["normalization_source"] = "jumphost_dmz_collector"
	tags["parser_version"] = jumphostParserVersion
	tags["splunk_sourcetype"] = jumphostSourcetype
	tags["siem_index_hint"] = "ot_security"
	tags["risk_level"] = class.RiskLevel
	if class.AlertCandidate {
		tags["alert_candidate"] = true
	}
	if boolValue(rec["low_value"]) || isJumphostNoise(firstString(rawFields, "syslog_message", "detail", "log_message")) {
		tags["low_value"] = true
		tags["collector_decision_hint"] = "sample"
	}
	if isJumphostHighValue(class.Message) {
		tags["high_value"] = true
	}

	for _, key := range jumphostMetadataKeys {
		if v, ok := rawFields[key]; ok && v != nil {
			tags[key] = v
		}
		if v, ok := rec[key]; ok && v != nil {
			tags[key] = v
		}
	}

	ev := event.Event{
		Timestamp:     ts,
		ReceivedAt:    now,
		Zone:          "DMZ",
		Source:        source,
		SourceType:    jumphostSourceType,
		AssetName:     jumphostAssetName,
		AssetIP:       jumphostAssetIP,
		Severity:      class.Severity,
		Protocol:      protocolForJumphost(class.Message, rec, rawFields),
		EventCategory: class.Category,
		Message:       class.Message,
		Raw:           string(rawJSON),
		Tags:          tags,
		ExtraFields:   map[string]any{"sourcetype": jumphostSourcetype},
	}
	for _, key := range jumphostMetadataKeys {
		if v, ok := tags[key]; ok && v != nil {
			ev.ExtraFields[key] = v
		}
	}
	ev.EnsureDefaults()
	return ev
}

func jumphostRawFields(rec map[string]any) map[string]any {
	if raw := mapAny(rec["raw"]); len(raw) > 0 {
		return redactJumphostValue(raw).(map[string]any)
	}
	if rawText := strings.TrimSpace(stringAny(rec["raw"])); rawText != "" {
		var rawObj map[string]any
		if err := json.Unmarshal([]byte(rawText), &rawObj); err == nil {
			return redactJumphostValue(rawObj).(map[string]any)
		}
		return map[string]any{"detail": redactJumphostValue(rawText)}
	}
	out := map[string]any{}
	for _, key := range jumphostMetadataKeys {
		if v, ok := rec[key]; ok {
			out[key] = v
		}
	}
	for _, key := range []string{"message", "msg", "log_message", "detail"} {
		if v, ok := rec[key]; ok {
			out[key] = v
		}
	}
	return redactJumphostValue(out).(map[string]any)
}

var jumphostMetadataKeys = []string{
	"src_ip", "dst_ip", "user", "sudo_command", "target_zone", "session_id",
	"duration_seconds", "mfa_method", "tty", "pam_service", "remote_addr",
	"src_port", "cert_id",
}

func normalizeJumphostMessage(v string) string {
	msg := strings.ToLower(strings.TrimSpace(strings.ReplaceAll(v, "-", "_")))
	switch msg {
	case "jump_login_attempt", "jump_login_success", "jump_login_failed", "jump_logout",
		"jump_sudo_executed", "jump_sudo_failed", "jump_session_opened",
		"jump_session_closed", "jump_heartbeat", "jump_unauthorized_zone_access",
		"jump_mfa_success", "jump_mfa_failed", "jump_event_unknown",
		"jump_cert_login_success", "jump_invalid_user", "jump_preauth_connection_closed",
		"jump_forward_denied", "jump_session_open", "jump_session_close",
		"jump_password_auth_disabled", "jump_bastion_policy_applied",
		"jump_cert_accepted", "jump_pubkey_postponed", "jump_hostkey_mismatch",
		"jump_session_disconnected", "jump_session_closed_user", "jump_account_locked",
		"jump_connection_started":
		return msg
	default:
		return ""
	}
}

func messageFromJumphostText(text string) string {
	lower := strings.ToLower(text)
	switch {
	case strings.Contains(lower, "accepted certificate id"):
		return "jump_cert_accepted"
	case strings.Contains(lower, "postponed publickey for"):
		return "jump_pubkey_postponed"
	case strings.Contains(lower, "unable to negotiate with") && strings.Contains(lower, "no matching host key type"):
		return "jump_hostkey_mismatch"
	case jumphostAcceptedKeyWithCertRe.MatchString(text):
		return "jump_cert_login_success"
	case jumphostAcceptedKeyRe.MatchString(text):
		return "jump_login_success"
	case jumphostFailedAuthRe.MatchString(text):
		return "jump_login_failed"
	case strings.Contains(lower, "connection closed by invalid user"):
		return "jump_invalid_user"
	case jumphostInvalidUserRe.MatchString(text):
		return "jump_invalid_user"
	case strings.Contains(lower, "not allowed because account is locked"):
		return "jump_account_locked"
	case jumphostClosedPreauthRe.MatchString(text):
		return "jump_preauth_connection_closed"
	case jumphostConnectionFromRe.MatchString(text):
		return "jump_connection_started"
	case strings.Contains(lower, "received disconnect from"):
		return "jump_session_disconnected"
	case strings.Contains(lower, "disconnected from user"):
		return "jump_session_closed_user"
	case strings.Contains(lower, "open failed") || strings.Contains(lower, "administratively prohibited") ||
		strings.Contains(lower, "permitopen") && strings.Contains(lower, "den") ||
		strings.Contains(lower, "forward denied"):
		return "jump_forward_denied"
	case jumphostSessionOpenedRe.MatchString(text):
		return "jump_session_open"
	case jumphostSessionClosedRe.MatchString(text):
		return "jump_session_close"
	case strings.Contains(lower, "user/password ssh access is disabled") || strings.Contains(lower, "passwordauthentication no"):
		return "jump_password_auth_disabled"
	case strings.Contains(lower, "trustedusercakeys") || strings.Contains(lower, "allowtcpforwarding") ||
		strings.Contains(lower, "vault ssh ca bastion policy") ||
		(strings.Contains(lower, "permitopen") && !strings.Contains(lower, "den")):
		return "jump_bastion_policy_applied"
	case strings.Contains(lower, "unauthorized") && strings.Contains(lower, "zone"):
		return "jump_unauthorized_zone_access"
	case strings.Contains(lower, "sudo") && (strings.Contains(lower, "authentication failure") || strings.Contains(lower, "incorrect password") || strings.Contains(lower, "failed")):
		return "jump_sudo_failed"
	case strings.Contains(lower, "sudo"):
		return "jump_sudo_executed"
	case strings.Contains(lower, "failed password") || strings.Contains(lower, "authentication failure"):
		return "jump_login_failed"
	case strings.Contains(lower, "accepted password") || strings.Contains(lower, "accepted publickey") || strings.Contains(lower, "session opened for user"):
		return "jump_login_success"
	case strings.Contains(lower, "session opened"):
		return "jump_session_opened"
	case strings.Contains(lower, "session closed"):
		return "jump_session_closed"
	case strings.Contains(lower, "logout"):
		return "jump_logout"
	case strings.Contains(lower, "heartbeat"):
		return "jump_heartbeat"
	default:
		return ""
	}
}

func classifyJumphostMessage(message string) jumphostClassification {
	switch message {
	case "jump_login_attempt", "jump_login_success", "jump_cert_login_success", "jump_mfa_success",
		"jump_cert_accepted", "jump_pubkey_postponed", "jump_connection_started":
		return jumphostClassification{Category: "access_control", Severity: "info"}
	case "jump_login_failed", "jump_invalid_user", "jump_mfa_failed", "jump_account_locked":
		return jumphostClassification{Category: "access_control", Severity: "warning"}
	case "jump_logout", "jump_session_opened", "jump_session_closed", "jump_session_open", "jump_session_close",
		"jump_preauth_connection_closed", "jump_session_disconnected", "jump_session_closed_user":
		return jumphostClassification{Category: "session", Severity: "info"}
	case "jump_sudo_executed", "jump_sudo_failed", "jump_forward_denied", "jump_hostkey_mismatch":
		return jumphostClassification{Category: "security", Severity: "warning"}
	case "jump_unauthorized_zone_access":
		return jumphostClassification{Category: "security", Severity: "critical"}
	case "jump_password_auth_disabled", "jump_bastion_policy_applied":
		return jumphostClassification{Category: "security_config", Severity: "info"}
	case "jump_heartbeat":
		return jumphostClassification{Category: "system_health", Severity: "info"}
	default:
		return jumphostClassification{Category: "system", Severity: "info"}
	}
}

func validJumphostCategory(v string) string {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "system_health", "access_control", "security", "security_config", "session", "error", "system":
		return strings.ToLower(strings.TrimSpace(v))
	default:
		return ""
	}
}

func validJumphostSeverity(v string) string {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "info", "warning", "error", "critical":
		return strings.ToLower(strings.TrimSpace(v))
	case "warn":
		return "warning"
	default:
		return ""
	}
}

func riskForJumphost(message, category, severity string) string {
	if message == "jump_unauthorized_zone_access" || severity == "critical" {
		return "CRITICAL"
	}
	if message == "jump_sudo_executed" || message == "jump_sudo_failed" || message == "jump_forward_denied" || severity == "warning" || category == "security" {
		return "MEDIUM"
	}
	if severity == "error" {
		return "HIGH"
	}
	return "LOW"
}

func jumphostAlertCandidate(message, category, severity string) bool {
	switch message {
	case "jump_login_failed", "jump_invalid_user", "jump_sudo_executed", "jump_sudo_failed", "jump_unauthorized_zone_access", "jump_mfa_failed", "jump_forward_denied", "jump_hostkey_mismatch", "jump_account_locked":
		return true
	}
	return severity == "warning" || severity == "error" || severity == "critical" || category == "security"
}

func protocolForJumphost(message string, rec, rawFields map[string]any) string {
	blob := strings.ToLower(strings.Join([]string{
		message,
		firstString(rec, "program", "process", "service"),
		firstString(rawFields, "program", "process", "service", "detail", "log_message"),
	}, " "))
	if strings.Contains(blob, "ssh") || strings.Contains(blob, "sshd") || strings.Contains(blob, "pam") ||
		strings.Contains(message, "login") || strings.Contains(message, "session") || strings.Contains(message, "logout") ||
		strings.Contains(message, "forward") || strings.Contains(message, "password_auth") || strings.Contains(message, "bastion_policy") {
		return "ssh"
	}
	return "syslog"
}

func redactJumphostValue(v any) any {
	switch t := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, item := range t {
			if isJumphostSensitiveKey(k) {
				out[k] = "[REDACTED]"
				continue
			}
			out[k] = redactJumphostValue(item)
		}
		return out
	case []any:
		out := make([]any, 0, len(t))
		for _, item := range t {
			out = append(out, redactJumphostValue(item))
		}
		return out
	case string:
		if looksLikeJumphostSecret(t) {
			return "[REDACTED]"
		}
		return t
	default:
		return v
	}
}

func isJumphostSensitiveKey(key string) bool {
	k := strings.ToLower(strings.TrimSpace(key))
	collapsed := strings.NewReplacer("-", "_", ".", "_").Replace(k)
	if collapsed == "key" {
		return true
	}
	for _, item := range []string{"password", "token", "secret", "authorization", "private_key", "credential"} {
		if strings.Contains(collapsed, item) {
			return true
		}
	}
	return false
}

func looksLikeJumphostSecret(value string) bool {
	lower := strings.ToLower(value)
	return strings.Contains(lower, "-----begin ") || strings.HasPrefix(strings.TrimSpace(lower), "bearer ")
}

func fieldsFromJumphostSyslogMessage(message string) map[string]any {
	out := map[string]any{}
	for _, re := range []*regexp.Regexp{jumphostAcceptedKeyWithCertRe, jumphostAcceptedKeyRe, jumphostFailedAuthRe, jumphostInvalidUserRe} {
		if m := re.FindStringSubmatch(message); len(m) >= 4 {
			out["user"] = m[1]
			out["src_ip"] = m[2]
			out["src_port"] = m[3]
			if len(m) >= 5 {
				out["cert_id"] = m[4]
			}
			return out
		}
	}
	if m := jumphostClosedPreauthRe.FindStringSubmatch(message); len(m) >= 3 {
		out["src_ip"] = m[1]
		out["src_port"] = m[2]
		return out
	}
	if m := jumphostConnectionFromRe.FindStringSubmatch(message); len(m) >= 3 {
		out["src_ip"] = m[1]
		out["src_port"] = m[2]
		return out
	}
	for _, re := range []*regexp.Regexp{jumphostSessionOpenedRe, jumphostSessionClosedRe} {
		if m := re.FindStringSubmatch(message); len(m) >= 2 {
			out["user"] = m[1]
			return out
		}
	}
	return out
}

func isJumphostNoise(message string) bool {
	lower := strings.ToLower(message)
	for _, needle := range []string{"crond", "run-parts", "periodic", "wakeup dt", "file root", "user root pid", "child running /bin/sh", "user child is on pid"} {
		if strings.Contains(lower, needle) {
			return true
		}
	}
	return false
}

func isJumphostHighValue(message string) bool {
	switch message {
	case "jump_cert_login_success", "jump_forward_denied", "jump_account_locked", "jump_hostkey_mismatch":
		return true
	default:
		return false
	}
}
