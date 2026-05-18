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
	vaultAssetName  = "labshock_vault"
	vaultAssetIP    = "192.168.10.10"
	vaultSourcetype = "labshock:dmz:vault"
)

type vaultAuditClassification struct {
	Message        string
	Category       string
	Severity       string
	RiskLevel      string
	AlertCandidate bool
}

func NormalizeVaultAuditMany(raw []byte) ([]event.Event, error) {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 {
		return nil, fmt.Errorf("empty vault audit payload")
	}

	if raw[0] == '[' {
		var rows []json.RawMessage
		if err := json.Unmarshal(raw, &rows); err != nil {
			return nil, err
		}
		out := make([]event.Event, 0, len(rows))
		for _, row := range rows {
			ev, err := NormalizeVaultAudit(row)
			if err != nil {
				return nil, err
			}
			out = append(out, ev)
		}
		return out, nil
	}

	if raw[0] == '{' {
		ev, err := NormalizeVaultAudit(raw)
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
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		ev, err := NormalizeVaultAudit(line)
		if err != nil {
			return nil, err
		}
		out = append(out, ev)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no vault audit records found")
	}
	return out, nil
}

func NormalizeVaultAudit(raw []byte) (event.Event, error) {
	var rec map[string]any
	if err := json.Unmarshal(raw, &rec); err != nil {
		return event.Event{}, err
	}

	req := mapValue(rec, "request")
	auth := mapValue(rec, "auth")
	resp := mapValue(rec, "response")
	respData := mapValue(resp, "data")

	path := strings.Trim(strings.TrimSpace(stringValue(req, "path")), "/")
	operation := strings.ToLower(strings.TrimSpace(stringValue(req, "operation")))
	errText := strings.TrimSpace(stringValue(rec, "error"))
	auditType := strings.ToLower(strings.TrimSpace(stringValue(rec, "type")))
	displayName := stringValue(auth, "display_name")
	mountType := stringValue(req, "mount_type")

	class := classifyVaultAudit(path, operation, errText, displayName, auditType)
	safeRaw := map[string]any{
		"audit_type":            auditType,
		"vault_operation":       operation,
		"vault_path":            path,
		"vault_namespace":       stringValue(mapValue(req, "namespace"), "id"),
		"request_id":            stringValue(req, "id"),
		"mount_type":            mountType,
		"mount_point":           stringValue(req, "mount_point"),
		"mount_accessor":        stringValue(req, "mount_accessor"),
		"remote_address":        stringValue(req, "remote_address"),
		"remote_port":           stringValue(req, "remote_port"),
		"display_name":          displayName,
		"policy_names":          stringSlice(auth["policies"]),
		"token_policies":        stringSlice(auth["token_policies"]),
		"client_token_accessor": stringValue(req, "client_token_accessor"),
		"error":                 errText,
		"common_name":           stringValue(respData, "common_name"),
		"serial_number":         firstNonEmptyString(stringValue(respData, "serial_number"), stringValue(respData, "serial")),
		"ttl":                   firstNonEmptyString(stringValue(respData, "ttl"), stringValue(respData, "lease_duration")),
	}
	rawJSON, _ := json.Marshal(compactMap(safeRaw))

	tags := map[string]any{
		"component":               "vault",
		"zone":                    "DMZ",
		"collector_decision_hint": "store_forward",
		"risk_level":              class.RiskLevel,
		"normalized":              true,
		"normalization_source":    "logs_by_sources_md",
		"parser_version":          "v2.logs_by_sources_md",
		"splunk_sourcetype":       vaultSourcetype,
		"siem_index_hint":         "ot_security",
		"vault_operation":         operation,
		"vault_path":              path,
		"vault_namespace":         stringValue(mapValue(req, "namespace"), "id"),
		"client_token_accessor":   stringValue(req, "client_token_accessor"),
		"remote_address":          stringValue(req, "remote_address"),
		"mount_type":              mountType,
		"audit_type":              auditType,
	}
	if class.AlertCandidate {
		tags["alert_candidate"] = true
	}
	if displayName == "root" {
		tags["root_token_used"] = true
	}
	if errText != "" {
		tags["error"] = errText
	}

	ts := strings.TrimSpace(stringValue(rec, "time"))
	if ts == "" {
		ts = time.Now().UTC().Format(time.RFC3339Nano)
	}

	ev := event.Event{
		Timestamp:     ts,
		ReceivedAt:    time.Now().UTC().Format(time.RFC3339Nano),
		Zone:          "DMZ",
		Source:        "vault_audit",
		SourceType:    "vault",
		AssetName:     vaultAssetName,
		AssetIP:       vaultAssetIP,
		Severity:      class.Severity,
		Protocol:      "vault_audit_file",
		EventCategory: class.Category,
		Message:       class.Message,
		Raw:           string(rawJSON),
		Tags:          compactMap(tags),
	}
	ev.EnsureDefaults()
	ev.OriginalRaw = append(ev.OriginalRaw, raw...)
	return ev, nil
}

func classifyVaultAudit(path, operation, errText, displayName, auditType string) vaultAuditClassification {
	p := strings.ToLower(path)
	op := strings.ToLower(operation)
	errLower := strings.ToLower(errText)

	if strings.HasPrefix(p, "sys/audit") && errText != "" {
		return vaultAuditClassification{"vault_audit_log_failure", "security", "critical", "CRITICAL", true}
	}
	if strings.Contains(errLower, "permission denied") || strings.Contains(errLower, "policy") {
		return vaultAuditClassification{"vault_policy_violation", "security", "critical", "CRITICAL", true}
	}
	if strings.HasPrefix(p, "auth/") && errText != "" {
		return vaultAuditClassification{"vault_auth_failure", "access_control", "warning", "HIGH", true}
	}
	if strings.Contains(p, "/revoke") || strings.HasSuffix(p, "revoke") {
		return vaultAuditClassification{"vault_pki_revoke", "certificate_lifecycle", "warning", "HIGH", true}
	}
	if strings.Contains(p, "/issue/") || strings.HasSuffix(p, "/issue") {
		return vaultAuditClassification{"vault_pki_issue", "pki_lifecycle", "info", "LOW", false}
	}
	if strings.Contains(p, "/sign/") || strings.HasSuffix(p, "/sign") {
		return vaultAuditClassification{"vault_pki_sign", "pki_lifecycle", "info", "LOW", false}
	}
	if strings.Contains(p, "/tidy") || strings.HasSuffix(p, "tidy") {
		return vaultAuditClassification{"vault_pki_tidy", "pki_lifecycle", "info", "LOW", false}
	}
	if strings.Contains(p, "lease") && strings.Contains(p, "renew") {
		return vaultAuditClassification{"vault_lease_renewed", "pki_lifecycle", "info", "LOW", false}
	}
	if strings.Contains(p, "lease") && strings.Contains(p, "expire") {
		return vaultAuditClassification{"vault_lease_expired", "pki_lifecycle", "warning", "HIGH", true}
	}
	if strings.HasPrefix(p, "auth/token/create") {
		return vaultAuditClassification{"vault_token_created", "access_control", "info", "LOW", false}
	}
	if strings.HasPrefix(p, "auth/token/revoke") {
		return vaultAuditClassification{"vault_token_revoked", "access_control", "info", "LOW", false}
	}
	if strings.HasPrefix(p, "auth/") && errText == "" && auditType == "response" {
		return vaultAuditClassification{"vault_auth_success", "access_control", "info", "LOW", false}
	}
	if displayName == "root" && auditType == "response" && !strings.HasPrefix(p, "auth/token/lookup-self") {
		return vaultAuditClassification{"vault_root_token_used", "security", "critical", "CRITICAL", true}
	}
	if strings.HasPrefix(p, "secret/") || strings.Contains(p, "/data/") {
		switch op {
		case "read", "list":
			return vaultAuditClassification{"vault_secret_read", "operator_action", "info", "LOW", false}
		case "create", "update", "patch":
			return vaultAuditClassification{"vault_secret_write", "operator_action", "warning", "MEDIUM", false}
		case "delete":
			return vaultAuditClassification{"vault_secret_delete", "security", "warning", "HIGH", true}
		}
	}
	if errText != "" {
		return vaultAuditClassification{"vault_policy_violation", "security", "critical", "CRITICAL", true}
	}
	return vaultAuditClassification{"vault_request", "operator_action", "info", "LOW", false}
}

func mapValue(in map[string]any, key string) map[string]any {
	if in == nil {
		return map[string]any{}
	}
	if m, ok := in[key].(map[string]any); ok {
		return m
	}
	return map[string]any{}
}

func stringValue(in map[string]any, key string) string {
	if in == nil {
		return ""
	}
	v, ok := in[key]
	if !ok || v == nil {
		return ""
	}
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
	default:
		return fmt.Sprintf("%v", t)
	}
}

func stringSlice(v any) []string {
	arr, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(arr))
	for _, item := range arr {
		s := strings.TrimSpace(fmt.Sprintf("%v", item))
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}

func compactMap(in map[string]any) map[string]any {
	out := make(map[string]any, len(in))
	for k, v := range in {
		switch t := v.(type) {
		case string:
			if strings.TrimSpace(t) != "" {
				out[k] = t
			}
		case []string:
			if len(t) > 0 {
				out[k] = t
			}
		case nil:
		default:
			out[k] = v
		}
	}
	return out
}

func firstNonEmptyString(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}
