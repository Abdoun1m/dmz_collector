package sourceutil

import "strings"

var placeholderNames = map[string]struct{}{
	"firewall future": {},
	"ids future":      {},
	"future ids":      {},
}

func NormalizeSourceType(raw string) string {
	t := strings.ToLower(strings.TrimSpace(raw))
	switch t {
	case "", "unknown":
		return "unknown"
	case "opnsense", "firewall":
		return "firewall"
	case "gds-agent", "gds_agent":
		return "gds_agent"
	case "fuxa", "fuxa-ui", "scada":
		return "scada"
	case "plc":
		return "plc"
	case "opcua":
		return "opcua"
	case "opcua_gateway":
		return "opcua_gateway"
	case "ews":
		return "ews"
	case "ids":
		return "ids"
	case "influxdb":
		return "influxdb"
	case "dmz_collector", "dmz-collector":
		return "dmz_collector"
	case "vault_agent", "vault-agent":
		return "vault_agent"
	case "gds":
		return "gds"
	case "postgres_gds", "postgres-gds":
		return "postgres_gds"
	case "jumphost", "jump_host", "jump-host":
		return "jumphost"
	case "ot_collector":
		return "collector"
	case "collector":
		return "collector"
	case "vault":
		return "vault"
	case "manual_test":
		return "manual_test"
	default:
		return "unknown"
	}
}

func GroupForSourceType(sourceType string) string {
	switch NormalizeSourceType(sourceType) {
	case "firewall":
		return "Firewall"
	case "plc":
		return "PLCs"
	case "scada":
		return "SCADA / FUXA"
	case "opcua":
		return "OPC UA"
	case "gds_agent":
		return "GDS / PKI"
	case "ews":
		return "Engineering Workstation"
	case "ids":
		return "IDS / Future Monitoring"
	case "influxdb", "opcua_gateway", "collector", "vault", "dmz_collector", "vault_agent", "gds", "postgres_gds", "jumphost":
		return "DMZ Services"
	default:
		return "Unknown / Other"
	}
}

func SplunkSourcetypeFor(sourceType string) string {
	switch NormalizeSourceType(sourceType) {
	case "firewall":
		return "labshock:net:firewall"
	case "plc":
		return "labshock:ot:plc"
	case "opcua":
		return "labshock:ot:opcua"
	case "scada":
		return "labshock:ot:scada"
	case "gds_agent":
		return "labshock:ot:gds"
	case "ews":
		return "labshock:ot:ews"
	case "ids":
		return "labshock:ot:ids"
	case "dmz_collector":
		return "labshock:dmz:dmz_collector"
	case "vault":
		return "labshock:dmz:vault"
	case "vault_agent":
		return "labshock:dmz:vault_agent"
	case "influxdb":
		return "labshock:dmz:influxdb"
	case "opcua_gateway":
		return "labshock:dmz:opcua_gateway"
	case "gds":
		return "labshock:dmz:gds"
	case "postgres_gds":
		return "labshock:dmz:postgres_gds"
	case "jumphost":
		return "labshock:dmz:jumphost"
	default:
		return "labshock:ot:unknown"
	}
}

func IsInternalDMZSourceType(sourceType string) bool {
	switch NormalizeSourceType(sourceType) {
	case "influxdb", "opcua_gateway", "collector", "vault", "dmz_collector", "vault_agent", "gds", "postgres_gds", "jumphost":
		return true
	default:
		return false
	}
}

func IsDirectSIEMSourceType(sourceType string) bool {
	return NormalizeSourceType(sourceType) == "ids"
}

func IsPlaceholderSourceName(name string) bool {
	_, ok := placeholderNames[strings.ToLower(strings.TrimSpace(name))]
	return ok
}

func IsSupportOnlySourceName(name string) bool {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "firewall future", "ids future":
		return true
	default:
		return false
	}
}
