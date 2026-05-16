package sourceutil

import "strings"

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
	case "influxdb", "opcua_gateway", "collector", "vault":
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
	default:
		return "labshock:ot:unknown"
	}
}