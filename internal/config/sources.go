package config

type SourceStatus struct {
	Name      string `json:"name"`
	Type      string `json:"type"`
	Endpoint  string `json:"endpoint"`
	Enabled   bool   `json:"enabled"`
	LastSeen  string `json:"last_seen"`
	EventSeen int64  `json:"event_seen"`
}

func DefaultSources() []SourceStatus {
	return []SourceStatus{
		{Name: "OT Collector", Type: "ot_collector", Endpoint: "http://192.168.1.70:8088", Enabled: true},
		{Name: "DMZ Collector", Type: "dmz_collector", Endpoint: "http://192.168.10.70:9000", Enabled: true},
		{Name: "Vault", Type: "vault", Endpoint: "http://192.168.10.10:8200", Enabled: false},
		{Name: "Vault Agent", Type: "vault_agent", Endpoint: "192.168.10.11", Enabled: false},
		{Name: "InfluxDB", Type: "influxdb", Endpoint: "http://192.168.10.15:8086", Enabled: true},
		{Name: "OPC UA DMZ Gateway", Type: "opcua_dmz_gateway", Endpoint: "192.168.10.20", Enabled: true},
		{Name: "LabShock GDS", Type: "gds", Endpoint: "192.168.10.30", Enabled: false},
		{Name: "PostgreSQL GDS", Type: "postgres_gds", Endpoint: "192.168.10.31", Enabled: false},
		{Name: "Jump Host", Type: "jumphost", Endpoint: "192.168.10.5", Enabled: false},
		{Name: "Firewall Future", Type: "firewall", Endpoint: "udp://0.0.0.0:5514", Enabled: false},
		{Name: "IDS Future", Type: "ids", Endpoint: "/ids/alerts", Enabled: true},
	}
}
