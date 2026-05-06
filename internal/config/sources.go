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
		{Name: "Vault", Type: "vault", Endpoint: "http://192.168.10.10:8200", Enabled: false},
		{Name: "InfluxDB", Type: "influxdb", Endpoint: "http://192.168.10.15:8086", Enabled: true},
		{Name: "OPC UA DMZ Gateway", Type: "opcua_gateway", Endpoint: "192.168.10.20", Enabled: true},
		{Name: "Firewall Future", Type: "firewall", Endpoint: "udp://0.0.0.0:5514", Enabled: false},
		{Name: "IDS Future", Type: "ids", Endpoint: "/ids/alerts", Enabled: true},
	}
}

