package config

type Rule struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Enabled     bool   `json:"enabled"`
}

func DefaultRules() []Rule {
	return []Rule{
		{ID: "dmz-high-value-priority", Name: "High Value Priority", Description: "Prioritize operator_write, security, error/critical, ids/firewall, sensitive actions", Enabled: true},
	}
}

