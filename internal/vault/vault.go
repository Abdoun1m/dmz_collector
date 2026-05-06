package vault

import (
	"log/slog"

	"github.com/Abdoun1m/dmz_collector/internal/config"
)

type Client struct {
	cfg    config.VaultConfig
	logger *slog.Logger
}

func New(cfg config.VaultConfig, logger *slog.Logger) *Client {
	return &Client{cfg: cfg, logger: logger}
}

func (c *Client) LoadSecrets() map[string]string {
	if !c.cfg.Enabled {
		c.logger.Info("vault integration disabled")
		return map[string]string{}
	}
	c.logger.Info("vault integration is stubbed in v1", "addr", c.cfg.Addr, "path", c.cfg.SecretPath)
	return map[string]string{}
}

