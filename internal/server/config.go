package server

import (
	"fmt"
	"os"
	"strings"
	"time"
)

// Config holds all server configuration parsed from environment variables.
type Config struct {
	// Database
	DatabaseURL string

	// Polling
	PollInterval time.Duration
	Namespaces   []string // Empty = all namespaces

	// Notifications
	SlackWebhook   string
	GenericWebhook string
	MinSeverity    string // CRITICAL, HIGH, MEDIUM, LOW

	// Logging
	LogFormat string // json, text
	LogLevel  string // debug, info, warn, error

	// Health server
	HealthAddr string
}

// LoadConfig reads configuration from environment variables.
func LoadConfig() (*Config, error) {
	cfg := &Config{
		// Defaults
		PollInterval: 5 * time.Minute,
		MinSeverity:  "CRITICAL",
		LogFormat:    "json",
		LogLevel:     "info",
		HealthAddr:   ":8080",
	}

	// Required
	cfg.DatabaseURL = os.Getenv("TRIX_DATABASE_URL")
	if cfg.DatabaseURL == "" {
		return nil, fmt.Errorf("TRIX_DATABASE_URL is required")
	}

	// Optional: Poll interval
	if v := os.Getenv("TRIX_POLL_INTERVAL"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			return nil, fmt.Errorf("invalid TRIX_POLL_INTERVAL: %w", err)
		}
		cfg.PollInterval = d
	}

	// Optional: Namespaces (comma-separated)
	if v := os.Getenv("TRIX_NAMESPACES"); v != "" {
		cfg.Namespaces = strings.Split(v, ",")
		for i := range cfg.Namespaces {
			cfg.Namespaces[i] = strings.TrimSpace(cfg.Namespaces[i])
		}
	}

	// Notifications
	cfg.SlackWebhook = os.Getenv("TRIX_NOTIFY_SLACK")
	cfg.GenericWebhook = os.Getenv("TRIX_NOTIFY_WEBHOOK")

	if v := os.Getenv("TRIX_NOTIFY_SEVERITY"); v != "" {
		cfg.MinSeverity = strings.ToUpper(v)
	}

	// Logging
	if v := os.Getenv("TRIX_LOG_FORMAT"); v != "" {
		cfg.LogFormat = v
	}
	if v := os.Getenv("TRIX_LOG_LEVEL"); v != "" {
		cfg.LogLevel = v
	}

	// Health
	if v := os.Getenv("TRIX_HEALTH_ADDR"); v != "" {
		cfg.HealthAddr = v
	}

	return cfg, nil
}

// HasNotifications returns true if at least one notification target is configured.
func (c *Config) HasNotifications() bool {
	return c.SlackWebhook != "" || c.GenericWebhook != ""
}
