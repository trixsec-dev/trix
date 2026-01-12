package cmd

import (
	"context"
	"log/slog"
	"os"

	"github.com/spf13/cobra"
	"github.com/trixsec-dev/trix/internal/server"
)

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Run as a long-running server",
	Long: `Run trix as a daemon that continuously monitors Trivy findings
and sends notifications when vulnerabilities are discovered or fixed.

Required environment variables:
  TRIX_DATABASE_URL       PostgreSQL connection string

Optional environment variables:
  TRIX_POLL_INTERVAL      How often to poll (default: 5m)
  TRIX_NAMESPACES         Comma-separated namespaces to watch (default: all)
  TRIX_NOTIFY_SLACK       Slack incoming webhook URL
  TRIX_NOTIFY_WEBHOOK     Generic webhook URL for notifications
  TRIX_NOTIFY_SEVERITY    Minimum severity to notify (default: CRITICAL)
  TRIX_LOG_FORMAT         Log format: json or text (default: json)
  TRIX_LOG_LEVEL          Log level: debug, info, warn, error (default: info)
  TRIX_HEALTH_ADDR        Health endpoint address (default: :8080)`,
	RunE: runServe,
}

func init() {
	rootCmd.AddCommand(serveCmd)
}

func runServe(cmd *cobra.Command, args []string) error {
	cfg, err := server.LoadConfig()
	if err != nil {
		return err
	}
	cfg.Version = Version

	logger := setupLogger(cfg.LogFormat, cfg.LogLevel)

	srv, err := server.New(cfg, logger)
	if err != nil {
		return err
	}

	logger.Info("trix server starting",
		"poll_interval", cfg.PollInterval,
		"namespaces", cfg.Namespaces,
		"notify_slack", cfg.SlackWebhook != "",
		"notify_webhook", cfg.GenericWebhook != "",
	)

	return srv.Run(context.Background())
}

func setupLogger(format, level string) *slog.Logger {
	var handler slog.Handler

	opts := &slog.HandlerOptions{}
	switch level {
	case "debug":
		opts.Level = slog.LevelDebug
	case "warn":
		opts.Level = slog.LevelWarn
	case "error":
		opts.Level = slog.LevelError
	default:
		opts.Level = slog.LevelInfo
	}

	if format == "json" {
		handler = slog.NewJSONHandler(os.Stdout, opts)
	} else {
		handler = slog.NewTextHandler(os.Stdout, opts)
	}

	return slog.New(handler)
}
