package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

type Notifier struct {
	config     *Config
	httpClient *http.Client
	logger     *slog.Logger
}

func NewNotifier(config *Config, logger *slog.Logger) *Notifier {
	return &Notifier{
		config: config,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
		logger: logger,
	}
}

// NotifyInitialized sends a summary notification on first poll.
func (n *Notifier) NotifyInitialized(ctx context.Context, events []VulnerabilityEvent) error {
	var errs []error

	if n.config.SlackWebhook != "" {
		if err := n.sendSlackSummary(ctx, events); err != nil {
			n.logger.Error("slack init notification failed", "error", err)
			errs = append(errs, err)
		}
	}

	if n.config.GenericWebhook != "" {
		if err := n.sendWebhookSummary(ctx, events); err != nil {
			n.logger.Error("webhook init notification failed", "error", err)
			errs = append(errs, err)
		}
	}

	if n.config.SaasEndpoint != "" {
		if err := n.sendSaasSummary(ctx, events); err != nil {
			n.logger.Error("saas init notification failed", "error", err)
			errs = append(errs, err)
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("notification errors: %v", errs)
	}
	return nil
}

func (n *Notifier) Notify(ctx context.Context, events []VulnerabilityEvent) error {
	filtered := n.filterBySeverity(events)
	if len(filtered) == 0 {
		return nil
	}

	var errs []error

	if n.config.SlackWebhook != "" {
		if err := n.sendSlack(ctx, filtered); err != nil {
			n.logger.Error("slack notification failed", "error", err)
			errs = append(errs, err)
		}
	}

	if n.config.GenericWebhook != "" {
		if err := n.sendWebhook(ctx, filtered); err != nil {
			n.logger.Error("webhook notification failed", "error", err)
			errs = append(errs, err)
		}
	}

	if n.config.SaasEndpoint != "" {
		if err := n.sendSaas(ctx, filtered); err != nil {
			n.logger.Error("saas notification failed", "error", err)
			errs = append(errs, err)
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("notification errors: %v", errs)
	}
	return nil
}

func (n *Notifier) filterBySeverity(events []VulnerabilityEvent) []VulnerabilityEvent {
	minLevel := severityLevel(n.config.MinSeverity)
	var filtered []VulnerabilityEvent
	for _, e := range events {
		if severityLevel(e.Severity) <= minLevel {
			filtered = append(filtered, e)
		}
	}
	return filtered
}

func severityLevel(s string) int {
	switch strings.ToUpper(s) {
	case "CRITICAL":
		return 1
	case "HIGH":
		return 2
	case "MEDIUM":
		return 3
	case "LOW":
		return 4
	default:
		return 5
	}
}

func (n *Notifier) sendSlack(ctx context.Context, events []VulnerabilityEvent) error {
	newEvents := filterByType(events, "NEW")
	fixedEvents := filterByType(events, "FIXED")

	var attachments []map[string]interface{}

	// New vulnerabilities attachment (red/orange based on severity)
	if len(newEvents) > 0 {
		grouped := groupByWorkload(newEvents)
		color := "#fd7e14" // orange for HIGH
		for _, e := range newEvents {
			if e.Severity == "CRITICAL" {
				color = "#dc3545" // red
				break
			}
		}

		var lines []string
		for workload, group := range grouped {
			severityCounts := countBySeverity(group)
			var parts []string
			if c := severityCounts["CRITICAL"]; c > 0 {
				parts = append(parts, fmt.Sprintf("%d critical", c))
			}
			if c := severityCounts["HIGH"]; c > 0 {
				parts = append(parts, fmt.Sprintf("%d high", c))
			}
			if c := severityCounts["MEDIUM"]; c > 0 {
				parts = append(parts, fmt.Sprintf("%d medium", c))
			}
			if c := severityCounts["LOW"]; c > 0 {
				parts = append(parts, fmt.Sprintf("%d low", c))
			}
			lines = append(lines, fmt.Sprintf("`%s`\n%s", workload, strings.Join(parts, ", ")))
		}

		attachments = append(attachments, map[string]interface{}{
			"color":     color,
			"title":     fmt.Sprintf("New Vulnerabilities (%d)", len(newEvents)),
			"text":      strings.Join(lines, "\n\n"),
			"mrkdwn_in": []string{"text"},
		})
	}

	// Fixed vulnerabilities attachment (green)
	if len(fixedEvents) > 0 {
		grouped := groupByWorkload(fixedEvents)

		var lines []string
		for workload, group := range grouped {
			lines = append(lines, fmt.Sprintf("`%s`: %d CVEs", workload, len(group)))
		}

		attachments = append(attachments, map[string]interface{}{
			"color":     "#36a64f", // green
			"title":     fmt.Sprintf("Fixed Vulnerabilities (%d)", len(fixedEvents)),
			"text":      strings.Join(lines, "\n"),
			"mrkdwn_in": []string{"text"},
		})
	}

	return n.postJSON(ctx, n.config.SlackWebhook, map[string]interface{}{
		"attachments": attachments,
	})
}

func groupByWorkload(events []VulnerabilityEvent) map[string][]VulnerabilityEvent {
	grouped := make(map[string][]VulnerabilityEvent)
	for _, e := range events {
		grouped[e.Workload] = append(grouped[e.Workload], e)
	}
	return grouped
}

func (n *Notifier) sendWebhook(ctx context.Context, events []VulnerabilityEvent) error {
	payload := map[string]interface{}{
		"timestamp": time.Now().UTC().Format(time.RFC3339),
		"events":    events,
	}
	return n.postJSON(ctx, n.config.GenericWebhook, payload)
}

func (n *Notifier) postJSON(ctx context.Context, url string, payload interface{}) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := n.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode >= 300 {
		return fmt.Errorf("status %d", resp.StatusCode)
	}

	n.logger.Debug("notification sent", "url", url)
	return nil
}

func filterByType(events []VulnerabilityEvent, eventType string) []VulnerabilityEvent {
	var filtered []VulnerabilityEvent
	for _, e := range events {
		if e.Type == eventType {
			filtered = append(filtered, e)
		}
	}
	return filtered
}

func (n *Notifier) sendSlackSummary(ctx context.Context, events []VulnerabilityEvent) error {
	counts := countBySeverity(events)
	total := len(events)

	// Determine color based on highest severity
	color := "#36a64f" // green
	if counts["CRITICAL"] > 0 {
		color = "#dc3545" // red
	} else if counts["HIGH"] > 0 {
		color = "#fd7e14" // orange
	} else if counts["MEDIUM"] > 0 {
		color = "#ffc107" // yellow
	}

	// Build fields for severity breakdown
	var fields []map[string]interface{}
	if c := counts["CRITICAL"]; c > 0 {
		fields = append(fields, map[string]interface{}{"title": "Critical", "value": fmt.Sprintf("%d", c), "short": true})
	}
	if c := counts["HIGH"]; c > 0 {
		fields = append(fields, map[string]interface{}{"title": "High", "value": fmt.Sprintf("%d", c), "short": true})
	}
	if c := counts["MEDIUM"]; c > 0 {
		fields = append(fields, map[string]interface{}{"title": "Medium", "value": fmt.Sprintf("%d", c), "short": true})
	}
	if c := counts["LOW"]; c > 0 {
		fields = append(fields, map[string]interface{}{"title": "Low", "value": fmt.Sprintf("%d", c), "short": true})
	}

	attachment := map[string]interface{}{
		"color":       color,
		"title":       "trix initialized",
		"text":        fmt.Sprintf("Found *%d* vulnerabilities", total),
		"fields":      fields,
		"footer":      "Monitoring started",
		"footer_icon": "https://raw.githubusercontent.com/aquasecurity/trivy/main/docs/imgs/logo.png",
		"mrkdwn_in":   []string{"text"},
	}

	return n.postJSON(ctx, n.config.SlackWebhook, map[string]interface{}{
		"attachments": []map[string]interface{}{attachment},
	})
}

func (n *Notifier) sendWebhookSummary(ctx context.Context, events []VulnerabilityEvent) error {
	counts := countBySeverity(events)
	payload := map[string]interface{}{
		"type":       "initialized",
		"timestamp":  time.Now().UTC().Format(time.RFC3339),
		"total":      len(events),
		"bySeverity": counts,
	}
	return n.postJSON(ctx, n.config.GenericWebhook, payload)
}

func countBySeverity(events []VulnerabilityEvent) map[string]int {
	counts := make(map[string]int)
	for _, e := range events {
		counts[e.Severity]++
	}
	return counts
}

// SAAS notifier methods

func (n *Notifier) sendSaas(ctx context.Context, events []VulnerabilityEvent) error {
	payload := map[string]interface{}{
		"cluster_name": n.config.ClusterName,
		"timestamp":    time.Now().UTC().Format(time.RFC3339),
		"events":       events,
	}
	url := strings.TrimSuffix(n.config.SaasEndpoint, "/") + "/api/v1/events"
	return n.postJSONWithAuth(ctx, url, payload)
}

func (n *Notifier) sendSaasSummary(ctx context.Context, events []VulnerabilityEvent) error {
	counts := countBySeverity(events)
	payload := map[string]interface{}{
		"cluster_name": n.config.ClusterName,
		"type":         "initialized",
		"timestamp":    time.Now().UTC().Format(time.RFC3339),
		"total":        len(events),
		"bySeverity":   counts,
	}
	url := strings.TrimSuffix(n.config.SaasEndpoint, "/") + "/api/v1/events"
	return n.postJSONWithAuth(ctx, url, payload)
}

func (n *Notifier) postJSONWithAuth(ctx context.Context, url string, payload interface{}) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	// Add API key authentication if configured
	if n.config.SaasApiKey != "" {
		req.Header.Set("Authorization", "Bearer "+n.config.SaasApiKey)
	}

	resp, err := n.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode >= 300 {
		return fmt.Errorf("status %d", resp.StatusCode)
	}

	n.logger.Debug("saas notification sent", "url", url)
	return nil
}
