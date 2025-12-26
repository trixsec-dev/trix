package trivy

import (
	"context"
	"fmt"
)

// BenchmarkScanner scans CIS/NSA benchmark compliance reports
type BenchmarkScanner struct {
	client *Client
}

// NewBenchmarkScanner creates a new benchmark scanner
func NewBenchmarkScanner(client *Client) *BenchmarkScanner {
	return &BenchmarkScanner{client: client}
}

// Name returns the scanner identifier
func (s *BenchmarkScanner) Name() string {
	return "benchmark"
}

// Scan queries ClusterComplianceReports and returns failed controls as findings
func (s *BenchmarkScanner) Scan(ctx context.Context, _ string) ([]Finding, error) {
	reports, err := s.client.ListBenchmarkReports(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list benchmark reports: %w", err)
	}

	var findings []Finding

	for _, report := range reports {
		benchmarkName, controls, err := s.client.ParseBenchmarkControls(report)
		if err != nil {
			continue
		}

		for _, c := range controls {
			if c.TotalFail == 0 {
				continue // Only report failures
			}
			finding := BenchmarkControlToFinding(c, benchmarkName)
			findings = append(findings, finding)
		}
	}

	return findings, nil
}
