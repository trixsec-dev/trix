package trivy

import (
	"context"
	"fmt"
)

// TrivyInfraScanner scans for infrastructure issues using Trivy Operator CRDs
type TrivyInfraScanner struct {
	client *Client
}

// NewTrivyInfraScanner creates a new infra scanner
func NewTrivyInfraScanner(client *Client) *TrivyInfraScanner {
	return &TrivyInfraScanner{client: client}
}

// Name returns the scanner identifier
func (s *TrivyInfraScanner) Name() string {
	return "trivy-infra"
}

// Scan queries InfraAssessmentReports and returns findings
func (s *TrivyInfraScanner) Scan(ctx context.Context, namespace string) ([]Finding, error) {
	reports, err := s.client.ListInfraAssessmentReports(ctx, namespace)
	if err != nil {
		return nil, fmt.Errorf("failed to list infra assessment reports: %w", err)
	}

	var findings []Finding

	for _, report := range reports {
		metadata, ok := report["metadata"].(map[string]interface{})
		if !ok {
			continue
		}
		name, _ := metadata["name"].(string)
		ns, _ := metadata["namespace"].(string)

		checks, err := s.client.ParseInfraChecks(report)
		if err != nil {
			continue
		}

		for _, c := range checks {
			if c.Success {
				continue
			}
			finding := InfraCheckToFinding(c, ns, name)
			findings = append(findings, finding)
		}
	}

	return findings, nil
}
