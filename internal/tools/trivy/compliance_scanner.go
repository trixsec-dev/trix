package trivy

import (
	"context"
	"fmt"
)

// TrivyComplianceScanner scans for compliance issues using Trivy Operator CRDs
type TrivyComplianceScanner struct {
	client *Client
}

// NewTrivyComplianceScanner creates a new compliance scanner
func NewTrivyComplianceScanner(client *Client) *TrivyComplianceScanner {
	return &TrivyComplianceScanner{client: client}
}

// Name returns the scanner identifier
func (s *TrivyComplianceScanner) Name() string {
	return "trivy-compliance"
}

// Scan queries ConfigAuditReports and returns findings
func (s *TrivyComplianceScanner) Scan(ctx context.Context, namespace string) ([]Finding, error) {
	reports, err := s.client.ListConfigAuditReports(ctx, namespace)
	if err != nil {
		return nil, fmt.Errorf("failed to list config audit reports: %w", err)
	}

	var findings []Finding

	for _, report := range reports {
		// Extract metadata
		metadata, ok := report["metadata"].(map[string]interface{})
		if !ok {
			continue
		}
		name, _ := metadata["name"].(string)
		ns, _ := metadata["namespace"].(string)

		// Parse compliance checks
		checks, err := s.client.ParseComplianceChecks(report)
		if err != nil {
			continue
		}

		// Convert each failed check to a Finding
		for _, c := range checks {
			if c.Success {
				continue // Only report failures
			}
			finding := ComplianceCheckToFinding(c, ns, name)
			findings = append(findings, finding)
		}
	}

	return findings, nil
}
