package trivy

import (
	"context"
	"fmt"
)

// TrivyRbacScanner scans for RBAC issues using Trivy Operator CRDs
type TrivyRbacScanner struct {
	client *Client
}

// NewTrivyRbacScanner creates a new RBAC scanner
func NewTrivyRbacScanner(client *Client) *TrivyRbacScanner {
	return &TrivyRbacScanner{client: client}
}

// Name returns the scanner identifier
func (s *TrivyRbacScanner) Name() string {
	return "trivy-rbac"
}

// Scan queries RbacAssessmentReports and returns findings
func (s *TrivyRbacScanner) Scan(ctx context.Context, namespace string) ([]Finding, error) {
	reports, err := s.client.ListRbacAssessmentReports(ctx, namespace)
	if err != nil {
		return nil, fmt.Errorf("failed to list rbac assessment reports: %w", err)
	}

	var findings []Finding

	for _, report := range reports {
		metadata, ok := report["metadata"].(map[string]interface{})
		if !ok {
			continue
		}
		name, _ := metadata["name"].(string)
		ns, _ := metadata["namespace"].(string)

		checks, err := s.client.ParseRbacChecks(report)
		if err != nil {
			continue
		}

		for _, c := range checks {
			if c.Success {
				continue // Only report failures
			}
			finding := RbacCheckToFinding(c, ns, name)
			findings = append(findings, finding)
		}
	}

	return findings, nil
}
