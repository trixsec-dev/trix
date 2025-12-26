package trivy

import (
	"context"
	"fmt"
)

// TrivyVulnScanner scans for vulnerabilities using Trivy Operator CRDs
type TrivyVulnScanner struct {
	client *Client
}

// NewTrivyVulnScanner creates a new vulnerability scanner
func NewTrivyVulnScanner(client *Client) *TrivyVulnScanner {
	return &TrivyVulnScanner{client: client}
}

// Name returns the scanner identifier
func (s *TrivyVulnScanner) Name() string {
	return "trivy-vulns"
}

// Scan queries VulnerabilityReports and returns findings
func (s *TrivyVulnScanner) Scan(ctx context.Context, namespace string) ([]Finding, error) {
	reports, err := s.client.ListVulnerabilityReports(ctx, namespace)
	if err != nil {
		return nil, fmt.Errorf("failed to list vulnerability reports: %w", err)
	}

	var findings []Finding
	for _, report := range reports {
		// Extract Metadata
		metadata, ok := report["metadata"].(map[string]interface{})
		if !ok {
			continue
		}
		name, _ := metadata["name"].(string)
		ns, _ := metadata["namespace"].(string)

		// Parse vulnerabilities
		vulns, err := s.client.ParseVulnerabilities(report)
		if err != nil {
			continue
		}

		// Convert each vulnerability to a Finding
		for _, v := range vulns {
			finding := VulnerabilityToFinding(v, ns, name)
			findings = append(findings, finding)
		}
	}
	return findings, nil
}
