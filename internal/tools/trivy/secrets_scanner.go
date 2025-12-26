package trivy

import (
	"context"
	"fmt"
)

// TrivySecretScanner scans for exposed secrets using Trivy Operator CRDs
type TrivySecretScanner struct {
	client *Client
}

// NewTrivySecretScanner creates a new secret scanner
func NewTrivySecretScanner(client *Client) *TrivySecretScanner {
	return &TrivySecretScanner{client: client}
}

// Name returns the scanner identifier
func (s *TrivySecretScanner) Name() string {
	return "trivy-secrets"
}

// Scan queries ExposedSecretReports and returns findings
func (s *TrivySecretScanner) Scan(ctx context.Context, namespace string) ([]Finding, error) {
	reports, err := s.client.ListExposedSecretReports(ctx, namespace)
	if err != nil {
		return nil, fmt.Errorf("failed to list exposed secret reports: %w", err)
	}

	var findings []Finding

	for _, report := range reports {
		metadata, ok := report["metadata"].(map[string]interface{})
		if !ok {
			continue
		}
		name, _ := metadata["name"].(string)
		ns, _ := metadata["namespace"].(string)

		secrets, err := s.client.ParseExposedSecrets(report)
		if err != nil {
			continue
		}

		for _, secret := range secrets {
			finding := ExposedSecretToFinding(secret, ns, name)
			findings = append(findings, finding)
		}
	}

	return findings, nil
}
