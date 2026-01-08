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
		ns, _ := metadata["namespace"].(string)

		// Extract labels for workload and container info
		labels, _ := metadata["labels"].(map[string]interface{})
		resourceKind, _ := labels["trivy-operator.resource.kind"].(string)
		resourceName, _ := labels["trivy-operator.resource.name"].(string)
		containerName, _ := labels["trivy-operator.container.name"].(string)

		// Default to Pod if no kind specified
		if resourceKind == "" {
			resourceKind = "Pod"
		}

		// Extract artifact info (image details)
		artifact := extractArtifactInfo(report)
		artifact.ContainerName = containerName

		// Parse vulnerabilities
		vulns, err := s.client.ParseVulnerabilities(report)
		if err != nil {
			continue
		}

		// Convert each vulnerability to a Finding
		for _, v := range vulns {
			finding := VulnerabilityToFinding(v, ns, resourceKind, resourceName, artifact)
			findings = append(findings, finding)
		}
	}
	return findings, nil
}

// extractArtifactInfo extracts image repository, tag, and digest from a report
func extractArtifactInfo(report map[string]interface{}) ArtifactInfo {
	artifact := ArtifactInfo{}

	// Navigate to report.artifact
	reportData, ok := report["report"].(map[string]interface{})
	if !ok {
		return artifact
	}

	artifactData, ok := reportData["artifact"].(map[string]interface{})
	if !ok {
		return artifact
	}

	artifact.Repository, _ = artifactData["repository"].(string)
	artifact.Tag, _ = artifactData["tag"].(string)
	artifact.Digest, _ = artifactData["digest"].(string)

	return artifact
}
