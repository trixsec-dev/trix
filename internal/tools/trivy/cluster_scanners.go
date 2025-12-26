package trivy

import (
	"context"
	"fmt"
)

// ClusterVulnScanner scans cluster-scoped vulnerability reports
type ClusterVulnScanner struct {
	client *Client
}

func NewClusterVulnScanner(client *Client) *ClusterVulnScanner {
	return &ClusterVulnScanner{client: client}
}

func (s *ClusterVulnScanner) Name() string {
	return "cluster-vulns"
}

func (s *ClusterVulnScanner) Scan(ctx context.Context, _ string) ([]Finding, error) {
	reports, err := s.client.ListClusterVulnerabilityReports(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list cluster vulnerability reports: %w", err)
	}

	var findings []Finding
	for _, report := range reports {
		metadata, ok := report["metadata"].(map[string]interface{})
		if !ok {
			continue
		}
		name, _ := metadata["name"].(string)

		vulns, err := s.client.ParseVulnerabilities(report)
		if err != nil {
			continue
		}

		for _, v := range vulns {
			finding := VulnerabilityToFinding(v, "", name)
			finding.ResourceKind = "Cluster"
			findings = append(findings, finding)
		}
	}
	return findings, nil
}

// ClusterComplianceScanner scans cluster-scoped config audit reports
type ClusterComplianceScanner struct {
	client *Client
}

func NewClusterComplianceScanner(client *Client) *ClusterComplianceScanner {
	return &ClusterComplianceScanner{client: client}
}

func (s *ClusterComplianceScanner) Name() string {
	return "cluster-compliance"
}

func (s *ClusterComplianceScanner) Scan(ctx context.Context, _ string) ([]Finding, error) {
	reports, err := s.client.ListClusterConfigAuditReports(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list cluster config audit reports: %w", err)
	}

	var findings []Finding
	for _, report := range reports {
		metadata, ok := report["metadata"].(map[string]interface{})
		if !ok {
			continue
		}
		name, _ := metadata["name"].(string)

		checks, err := s.client.ParseComplianceChecks(report)
		if err != nil {
			continue
		}

		for _, c := range checks {
			if c.Success {
				continue
			}
			finding := ComplianceCheckToFinding(c, "", name)
			finding.ResourceKind = "Cluster"
			findings = append(findings, finding)
		}
	}
	return findings, nil
}

// ClusterRbacScanner scans cluster-scoped RBAC assessment reports
type ClusterRbacScanner struct {
	client *Client
}

func NewClusterRbacScanner(client *Client) *ClusterRbacScanner {
	return &ClusterRbacScanner{client: client}
}

func (s *ClusterRbacScanner) Name() string {
	return "cluster-rbac"
}

func (s *ClusterRbacScanner) Scan(ctx context.Context, _ string) ([]Finding, error) {
	reports, err := s.client.ListClusterRbacAssessmentReports(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list cluster rbac assessment reports: %w", err)
	}

	var findings []Finding
	for _, report := range reports {
		metadata, ok := report["metadata"].(map[string]interface{})
		if !ok {
			continue
		}
		name, _ := metadata["name"].(string)

		checks, err := s.client.ParseRbacChecks(report)
		if err != nil {
			continue
		}

		for _, c := range checks {
			if c.Success {
				continue
			}
			finding := RbacCheckToFinding(c, "", name)
			finding.ResourceKind = "ClusterRole"
			findings = append(findings, finding)
		}
	}
	return findings, nil
}

// ClusterInfraScanner scans cluster-scoped infra assessment reports
type ClusterInfraScanner struct {
	client *Client
}

func NewClusterInfraScanner(client *Client) *ClusterInfraScanner {
	return &ClusterInfraScanner{client: client}
}

func (s *ClusterInfraScanner) Name() string {
	return "cluster-infra"
}

func (s *ClusterInfraScanner) Scan(ctx context.Context, _ string) ([]Finding, error) {
	reports, err := s.client.ListClusterInfraAssessmentReports(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list cluster infra assessment reports: %w", err)
	}

	var findings []Finding
	for _, report := range reports {
		metadata, ok := report["metadata"].(map[string]interface{})
		if !ok {
			continue
		}
		name, _ := metadata["name"].(string)

		checks, err := s.client.ParseInfraChecks(report)
		if err != nil {
			continue
		}

		for _, c := range checks {
			if c.Success {
				continue
			}
			finding := InfraCheckToFinding(c, "", name)
			finding.ResourceKind = "Cluster"
			findings = append(findings, finding)
		}
	}
	return findings, nil
}
