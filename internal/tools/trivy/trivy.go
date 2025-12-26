package trivy

import (
	"context"
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// ListVulnerabilityReports queries Trivy VulnerabilityReport CRDs
func (c *Client) ListVulnerabilityReports(ctx context.Context, namespace string) ([]map[string]interface{}, error) {
	// Define the GVR (GroupVersionResource) for VulnerabilityReports
	gvr := schema.GroupVersionResource{
		Group:    "aquasecurity.github.io",
		Version:  "v1alpha1",
		Resource: "vulnerabilityreports",
	}

	// Query the resources
	list, err := c.dynamicClient.Resource(gvr).Namespace(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list vulnerability reports: %w", err)
	}

	// Convert to slice of maps
	var reports []map[string]interface{}
	for _, item := range list.Items {
		reports = append(reports, item.Object)
	}

	return reports, nil
}

// ParseVulnerabilities extracts vulnerability details from a report
func (c *Client) ParseVulnerabilities(report map[string]interface{}) ([]Vulnerability, error) {
	var vulns []Vulnerability

	// Navigate to report.vulnerabilities array
	reportData, ok := report["report"].(map[string]interface{})
	if !ok {
		return vulns, fmt.Errorf("no report data found")
	}

	vulnArray, ok := reportData["vulnerabilities"].([]interface{})
	if !ok {
		return vulns, nil // No vulnerabilities = empty slice, not error
	}

	// Parse each vulnerability
	for _, item := range vulnArray {
		vulnMap, ok := item.(map[string]interface{})
		if !ok {
			continue
		}

		vuln := Vulnerability{
			VulnerabilityID:  getString(vulnMap, "vulnerabilityID"),
			PkgName:          getString(vulnMap, "resource"),
			InstalledVersion: getString(vulnMap, "installedVersion"),
			FixedVersion:     getString(vulnMap, "fixedVersion"),
			Severity:         getString(vulnMap, "severity"),
			Title:            getString(vulnMap, "title"),
		}

		// CVSS score might be nested or missing
		if score, ok := vulnMap["score"].(float64); ok {
			vuln.Score = score
		}

		vulns = append(vulns, vuln)
	}

	return vulns, nil
}

// getString safely extracts string values from maps
func getString(m map[string]interface{}, key string) string {
	if val, ok := m[key].(string); ok {
		return val
	}
	return ""
}

const MinTrivyOperatorVersion = "0.20.0" // minimum supported version

// CheckTrivyOperator verifies if Trivy Operator is installed and gets version
func (c *Client) CheckTrivyOperator(ctx context.Context) (bool, string) {
	// Try to list VulnerabilityReports CRD in any namespace
	gvr := schema.GroupVersionResource{
		Group:    "aquasecurity.github.io",
		Version:  "v1alpha1",
		Resource: "vulnerabilityreports",
	}

	// Try to list in trivy-system namespace first, fallback to default
	_, err := c.dynamicClient.Resource(gvr).Namespace("trivy-system").List(ctx, metav1.ListOptions{Limit: 1})
	if err != nil {
		// Try default namespace as fallback
		_, err = c.dynamicClient.Resource(gvr).Namespace("default").List(ctx, metav1.ListOptions{Limit: 1})
		if err != nil {
			// CRD might not exist or no access
			return false, ""
		}
	}

	// Get Trivy Operator deployment to extract version
	deploy, err := c.clientset.AppsV1().Deployments("trivy-system").Get(ctx, "trivy-operator", metav1.GetOptions{})
	if err != nil {
		// Installed but can't get version
		return true, "unknown"
	}

	// Extract version from image tag
	if len(deploy.Spec.Template.Spec.Containers) > 0 {
		image := deploy.Spec.Template.Spec.Containers[0].Image
		// Image format aquasec/trivy-operator:0.29.0
		// Extract version after last ":"
		version := "unknown"
		if idx := len(image) - 1; idx >= 0 {
			for i := idx; i >= 0; i-- {
				if image[i] == ':' {
					version = image[i+1:]
					break
				}
			}
		}
		return true, version
	}
	// Found reports but no deployment info
	return true, "unknown"
}
