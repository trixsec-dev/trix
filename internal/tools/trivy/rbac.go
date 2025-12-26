package trivy

import (
	"context"
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// ListRbacAssessmentReports queries Trivy RbacAssessmentReport CRDs
func (c *Client) ListRbacAssessmentReports(ctx context.Context, namespace string) ([]map[string]interface{}, error) {
	gvr := schema.GroupVersionResource{
		Group:    "aquasecurity.github.io",
		Version:  "v1alpha1",
		Resource: "rbacassessmentreports",
	}

	list, err := c.dynamicClient.Resource(gvr).Namespace(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list rbac assessment reports: %w", err)
	}

	var reports []map[string]interface{}
	for _, item := range list.Items {
		reports = append(reports, item.Object)
	}

	return reports, nil
}

// ParseRbacChecks extracts RBAC check details from a report
// Reuses the same structure as compliance checks
func (c *Client) ParseRbacChecks(report map[string]interface{}) ([]ComplianceCheck, error) {
	var checks []ComplianceCheck

	reportData, ok := report["report"].(map[string]interface{})
	if !ok {
		return checks, fmt.Errorf("no report data found")
	}

	checksArray, ok := reportData["checks"].([]interface{})
	if !ok {
		return checks, nil
	}

	for _, item := range checksArray {
		checkMap, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		check := ComplianceCheck{
			CheckID:     getString(checkMap, "checkID"),
			Title:       getString(checkMap, "title"),
			Description: getString(checkMap, "description"),
			Severity:    getString(checkMap, "severity"),
			Category:    getString(checkMap, "category"),
			Remediation: getString(checkMap, "remediation"),
		}

		if success, ok := checkMap["success"].(bool); ok {
			check.Success = success
		}

		if msgArray, ok := checkMap["messages"].([]interface{}); ok {
			for _, msg := range msgArray {
				if msgStr, ok := msg.(string); ok {
					check.Messages = append(check.Messages, msgStr)
				}
			}
		}

		checks = append(checks, check)
	}

	return checks, nil
}
