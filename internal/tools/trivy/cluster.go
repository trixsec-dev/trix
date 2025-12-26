package trivy

import (
	"context"
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// ListClusterVulnerabilityReports queries cluster-scoped vulnerability reports
func (c *Client) ListClusterVulnerabilityReports(ctx context.Context) ([]map[string]interface{}, error) {
	gvr := schema.GroupVersionResource{
		Group:    "aquasecurity.github.io",
		Version:  "v1alpha1",
		Resource: "clustervulnerabilityreports",
	}

	list, err := c.dynamicClient.Resource(gvr).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list cluster vulnerability reports: %w", err)
	}

	var reports []map[string]interface{}
	for _, item := range list.Items {
		reports = append(reports, item.Object)
	}
	return reports, nil
}

// ListClusterConfigAuditReports queries cluster-scoped config audit reports
func (c *Client) ListClusterConfigAuditReports(ctx context.Context) ([]map[string]interface{}, error) {
	gvr := schema.GroupVersionResource{
		Group:    "aquasecurity.github.io",
		Version:  "v1alpha1",
		Resource: "clusterconfigauditreports",
	}

	list, err := c.dynamicClient.Resource(gvr).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list cluster config audit reports: %w", err)
	}

	var reports []map[string]interface{}
	for _, item := range list.Items {
		reports = append(reports, item.Object)
	}
	return reports, nil
}

// ListClusterRbacAssessmentReports queries cluster-scoped RBAC assessment reports
func (c *Client) ListClusterRbacAssessmentReports(ctx context.Context) ([]map[string]interface{}, error) {
	gvr := schema.GroupVersionResource{
		Group:    "aquasecurity.github.io",
		Version:  "v1alpha1",
		Resource: "clusterrbacassessmentreports",
	}

	list, err := c.dynamicClient.Resource(gvr).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list cluster rbac assessment reports: %w", err)
	}

	var reports []map[string]interface{}
	for _, item := range list.Items {
		reports = append(reports, item.Object)
	}
	return reports, nil
}

// ListClusterInfraAssessmentReports queries cluster-scoped infra assessment reports
func (c *Client) ListClusterInfraAssessmentReports(ctx context.Context) ([]map[string]interface{}, error) {
	gvr := schema.GroupVersionResource{
		Group:    "aquasecurity.github.io",
		Version:  "v1alpha1",
		Resource: "clusterinfraassessmentreports",
	}

	list, err := c.dynamicClient.Resource(gvr).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list cluster infra assessment reports: %w", err)
	}

	var reports []map[string]interface{}
	for _, item := range list.Items {
		reports = append(reports, item.Object)
	}
	return reports, nil
}

// ListClusterComplianceReports queries cluster-scoped compliance reports
func (c *Client) ListClusterComplianceReports(ctx context.Context) ([]map[string]interface{}, error) {
	gvr := schema.GroupVersionResource{
		Group:    "aquasecurity.github.io",
		Version:  "v1alpha1",
		Resource: "clustercompliancereports",
	}

	list, err := c.dynamicClient.Resource(gvr).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list cluster compliance reports: %w", err)
	}

	var reports []map[string]interface{}
	for _, item := range list.Items {
		reports = append(reports, item.Object)
	}
	return reports, nil
}

// ListClusterSbomReports queries cluster-scoped SBOM reports
func (c *Client) ListClusterSbomReports(ctx context.Context) ([]map[string]interface{}, error) {
	gvr := schema.GroupVersionResource{
		Group:    "aquasecurity.github.io",
		Version:  "v1alpha1",
		Resource: "clustersbomreports",
	}

	list, err := c.dynamicClient.Resource(gvr).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list cluster sbom reports: %w", err)
	}

	var reports []map[string]interface{}
	for _, item := range list.Items {
		reports = append(reports, item.Object)
	}
	return reports, nil
}
