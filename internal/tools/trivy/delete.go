package trivy

import (
	"context"
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// DeleteVulnerabilityReports deletes VulnerabilityReports to trigger rescan
// Returns the number of reports deleted
func (c *Client) DeleteVulnerabilityReports(ctx context.Context, namespace string) (int, error) {
	gvr := schema.GroupVersionResource{
		Group:    "aquasecurity.github.io",
		Version:  "v1alpha1",
		Resource: "vulnerabilityreports",
	}
	return c.deleteReports(ctx, gvr, namespace)
}

// DeleteConfigAuditReports deletes ConfigAuditReports to trigger rescan
func (c *Client) DeleteConfigAuditReports(ctx context.Context, namespace string) (int, error) {
	gvr := schema.GroupVersionResource{
		Group:    "aquasecurity.github.io",
		Version:  "v1alpha1",
		Resource: "configauditreports",
	}
	return c.deleteReports(ctx, gvr, namespace)
}

// DeleteExposedSecretReports deletes ExposedSecretReports to trigger rescan
func (c *Client) DeleteExposedSecretReports(ctx context.Context, namespace string) (int, error) {
	gvr := schema.GroupVersionResource{
		Group:    "aquasecurity.github.io",
		Version:  "v1alpha1",
		Resource: "exposedsecretreports",
	}
	return c.deleteReports(ctx, gvr, namespace)
}

// DeleteRbacAssessmentReports deletes RbacAssessmentReports to trigger rescan
func (c *Client) DeleteRbacAssessmentReports(ctx context.Context, namespace string) (int, error) {
	gvr := schema.GroupVersionResource{
		Group:    "aquasecurity.github.io",
		Version:  "v1alpha1",
		Resource: "rbacassessmentreports",
	}
	return c.deleteReports(ctx, gvr, namespace)
}

// DeleteInfraAssessmentReports deletes InfraAssessmentReports to trigger rescan
func (c *Client) DeleteInfraAssessmentReports(ctx context.Context, namespace string) (int, error) {
	gvr := schema.GroupVersionResource{
		Group:    "aquasecurity.github.io",
		Version:  "v1alpha1",
		Resource: "infraassessmentreports",
	}
	return c.deleteReports(ctx, gvr, namespace)
}

// DeleteSbomReports deletes SbomReports to trigger rescan
func (c *Client) DeleteSbomReports(ctx context.Context, namespace string) (int, error) {
	gvr := schema.GroupVersionResource{
		Group:    "aquasecurity.github.io",
		Version:  "v1alpha1",
		Resource: "sbomreports",
	}
	return c.deleteReports(ctx, gvr, namespace)
}

// DeleteClusterVulnerabilityReports deletes cluster-scoped VulnerabilityReports
func (c *Client) DeleteClusterVulnerabilityReports(ctx context.Context) (int, error) {
	gvr := schema.GroupVersionResource{
		Group:    "aquasecurity.github.io",
		Version:  "v1alpha1",
		Resource: "clustervulnerabilityreports",
	}
	return c.deleteClusterReports(ctx, gvr)
}

// DeleteClusterConfigAuditReports deletes cluster-scoped ConfigAuditReports
func (c *Client) DeleteClusterConfigAuditReports(ctx context.Context) (int, error) {
	gvr := schema.GroupVersionResource{
		Group:    "aquasecurity.github.io",
		Version:  "v1alpha1",
		Resource: "clusterconfigauditreports",
	}
	return c.deleteClusterReports(ctx, gvr)
}

// DeleteClusterRbacAssessmentReports deletes cluster-scoped RbacAssessmentReports
func (c *Client) DeleteClusterRbacAssessmentReports(ctx context.Context) (int, error) {
	gvr := schema.GroupVersionResource{
		Group:    "aquasecurity.github.io",
		Version:  "v1alpha1",
		Resource: "clusterrbacassessmentreports",
	}
	return c.deleteClusterReports(ctx, gvr)
}

// DeleteClusterInfraAssessmentReports deletes cluster-scoped InfraAssessmentReports
func (c *Client) DeleteClusterInfraAssessmentReports(ctx context.Context) (int, error) {
	gvr := schema.GroupVersionResource{
		Group:    "aquasecurity.github.io",
		Version:  "v1alpha1",
		Resource: "clusterinfraassessmentreports",
	}
	return c.deleteClusterReports(ctx, gvr)
}

// DeleteClusterComplianceReports deletes ClusterComplianceReports (benchmarks)
func (c *Client) DeleteClusterComplianceReports(ctx context.Context) (int, error) {
	gvr := schema.GroupVersionResource{
		Group:    "aquasecurity.github.io",
		Version:  "v1alpha1",
		Resource: "clustercompliancereports",
	}
	return c.deleteClusterReports(ctx, gvr)
}

// deleteReports is a helper that deletes namespaced reports
func (c *Client) deleteReports(ctx context.Context, gvr schema.GroupVersionResource, namespace string) (int, error) {
	// List first to get count
	list, err := c.dynamicClient.Resource(gvr).Namespace(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return 0, fmt.Errorf("failed to list %s: %w", gvr.Resource, err)
	}

	count := len(list.Items)
	if count == 0 {
		return 0, nil
	}

	// Delete all
	err = c.dynamicClient.Resource(gvr).Namespace(namespace).DeleteCollection(ctx, metav1.DeleteOptions{}, metav1.ListOptions{})
	if err != nil {
		return 0, fmt.Errorf("failed to delete %s: %w", gvr.Resource, err)
	}

	return count, nil
}

// deleteClusterReports is a helper that deletes cluster-scoped reports
func (c *Client) deleteClusterReports(ctx context.Context, gvr schema.GroupVersionResource) (int, error) {
	// List first to get count
	list, err := c.dynamicClient.Resource(gvr).List(ctx, metav1.ListOptions{})
	if err != nil {
		return 0, fmt.Errorf("failed to list %s: %w", gvr.Resource, err)
	}

	count := len(list.Items)
	if count == 0 {
		return 0, nil
	}

	// Delete all
	err = c.dynamicClient.Resource(gvr).DeleteCollection(ctx, metav1.DeleteOptions{}, metav1.ListOptions{})
	if err != nil {
		return 0, fmt.Errorf("failed to delete %s: %w", gvr.Resource, err)
	}

	return count, nil
}

// CountReports returns the number of reports for each type
type ReportCounts struct {
	VulnerabilityReports          int
	ConfigAuditReports            int
	ExposedSecretReports          int
	RbacAssessmentReports         int
	InfraAssessmentReports        int
	SbomReports                   int
	ClusterVulnerabilityReports   int
	ClusterConfigAuditReports     int
	ClusterRbacAssessmentReports  int
	ClusterInfraAssessmentReports int
	ClusterComplianceReports      int
}

// CountAllReports counts all report types
func (c *Client) CountAllReports(ctx context.Context, namespace string) (*ReportCounts, error) {
	counts := &ReportCounts{}

	// Namespaced reports
	if reports, err := c.ListVulnerabilityReports(ctx, namespace); err == nil {
		counts.VulnerabilityReports = len(reports)
	}
	if reports, err := c.ListConfigAuditReports(ctx, namespace); err == nil {
		counts.ConfigAuditReports = len(reports)
	}
	if reports, err := c.ListExposedSecretReports(ctx, namespace); err == nil {
		counts.ExposedSecretReports = len(reports)
	}
	if reports, err := c.ListRbacAssessmentReports(ctx, namespace); err == nil {
		counts.RbacAssessmentReports = len(reports)
	}
	if reports, err := c.ListInfraAssessmentReports(ctx, namespace); err == nil {
		counts.InfraAssessmentReports = len(reports)
	}
	if reports, err := c.ListSbomReports(ctx, namespace); err == nil {
		counts.SbomReports = len(reports)
	}

	// Cluster-scoped reports
	if reports, err := c.ListClusterVulnerabilityReports(ctx); err == nil {
		counts.ClusterVulnerabilityReports = len(reports)
	}
	if reports, err := c.ListClusterConfigAuditReports(ctx); err == nil {
		counts.ClusterConfigAuditReports = len(reports)
	}
	if reports, err := c.ListClusterRbacAssessmentReports(ctx); err == nil {
		counts.ClusterRbacAssessmentReports = len(reports)
	}
	if reports, err := c.ListClusterInfraAssessmentReports(ctx); err == nil {
		counts.ClusterInfraAssessmentReports = len(reports)
	}
	if reports, err := c.ListBenchmarkReports(ctx); err == nil {
		counts.ClusterComplianceReports = len(reports)
	}

	return counts, nil
}

// Total returns the total count of all reports
func (c *ReportCounts) Total() int {
	return c.VulnerabilityReports + c.ConfigAuditReports + c.ExposedSecretReports +
		c.RbacAssessmentReports + c.InfraAssessmentReports + c.SbomReports +
		c.ClusterVulnerabilityReports + c.ClusterConfigAuditReports +
		c.ClusterRbacAssessmentReports + c.ClusterInfraAssessmentReports +
		c.ClusterComplianceReports
}
