package trivy

import (
	"context"
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// ListSbomReports queries Trivy SbomReport CRDs
func (c *Client) ListSbomReports(ctx context.Context, namespace string) ([]map[string]interface{}, error) {
	gvr := schema.GroupVersionResource{
		Group:    "aquasecurity.github.io",
		Version:  "v1alpha1",
		Resource: "sbomreports",
	}

	list, err := c.dynamicClient.Resource(gvr).Namespace(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list sbom reports: %w", err)
	}

	var reports []map[string]interface{}
	for _, item := range list.Items {
		reports = append(reports, item.Object)
	}

	return reports, nil
}

// ParseSBOMReport extracts SBOM data from a report
func (c *Client) ParseSBOMReport(report map[string]interface{}) (*SBOMReport, error) {
	sbom := &SBOMReport{}

	// Extract Metadata
	metadata, ok := report["metadata"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("no metadata found")
	}

	sbom.Name, _ = metadata["name"].(string)
	sbom.Namespace, _ = metadata["namespace"].(string)

	// Extract report data
	reportData, ok := report["report"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("no report data found")
	}

	// Extract image info from artifacts
	if artifact, ok := reportData["artifact"].(map[string]interface{}); ok {
		repo, _ := artifact["repository"].(string)
		tag, _ := artifact["tag"].(string)
		sbom.Image = repo + ":" + tag
	}

	// Extract components
	components, ok := reportData["components"].(map[string]interface{})
	if !ok {
		return sbom, nil
	}

	componentsList, ok := components["components"].([]interface{})
	if !ok {
		return sbom, nil
	}

	for _, item := range componentsList {
		compMap, ok := item.(map[string]interface{})
		if !ok {
			continue
		}

		comp := SBOMComponent{
			Name:    getString(compMap, "name"),
			Version: getString(compMap, "version"),
			Type:    getString(compMap, "type"),
			PURL:    getString(compMap, "purl"),
		}

		// Skip empty components
		if comp.Name != "" {
			sbom.Components = append(sbom.Components, comp)
		}
	}

	return sbom, nil
}
