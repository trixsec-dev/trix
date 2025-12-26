package trivy

import (
	"context"
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// ListClusterComplianceReports queries ClusterComplianceReport CRDs (CIS/NSA benchmarks)
func (c *Client) ListBenchmarkReports(ctx context.Context) ([]map[string]interface{}, error) {
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

// ParseBenchmarkControls extracts failed controls from a benchmark report
func (c *Client) ParseBenchmarkControls(report map[string]interface{}) (string, []BenchmarkControl, error) {
	var controls []BenchmarkControl

	// Get benchmark name from metadata
	metadata, ok := report["metadata"].(map[string]interface{})
	if !ok {
		return "", nil, fmt.Errorf("no metadata found")
	}
	benchmarkName, _ := metadata["name"].(string)

	// Get status
	status, ok := report["status"].(map[string]interface{})
	if !ok {
		return benchmarkName, controls, nil
	}

	// Get summary report
	summaryReport, ok := status["summaryReport"].(map[string]interface{})
	if !ok {
		return benchmarkName, controls, nil
	}

	// Get control checks
	controlChecks, ok := summaryReport["controlCheck"].([]interface{})
	if !ok {
		return benchmarkName, controls, nil
	}

	for _, item := range controlChecks {
		checkMap, ok := item.(map[string]interface{})
		if !ok {
			continue
		}

		totalFail := 0
		// Try both int64 (from K8s API) and float64 (from JSON)
		if tf, ok := checkMap["totalFail"].(int64); ok {
			totalFail = int(tf)
		} else if tf, ok := checkMap["totalFail"].(float64); ok {
			totalFail = int(tf)
		}

		control := BenchmarkControl{
			ID:        getString(checkMap, "id"),
			Name:      getString(checkMap, "name"),
			Severity:  getString(checkMap, "severity"),
			TotalFail: totalFail,
		}

		controls = append(controls, control)
	}

	return benchmarkName, controls, nil
}
