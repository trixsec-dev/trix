package trivy

import (
	"context"
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// ListExposedSecretsReports queries Trivy ExposedSecretReports CRDs
func (c *Client) ListExposedSecretReports(ctx context.Context, namespace string) ([]map[string]interface{}, error) {
	gvr := schema.GroupVersionResource{
		Group:    "aquasecurity.github.io",
		Version:  "v1alpha1",
		Resource: "exposedsecretreports",
	}

	list, err := c.dynamicClient.Resource(gvr).Namespace(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list exposed secrets reports: %w", err)
	}

	var reports []map[string]interface{}
	for _, item := range list.Items {
		reports = append(reports, item.Object)
	}

	return reports, nil
}

// ParseExposedSecrets extracts secret details from a report
func (c *Client) ParseExposedSecrets(report map[string]interface{}) ([]ExposedSecret, error) {
	var secrets []ExposedSecret

	reportData, ok := report["report"].(map[string]interface{})
	if !ok {
		return secrets, fmt.Errorf("no report data found")
	}

	secretsArray, ok := reportData["secrets"].([]interface{})
	if !ok {
		return secrets, nil // No secrets = empty slice
	}

	for _, item := range secretsArray {
		secretMap, ok := item.(map[string]interface{})
		if !ok {
			continue
		}

		secret := ExposedSecret{
			Target:   getString(secretMap, "target"),
			RuleID:   getString(secretMap, "ruleID"),
			Title:    getString(secretMap, "title"),
			Category: getString(secretMap, "category"),
			Severity: getString(secretMap, "severity"),
			Match:    getString(secretMap, "match"),
		}

		secrets = append(secrets, secret)
	}

	return secrets, nil
}
