package kubectl

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// NetworkCoverage holds NetworkPolicy gap analysis results
type NetworkCoverage struct {
	Namespace     string
	TotalPods     int
	CoveredPods   int
	UncoveredPods []string // Pod names without any NetworkPolicy
	Policies      []string // Networkpolicy names in namespace
}

type NetworkPolicyInfo struct {
	Name        string
	Namespace   string
	PodSelector map[string]string
}

// ListNetworkPolicies gets all the native kubernetes NetworkPolicies through the API
func (c *Client) ListNetworkPolicies(ctx context.Context, namespace string) ([]NetworkPolicyInfo, error) {
	netpols, err := c.clientset.NetworkingV1().NetworkPolicies(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list network policies: %w", err)
	}

	var policies []NetworkPolicyInfo
	for _, netpol := range netpols.Items {
		policies = append(policies, NetworkPolicyInfo{
			Name:        netpol.Name,
			Namespace:   netpol.Namespace,
			PodSelector: netpol.Spec.PodSelector.MatchLabels,
		})
	}
	return policies, nil
}

// labelsMatch checks if all selector labels exist in the pod's labels
// An empty selector matches all pods (Kubernetes behavior)
func labelsMatch(selector, podLabels map[string]string) bool {
	// Empty selector matches everything
	if len(selector) == 0 {
		return true
	}

	// Every selector key-value must exist in pod labels
	for key, value := range selector {
		if podLabels[key] != value {
			return false
		}
	}
	return true
}

// isPodCovered checks if a pod is selected by at least one NetworkPolicy
func isPodCovered(podLabels map[string]string, policies []NetworkPolicyInfo) bool {
	for _, policy := range policies {
		if labelsMatch(policy.PodSelector, podLabels) {
			return true
		}
	}
	return false
}

// AnalyzeCoverage checks if pods are matching the labels in the NetworkPolicy
func (c *Client) AnalyzeCoverage(ctx context.Context, namespace string) ([]NetworkCoverage, error) {
	// Get all pods in a namespace
	pods, err := c.clientset.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list pods: %w", err)
	}

	// Get all network policies in namespace
	policies, err := c.ListNetworkPolicies(ctx, namespace)
	if err != nil {
		return nil, err
	}

	var uncoveredPods []string
	coveredCount := 0
	totalRunning := 0

	for _, pod := range pods.Items {
		// Skip non-running pods (completed jobs, pending, etc.)
		if pod.Status.Phase != corev1.PodRunning {
			continue
		}
		totalRunning++

		if isPodCovered(pod.Labels, policies) {
			coveredCount++
		} else {
			uncoveredPods = append(uncoveredPods, pod.Name)
		}
	}
	// Build policy names list
	var policyNames []string
	for _, p := range policies {
		policyNames = append(policyNames, p.Name)
	}

	// Return as slice (supports multi-namespace in future)
	return []NetworkCoverage{{
		Namespace:     namespace,
		TotalPods:     totalRunning,
		CoveredPods:   coveredCount,
		UncoveredPods: uncoveredPods,
		Policies:      policyNames,
	}}, nil
}
