// internal/exposure/service.go
package exposure

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// ServiceChecker finds Services that select a workload
type ServiceChecker struct {
	clientset kubernetes.Interface
}

// NewServiceChecker creates a new ServiceChecker
func NewServiceChecker(clientset kubernetes.Interface) *ServiceChecker {
	return &ServiceChecker{clientset: clientset}
}

// Name returns the checker name
func (s *ServiceChecker) Name() string {
	return "service"
}

// Check finds Services that select the given workload
func (s *ServiceChecker) Check(ctx context.Context, workload Workload) ([]ExposurePoint, error) {
	if len(workload.Labels) == 0 {
		return nil, nil // No labels = no selector can match
	}

	services, err := s.clientset.CoreV1().Services(workload.Namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list services: %w", err)
	}

	var points []ExposurePoint

	for _, svc := range services.Items {
		if svc.Spec.Selector == nil {
			continue // No selector
		}

		if matchesSelector(workload.Labels, svc.Spec.Selector) {
			point := serviceToExposurePoint(&svc)
			points = append(points, point)
		}
	}

	return points, nil
}

// matchesSelector checks if workload labels match a service selector
// All selector key-values must be present in workload labels
func matchesSelector(workloadLabels, selector map[string]string) bool {
	for key, value := range selector {
		if workloadLabels[key] != value {
			return false
		}
	}
	return true
}

// serviceToExposurePoint converts a Service to an ExposurePoint
func serviceToExposurePoint(svc *corev1.Service) ExposurePoint {
	// Determine exposure type based on service type
	expType := ExposureTypeService
	switch svc.Spec.Type {
	case corev1.ServiceTypeLoadBalancer:
		expType = ExposureTypeLoadbalancer
	case corev1.ServiceTypeNodePort:
		expType = ExposureTypeNodePort
	}

	// Extract ports
	var ports []int32
	for _, p := range svc.Spec.Ports {
		ports = append(ports, p.Port)
	}

	// Build details string
	details := fmt.Sprintf("Type: %s", svc.Spec.Type)
	if svc.Spec.Type == corev1.ServiceTypeLoadBalancer && len(svc.Status.LoadBalancer.Ingress) > 0 {
		ing := svc.Status.LoadBalancer.Ingress[0]
		if ing.Hostname != "" {
			details += fmt.Sprintf(", LB: %s", ing.Hostname)
		} else if ing.IP != "" {
			details += fmt.Sprintf(", LB: %s", ing.IP)
		}
	}

	return ExposurePoint{
		Type:      expType,
		Name:      svc.Name,
		Namespace: svc.Namespace,
		Details:   details,
		Ports:     ports,
	}
}
