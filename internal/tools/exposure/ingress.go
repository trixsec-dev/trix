// internal/exposure/ingress.go
package exposure

import (
	"context"
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// IngressChecker finds Ingresses that route to Services selecting the workload
type IngressChecker struct {
	clientset kubernetes.Interface
}

// NewIngressChecker creates a new IngressChecker
func NewIngressChecker(clientset kubernetes.Interface) *IngressChecker {
	return &IngressChecker{clientset: clientset}
}

// Name returns the checker name
func (i *IngressChecker) Name() string {
	return "ingress"
}

// Check finds Ingresses that route to the workload via Services
func (i *IngressChecker) Check(ctx context.Context, workload Workload) ([]ExposurePoint, error) {
	if len(workload.Labels) == 0 {
		return nil, nil
	}

	// List all Ingresses in the namespace
	ingresses, err := i.clientset.NetworkingV1().Ingresses(workload.Namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list ingresses: %w", err)
	}

	// Cache services we've already checked
	serviceCache := make(map[string]bool) // serviceName -> selects workload?

	var points []ExposurePoint

	for _, ing := range ingresses.Items {
		// Collect all hosts from this ingress
		var hosts []string
		var matchingServices []string

		// Check default backend
		if ing.Spec.DefaultBackend != nil && ing.Spec.DefaultBackend.Service != nil {
			svcName := ing.Spec.DefaultBackend.Service.Name
			if i.serviceSelectsWorkload(ctx, workload, svcName, serviceCache) {
				matchingServices = append(matchingServices, svcName)
			}
		}

		// Check each rule
		for _, rule := range ing.Spec.Rules {
			if rule.Host != "" {
				hosts = append(hosts, rule.Host)
			}

			if rule.HTTP == nil {
				continue
			}

			for _, path := range rule.HTTP.Paths {
				if path.Backend.Service == nil {
					continue
				}

				svcName := path.Backend.Service.Name
				if i.serviceSelectsWorkload(ctx, workload, svcName, serviceCache) {
					matchingServices = append(matchingServices, svcName)
				}
			}
		}

		// If any backend service selects our workload, this Ingress exposes it
		if len(matchingServices) > 0 {
			points = append(points, ExposurePoint{
				Type:        ExposureTypeIngress,
				Name:        ing.Name,
				Namespace:   ing.Namespace,
				Hosts:       uniqueStrings(hosts),
				ServiceName: matchingServices[0], // Primary service
				Details:     fmt.Sprintf("Routes to service(s): %v", uniqueStrings(matchingServices)),
			})
		}
	}

	return points, nil
}

// serviceSelectsWorkload checks if a Service selects the workload (with caching)
func (i *IngressChecker) serviceSelectsWorkload(ctx context.Context, workload Workload, serviceName string, cache map[string]bool) bool {
	// Check cache first
	if result, ok := cache[serviceName]; ok {
		return result
	}

	// Fetch the service
	svc, err := i.clientset.CoreV1().Services(workload.Namespace).Get(ctx, serviceName, metav1.GetOptions{})
	if err != nil {
		cache[serviceName] = false
		return false
	}

	if svc.Spec.Selector == nil {
		cache[serviceName] = false
		return false
	}

	result := matchesSelector(workload.Labels, svc.Spec.Selector)
	cache[serviceName] = result
	return result
}

// uniqueStrings removes duplicates from a string slice
func uniqueStrings(input []string) []string {
	seen := make(map[string]bool)
	var result []string
	for _, s := range input {
		if !seen[s] {
			seen[s] = true
			result = append(result, s)
		}
	}
	return result
}
