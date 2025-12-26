// internal/exposure/gateway.go
package exposure

import (
	"context"
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
)

// GatewayChecker finds Gateway API routes (HTTPRoute, GRPCRoute, UDPRoute)
// that route to Services selecting the workload
type GatewayChecker struct {
	clientset     kubernetes.Interface
	dynamicClient dynamic.Interface
}

// NewGatewayChecker creates a new GatewayChecker
func NewGatewayChecker(clientset kubernetes.Interface, dynamicClient dynamic.Interface) *GatewayChecker {
	return &GatewayChecker{
		clientset:     clientset,
		dynamicClient: dynamicClient,
	}
}

// Name returns the checker name
func (g *GatewayChecker) Name() string {
	return "gateway"
}

// Route types we check
var gatewayRouteTypes = []struct {
	gvr          schema.GroupVersionResource
	exposureType ExposureType
	name         string
}{
	{
		gvr: schema.GroupVersionResource{
			Group:    "gateway.networking.k8s.io",
			Version:  "v1",
			Resource: "httproutes",
		},
		exposureType: ExposureTypeHTTPRoute,
		name:         "HTTPRoute",
	},
	{
		gvr: schema.GroupVersionResource{
			Group:    "gateway.networking.k8s.io",
			Version:  "v1",
			Resource: "grpcroutes",
		},
		exposureType: ExposureTypeGRPCRoute,
		name:         "GRPCRoute",
	},
	{
		gvr: schema.GroupVersionResource{
			Group:    "gateway.networking.k8s.io",
			Version:  "v1alpha2",
			Resource: "udproutes",
		},
		exposureType: ExposureTypeUDPRoute,
		name:         "UDPRoute",
	},
}

// Gateway GVR for checking external IPs
var gatewayGVR = schema.GroupVersionResource{
	Group:    "gateway.networking.k8s.io",
	Version:  "v1",
	Resource: "gateways",
}

// Check finds Gateway API routes that route to the workload
func (g *GatewayChecker) Check(ctx context.Context, workload Workload) ([]ExposurePoint, error) {
	if len(workload.Labels) == 0 {
		return nil, nil
	}

	// Cache services we've already checked
	serviceCache := make(map[string]bool)

	var allPoints []ExposurePoint

	// Check each route type
	for _, routeType := range gatewayRouteTypes {
		points, err := g.checkRouteType(ctx, workload, routeType.gvr, routeType.exposureType, routeType.name, serviceCache)
		if err != nil {
			// Route type might not be installed - skip silently
			continue
		}
		allPoints = append(allPoints, points...)
	}

	return allPoints, nil
}

// checkRouteType checks a specific Gateway API route type
func (g *GatewayChecker) checkRouteType(
	ctx context.Context,
	workload Workload,
	gvr schema.GroupVersionResource,
	expType ExposureType,
	routeTypeName string,
	serviceCache map[string]bool,
) ([]ExposurePoint, error) {

	// List routes in namespace
	list, err := g.dynamicClient.Resource(gvr).Namespace(workload.Namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err // CRD might not exist
	}

	var points []ExposurePoint

	for _, item := range list.Items {
		routeName := item.GetName()
		routeNamespace := item.GetNamespace()

		// Extract hostnames (for HTTPRoute/GRPCRoute)
		var hosts []string
		if hostnames, ok := item.Object["spec"].(map[string]interface{})["hostnames"].([]interface{}); ok {
			for _, h := range hostnames {
				if hs, ok := h.(string); ok {
					hosts = append(hosts, hs)
				}
			}
		}

		// Extract backend refs and check if any service selects our workload
		var matchingServices []string
		backendRefs := g.extractBackendRefs(item.Object)

		for _, ref := range backendRefs {
			if ref.kind == "Service" && g.serviceSelectsWorkload(ctx, workload, ref.name, serviceCache) {
				matchingServices = append(matchingServices, ref.name)
			}
		}

		if len(matchingServices) > 0 {
			// Check if route is attached to a Gateway with external IPs
			gatewayInfo := g.getGatewayInfo(ctx, item.Object)

			details := fmt.Sprintf("%s routes to service(s): %v", routeTypeName, uniqueStrings(matchingServices))
			if gatewayInfo != "" {
				details += fmt.Sprintf(" | %s", gatewayInfo)
			}

			points = append(points, ExposurePoint{
				Type:        expType,
				Name:        routeName,
				Namespace:   routeNamespace,
				Hosts:       hosts,
				ServiceName: matchingServices[0],
				Details:     details,
			})
		}
	}

	return points, nil
}

// getGatewayInfo extracts Gateway name and external IPs from parentRefs
func (g *GatewayChecker) getGatewayInfo(ctx context.Context, routeObj map[string]interface{}) string {
	spec, ok := routeObj["spec"].(map[string]interface{})
	if !ok {
		return ""
	}

	parentRefs, ok := spec["parentRefs"].([]interface{})
	if !ok {
		return ""
	}

	var infos []string
	for _, pr := range parentRefs {
		prMap, ok := pr.(map[string]interface{})
		if !ok {
			continue
		}

		// Get Gateway name and namespace
		gwName, _ := prMap["name"].(string)
		gwNamespace, _ := prMap["namespace"].(string)
		if gwNamespace == "" {
			// Default to route's namespace
			if meta, ok := routeObj["metadata"].(map[string]interface{}); ok {
				gwNamespace, _ = meta["namespace"].(string)
			}
		}

		if gwName == "" {
			continue
		}

		// Fetch the Gateway to check for external addresses
		gw, err := g.dynamicClient.Resource(gatewayGVR).Namespace(gwNamespace).Get(ctx, gwName, metav1.GetOptions{})
		if err != nil {
			infos = append(infos, fmt.Sprintf("Gateway: %s/%s", gwNamespace, gwName))
			continue
		}

		// Extract addresses from status
		addresses := g.extractGatewayAddresses(gw.Object)
		if len(addresses) > 0 {
			infos = append(infos, fmt.Sprintf("Gateway: %s/%s (external: %v)", gwNamespace, gwName, addresses))
		} else {
			infos = append(infos, fmt.Sprintf("Gateway: %s/%s (no external IP)", gwNamespace, gwName))
		}
	}

	if len(infos) > 0 {
		return infos[0] // Return first gateway info
	}
	return ""
}

// extractGatewayAddresses gets external IPs/hostnames from Gateway status
func (g *GatewayChecker) extractGatewayAddresses(gwObj map[string]interface{}) []string {
	status, ok := gwObj["status"].(map[string]interface{})
	if !ok {
		return nil
	}

	addresses, ok := status["addresses"].([]interface{})
	if !ok {
		return nil
	}

	var result []string
	for _, addr := range addresses {
		addrMap, ok := addr.(map[string]interface{})
		if !ok {
			continue
		}

		value, _ := addrMap["value"].(string)
		if value != "" {
			result = append(result, value)
		}
	}

	return result
}

// backendRef holds parsed backend reference info
type backendRef struct {
	kind string
	name string
}

// extractBackendRefs extracts all backend references from a route
func (g *GatewayChecker) extractBackendRefs(obj map[string]interface{}) []backendRef {
	var refs []backendRef

	spec, ok := obj["spec"].(map[string]interface{})
	if !ok {
		return refs
	}

	// HTTPRoute and GRPCRoute have rules[].backendRefs[]
	// UDPRoute has rules[].backendRefs[] as well
	rules, ok := spec["rules"].([]interface{})
	if !ok {
		return refs
	}

	for _, rule := range rules {
		ruleMap, ok := rule.(map[string]interface{})
		if !ok {
			continue
		}

		backendRefs, ok := ruleMap["backendRefs"].([]interface{})
		if !ok {
			continue
		}

		for _, br := range backendRefs {
			brMap, ok := br.(map[string]interface{})
			if !ok {
				continue
			}

			kind := "Service" // Default kind
			if k, ok := brMap["kind"].(string); ok {
				kind = k
			}

			name, _ := brMap["name"].(string)
			if name != "" {
				refs = append(refs, backendRef{kind: kind, name: name})
			}
		}
	}

	return refs
}

// serviceSelectsWorkload checks if a Service selects the workload (with caching)
func (g *GatewayChecker) serviceSelectsWorkload(ctx context.Context, workload Workload, serviceName string, cache map[string]bool) bool {
	// Check cache first
	if result, ok := cache[serviceName]; ok {
		return result
	}

	// Fetch the service
	svc, err := g.clientset.CoreV1().Services(workload.Namespace).Get(ctx, serviceName, metav1.GetOptions{})
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
