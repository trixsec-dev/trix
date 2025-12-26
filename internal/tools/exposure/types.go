package exposure

import "context"

// ExposureType inidicates how a workload is exposed
type ExposureType string

const (
	ExposureTypeService      ExposureType = "service"
	ExposureTypeIngress      ExposureType = "ingress"
	ExposureTypeHTTPRoute    ExposureType = "httproute"
	ExposureTypeGRPCRoute    ExposureType = "grpcroute"
	ExposureTypeUDPRoute     ExposureType = "udproute"
	ExposureTypeGateway      ExposureType = "gateway"
	ExposureTypeLoadbalancer ExposureType = "loadbalancer"
	ExposureTypeNodePort     ExposureType = "nodePort"
	// Future: ExposureTypeIstioGateway, ExposureTypeCiliumPolicy, ExposureTypeTCPRoute
)

// ExposureLevel indicates the presumed exposure level
type ExposureLevel string

const (
	// ExposureLevelExternal - exposed via Ingress/Gateway/Loadbalancer
	ExposureLevelExternal ExposureLevel = "external"

	// ExposureLevelNodePort - exposed via NodePort on node IPs
	ExposureLevelNodePort ExposureLevel = "nodePort"

	// ExposureLevelClusterInternal - ClusterIP only, internal to cluster
	ExposureLevelClusterInternal ExposureLevel = "clusterInternal"

	// ExposureLevelNone - no service exposure detected
	ExposureLevelNone ExposureLevel = "none"
)

// Workload identifies a kubernetes workload to analyze
type Workload struct {
	Kind      string            `json:"kind"` // Deployment, DaemonSet, StatefulSet, Pod
	Name      string            `json:"name"`
	Namespace string            `json:"namespace"`
	Labels    map[string]string `json:"labels"`
}

// ExposurePoint respresents a single exposure vector
type ExposurePoint struct {
	Type        ExposureType `json:"type"`
	Name        string       `json:"name"`
	Namespace   string       `json:"namespace,omitempty"`
	Details     string       `json:"details,omitempty"`
	Ports       []int32      `json:"ports,omitempty"`
	Hosts       []string     `json:"hosts,omitempty"`
	ServiceName string       `json:"serviceName,omitempty"`
}

// Result contains the full exposure analysis for a workload
type Result struct {
	Workload       Workload        `json:"workload"`
	ExposurePoints []ExposurePoint `json:"exposurePoints"`
	Level          ExposureLevel   `json:"level"`
	Summary        string          `json:"summary"`
}

// Checker interface - implements this to add new exposure checks
type Checker interface {
	// Name returns the checker namee (for logging/debugging)
	Name() string

	// Check analyzes exposure for the given workload
	Check(ctx context.Context, workload Workload) ([]ExposurePoint, error)
}
