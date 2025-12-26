package trivy

import "fmt"

type Severity string

const (
	SeverityCritical Severity = "CRITICAL"
	SeverityHigh     Severity = "HIGH"
	SeverityMedium   Severity = "MEDIUM"
	SeverityLow      Severity = "LOW"
	SeverityUnknown  Severity = "UNKNOWN"
)

type FindingType string

const (
	FindingTypeVulnerability FindingType = "vulnerability"
	FindingTypeCompliance    FindingType = "compliance"
	FindingTypeRBAC          FindingType = "rbac"
	FindingTypeSecret        FindingType = "secret"
	FindingTypeInfra         FindingType = "infra"
	FindingTypeBenchmark     FindingType = "benchmark"
	FindingTypeEvent         FindingType = "event"
)

type Finding struct {
	// Identity
	ID   string      `json:"id"`
	Type FindingType `json:"type"`

	// Severity
	Severity Severity `json:"severity"`
	Score    float64  `json:"score,omitempty"` //CVSS score if available

	// Location - where in the cluster
	Namespace    string `json:"namespace,omitempty"`
	ResourceKind string `json:"resourceKind,omitempty"`
	ResourceName string `json:"resourceName,omitempty"`

	// Description
	Title       string `json:"title"`
	Description string `json:"description,omitempty"`
	Remediation string `json:"remediation,omitempty"`

	// Metadata
	Source    string `json:"source"`
	CreatedAt string `json:"createdAt,omitempty"`

	// Raw data from the source (for detailed inspection)
	RawData interface{} `json:"rawData,omitempty"`
}

// VulnerabilityToFinding converts a Trivy vulnerability to a Finding
func VulnerabilityToFinding(v Vulnerability, namespace, resourceName string) Finding {
	return Finding{
		ID:           v.VulnerabilityID,
		Type:         FindingTypeVulnerability,
		Severity:     Severity(v.Severity), // Convert string to Severity type
		Score:        v.Score,
		Namespace:    namespace,
		ResourceKind: "Pod",
		ResourceName: resourceName,
		Title:        v.Title,
		Description:  fmt.Sprintf("%s %s (installed: %s, fixed: %s)", v.PkgName, v.VulnerabilityID, v.InstalledVersion, v.FixedVersion),
		Remediation:  fmt.Sprintf("Update %s to version %s", v.PkgName, v.FixedVersion),
		Source:       "trivy",
		RawData:      v,
	}
}

// ComplianceCheckToFinding converts a Trivy compliance check to a Finding
func ComplianceCheckToFinding(c ComplianceCheck, namespace, resourceName string) Finding {
	return Finding{
		ID:           c.CheckID,
		Type:         FindingTypeCompliance,
		Severity:     Severity(c.Severity),
		Namespace:    namespace,
		ResourceKind: "Pod",
		ResourceName: resourceName,
		Title:        c.Title,
		Description:  c.Description,
		Remediation:  c.Remediation,
		Source:       "trivy",
		RawData:      c,
	}
}

// InfraCheckToFinding converts an infra assessment check to a Finding
func InfraCheckToFinding(c ComplianceCheck, namespace, resourceName string) Finding {
	return Finding{
		ID:           c.CheckID,
		Type:         FindingTypeInfra,
		Severity:     Severity(c.Severity),
		Namespace:    namespace,
		ResourceKind: "Pod",
		ResourceName: resourceName,
		Title:        c.Title,
		Description:  c.Description,
		Remediation:  c.Remediation,
		Source:       "trivy",
		RawData:      c,
	}
}

// RbacCheckToFinding converts an RBAC assessment check to a Finding
func RbacCheckToFinding(c ComplianceCheck, namespace, resourceName string) Finding {
	return Finding{
		ID:           c.CheckID,
		Type:         FindingTypeRBAC,
		Severity:     Severity(c.Severity),
		Namespace:    namespace,
		ResourceKind: "Role",
		ResourceName: resourceName,
		Title:        c.Title,
		Description:  c.Description,
		Remediation:  c.Remediation,
		Source:       "trivy",
		RawData:      c,
	}
}

// ExposedSecretToFinding converts an exposed secret to a Finding
func ExposedSecretToFinding(s ExposedSecret, namespace, resourceName string) Finding {
	return Finding{
		ID:           s.RuleID,
		Type:         FindingTypeSecret,
		Severity:     Severity(s.Severity),
		Namespace:    namespace,
		ResourceKind: "Pod",
		ResourceName: resourceName,
		Title:        s.Title,
		Description:  fmt.Sprintf("Secret found in %s", s.Target),
		Source:       "trivy",
		RawData:      s,
	}
}

// BenchmarkControlToFinding converts a CIS/NSA benchmark control to a Finding
func BenchmarkControlToFinding(c BenchmarkControl, benchmarkName string) Finding {
	return Finding{
		ID:           c.ID,
		Type:         FindingTypeBenchmark,
		Severity:     Severity(c.Severity),
		ResourceKind: "Cluster",
		ResourceName: benchmarkName,
		Title:        c.Name,
		Description:  fmt.Sprintf("CIS control %s failed %d times", c.ID, c.TotalFail),
		Source:       "trivy",
		RawData:      c,
	}
}
