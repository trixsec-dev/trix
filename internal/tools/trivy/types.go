package trivy

// Vulnerability represents a single CVE from a Trivy report
type Vulnerability struct {
	VulnerabilityID  string  `json:"vulnerabilityID"`
	PkgName          string  `json:"pkgName"`
	InstalledVersion string  `json:"installedVersion"`
	FixedVersion     string  `json:"fixedVersion"`
	Severity         string  `json:"severity"`
	Score            float64 `json:"score"`
	Title            string  `json:"title"`
}

type ComplianceCheck struct {
	CheckID     string   `json:"id"`
	Title       string   `json:"title"`
	Description string   `json:"description"`
	Severity    string   `json:"severity"`
	Category    string   `json:"category"`
	Success     bool     `json:"success"`
	Messages    []string `json:"messages,omitempty"`
	Remediation string   `json:"remediation,omitempty"`
}

type ExposedSecret struct {
	Target   string `json:"target"`
	RuleID   string `json:"ruleID"`
	Title    string `json:"title"`
	Category string `json:"category"`
	Severity string `json:"severity"`
	Match    string `json:"match"`
}

// SBOMComponent represents a software component from an SBOM report
type SBOMComponent struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Type    string `json:"type"` // library, operating system, etc
	PURL    string `json:"purl"` // Package URL
}

// SBOMReport represents an SBOM for a container image
type SBOMReport struct {
	Name       string          `json:"name"`
	Namespace  string          `json:"namespace"`
	Image      string          `json:"image"`
	Components []SBOMComponent `json:"components"`
}

// BenchmarkControl represents a CIS/NSA benchmark control check result
type BenchmarkControl struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Severity  string `json:"severity"`
	TotalFail int    `json:"totalFail"`
}
