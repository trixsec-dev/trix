package trivy

import "context"

// Scanner is implemented by all scanners
type Scanner interface {
	// Name returns the scanner identifier (e.g., "trivy-vulns", "rbac")
	Name() string

	// Scan runs the scanner and returns findings
	Scan(ctx context.Context, namespace string) ([]Finding, error)
}
