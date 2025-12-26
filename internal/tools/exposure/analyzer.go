package exposure

import (
	"context"
	"fmt"
	"strings"
)

// Analyzer runs all registered checkers and builds a Result
type Analyzer struct {
	checkers []Checker
}

// NewAnalyzer creates an analyzer with the given checkers
func NewAnalyzer(checkers ...Checker) *Analyzer {
	return &Analyzer{checkers: checkers}
}

// Analyze runs all checkers and returns the combined result
func (a *Analyzer) Analyze(ctx context.Context, workload Workload) (*Result, error) {
	var allPoints []ExposurePoint

	for _, checker := range a.checkers {
		points, err := checker.Check(ctx, workload)
		if err != nil {
			// Log but continue - one checker failing shouldnt stop others
			continue
		}
		allPoints = append(allPoints, points...)
	}

	level := DetermineLevel(allPoints)
	summary := GenerateSummary(level, allPoints)

	return &Result{
		Workload:       workload,
		ExposurePoints: allPoints,
		Level:          level,
		Summary:        summary,
	}, nil
}

// DetermineLevel calculates the highest exposure level from points
func DetermineLevel(points []ExposurePoint) ExposureLevel {
	if len(points) == 0 {
		return ExposureLevelNone
	}

	hasExternal := false
	hasNodePort := false
	hasClusterInternal := false

	for _, p := range points {
		switch p.Type {
		case ExposureTypeIngress, ExposureTypeHTTPRoute, ExposureTypeGRPCRoute, ExposureTypeUDPRoute, ExposureTypeGateway, ExposureTypeLoadbalancer:
			hasExternal = true
		case ExposureTypeNodePort:
			hasNodePort = true
		case ExposureTypeService:
			hasClusterInternal = true
		}
	}

	if hasExternal {
		return ExposureLevelExternal
	}
	if hasNodePort {
		return ExposureLevelNodePort
	}
	if hasClusterInternal {
		return ExposureLevelClusterInternal
	}
	return ExposureLevelNone
}

// GenerateSummary creates a human-readable summary
func GenerateSummary(level ExposureLevel, points []ExposurePoint) string {
	var details []string
	for _, p := range points {
		details = append(details, fmt.Sprintf("%s/%s", p.Type, p.Name))
	}

	base := ""
	switch level {
	case ExposureLevelExternal:
		base = "EXTERNALLY EXPOSED - This workload appears reachable from outside the cluster."
	case ExposureLevelNodePort:
		base = "NODEPORT EXPOSED - Reachable on node IPs, may be external depending on network."
	case ExposureLevelClusterInternal:
		base = "INTERNAL ONLY - ClusterIP service, accessible within cluster network only."
	case ExposureLevelNone:
		base = "NO EXPOSURE DETECTED - No services found selecting this workload."
	}

	if len(details) > 0 {
		return fmt.Sprintf("%s Via: %s", base, strings.Join(details, ", "))
	}
	return base
}

// CompactString returns a token-efficient string representation for AI agent output
// The full Result struct is available for programmatic use, but when sending to
// the LLM we want to minimize tokens while preserving actionable information
func (r *Result) CompactString() string {
	var b strings.Builder

	b.WriteString(fmt.Sprintf("Workload: %s/%s (%s)\n", r.Workload.Namespace, r.Workload.Name, r.Workload.Kind))
	b.WriteString(fmt.Sprintf("Exposure level: %s\n\n", r.Level))

	if len(r.ExposurePoints) == 0 {
		b.WriteString("No exposure points detected.\n")
	} else {
		b.WriteString("Exposure points:\n")
		maxPoints := 10
		for i, p := range r.ExposurePoints {
			if i >= maxPoints {
				b.WriteString(fmt.Sprintf("  ... and %d more\n", len(r.ExposurePoints)-maxPoints))
				break
			}
			line := fmt.Sprintf("  - %s: %s", p.Type, p.Name)
			if len(p.Ports) > 0 {
				line += fmt.Sprintf(" (ports: %v)", p.Ports)
			}
			if len(p.Hosts) > 0 {
				line += fmt.Sprintf(" (hosts: %v)", p.Hosts)
			}
			b.WriteString(line + "\n")
		}
	}
	b.WriteString(fmt.Sprintf("\nAssessment: %s\n", r.Summary))

	return b.String()
}
