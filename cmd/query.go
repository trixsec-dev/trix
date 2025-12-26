package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/davealtena/trix/internal/tools/kubectl"
	"github.com/davealtena/trix/internal/tools/trivy"
	"github.com/spf13/cobra"
)

var (
	namespace     string
	showDetails   bool
	allNamespaces bool
	output        string
	packageFilter string
	showFull      bool
)

var queryCmd = &cobra.Command{
	Use:   "query",
	Short: "Query Kubernetes security resources",
	Long:  `Query vulnerability reports, compliance data, and security posture from your cluster.`,
}

// VulnReport represents a vulnerability report with parsed data
type VulnReport struct {
	Name            string                `json:"name"`
	Namespace       string                `json:"namespace"`
	Critical        int64                 `json:"critical"`
	High            int64                 `json:"high"`
	Medium          int64                 `json:"medium"`
	Low             int64                 `json:"low"`
	Vulnerabilities []trivy.Vulnerability `json:"vulnerabilities,omitempty"`
}

// ComplianceReport represents a compliance report with parsed data
type ComplianceReport struct {
	Name      string                  `json:"name"`
	Namespace string                  `json:"namespace"`
	Critical  int64                   `json:"critical"`
	High      int64                   `json:"high"`
	Medium    int64                   `json:"medium"`
	Low       int64                   `json:"low"`
	Checks    []trivy.ComplianceCheck `json:"checks,omitempty"`
}

var queryVulnsCmd = &cobra.Command{
	Use:   "vulns",
	Short: "List vulnerability reports from Trivy Operator",
	Run: func(cmd *cobra.Command, args []string) {
		k8sClient, err := kubectl.NewClient()
		if err != nil {
			fmt.Printf("Error creating K8s client: %v\n", err)
			return
		}
		trivyClient := trivy.NewClient(k8sClient)

		ctx := context.Background()

		currentCtx, err := k8sClient.GetCurrentContext()
		if err != nil {
			fmt.Printf("Error getting context: %v\n", err)
		}

		// Only show context info in text mode
		if output != "json" {
			fmt.Printf("Using context: %s\n", currentCtx)
		}

		// Determine namespace based on flag
		ns := namespace
		if allNamespaces {
			ns = "" // Empty string = all namespaces in k8s API
			if output != "json" {
				fmt.Printf("Namespace: all\n\n")
			}
		} else {
			if output != "json" {
				fmt.Printf("Namespace: %s\n\n", ns)
			}
		}

		reports, err := trivyClient.ListVulnerabilityReports(ctx, ns)
		if err != nil {
			fmt.Printf("Error listing vulnerability reports: %v\n", err)
			return
		}

		// Collect all reports for JSON output
		var vulnReports []VulnReport

		if output != "json" {
			fmt.Printf("Found %d vulnerability reports:\n", len(reports))
		}

		for i, report := range reports {
			// Extract metadata
			metadata, ok := report["metadata"].(map[string]interface{})
			if !ok {
				continue
			}
			name, _ := metadata["name"].(string)
			ns, _ := metadata["namespace"].(string)

			// Extract report data
			reportData, ok := report["report"].(map[string]interface{})
			if !ok {
				if output != "json" {
					fmt.Printf("%d. %s (no report data)\n", i+1, name)
				}
				continue
			}

			// Extract summary from report
			summary, ok := reportData["summary"].(map[string]interface{})
			if !ok {
				if output != "json" {
					fmt.Printf("%d. %s (no summary)\n", i+1, name)
				}
				continue
			}

			// Convert to int
			critical, _ := summary["criticalCount"].(int64)
			high, _ := summary["highCount"].(int64)
			medium, _ := summary["mediumCount"].(int64)
			low, _ := summary["lowCount"].(int64)

			vulnReport := VulnReport{
				Name:      name,
				Namespace: ns,
				Critical:  critical,
				High:      high,
				Medium:    medium,
				Low:       low,
			}

			// Parse vulnerabilities if requested or JSON output
			if showDetails || output == "json" {
				vulns, err := trivyClient.ParseVulnerabilities(report)
				if err != nil && output != "json" {
					fmt.Printf("Error parsing vulnerabilities: %v\n", err)
					continue
				}
				vulnReport.Vulnerabilities = vulns
			}

			vulnReports = append(vulnReports, vulnReport)

			// Text output
			if output != "json" {
				fmt.Printf("%d. %s Critical: %d High: %d Medium: %d Low: %d\n", i+1, name, critical, high, medium, low)

				if showDetails && len(vulnReport.Vulnerabilities) > 0 {
					fmt.Printf("   Parsed %d vulnerabilities (Showing first 3):\n", len(vulnReport.Vulnerabilities))
					for i, v := range vulnReport.Vulnerabilities {
						if i >= 3 {
							break
						}
						fmt.Printf("   %+v\n", v)
					}
				}
			}
		}

		// JSON output
		if output == "json" {
			jsonData, err := json.MarshalIndent(vulnReports, "", "  ")
			if err != nil {
				fmt.Printf("Error marshaling JSON: %v\n", err)
				return
			}
			fmt.Println(string(jsonData))
		}
	},
}

var queryComplianceCmd = &cobra.Command{
	Use:   "compliance",
	Short: "List compliance reports from Trivy Operator",
	Run: func(cmd *cobra.Command, args []string) {
		k8sClient, err := kubectl.NewClient()
		if err != nil {
			fmt.Printf("Error creating K8s client: %v\n", err)
			return
		}
		trivyClient := trivy.NewClient(k8sClient)

		ctx := context.Background()

		currentCtx, err := k8sClient.GetCurrentContext()
		if err != nil {
			fmt.Printf("Error getting context: %v\n", err)
		}

		// Only show context info in text mode
		if output != "json" {
			fmt.Printf("Using context: %s\n", currentCtx)
		}

		// Determine namespace based on flag
		ns := namespace
		if allNamespaces {
			ns = "" // Empty string = all namespaces in k8s API
			if output != "json" {
				fmt.Printf("Namespace: all\n\n")
			}
		} else {
			if output != "json" {
				fmt.Printf("Namespace: %s\n\n", ns)
			}
		}

		reports, err := trivyClient.ListConfigAuditReports(ctx, ns)
		if err != nil {
			fmt.Printf("Error listing compliance reports: %v\n", err)
			return
		}

		// Collect all reports for JSON output
		var complianceReports []ComplianceReport

		if output != "json" {
			fmt.Printf("Found %d compliance reports:\n", len(reports))
		}

		for i, report := range reports {
			// Extract metadata
			metadata, ok := report["metadata"].(map[string]interface{})
			if !ok {
				continue
			}
			name, _ := metadata["name"].(string)
			ns, _ := metadata["namespace"].(string)

			// Extract report data
			reportData, ok := report["report"].(map[string]interface{})
			if !ok {
				if output != "json" {
					fmt.Printf("%d. %s (no report data)\n", i+1, name)
				}
				continue
			}

			// Extract summary from report
			summary, ok := reportData["summary"].(map[string]interface{})
			if !ok {
				if output != "json" {
					fmt.Printf("%d. %s (no summary)\n", i+1, name)
				}
				continue
			}

			// Convert to int
			critical, _ := summary["criticalCount"].(int64)
			high, _ := summary["highCount"].(int64)
			medium, _ := summary["mediumCount"].(int64)
			low, _ := summary["lowCount"].(int64)

			complianceReport := ComplianceReport{
				Name:      name,
				Namespace: ns,
				Critical:  critical,
				High:      high,
				Medium:    medium,
				Low:       low,
			}

			// Parse checks if requested or JSON output
			if showDetails || output == "json" {
				checks, err := trivyClient.ParseComplianceChecks(report)
				if err != nil && output != "json" {
					fmt.Printf("Error parsing compliance checks: %v\n", err)
					continue
				}
				complianceReport.Checks = checks
			}

			complianceReports = append(complianceReports, complianceReport)

			// Text output
			if output != "json" {
				fmt.Printf("%d. %s Critical: %d High: %d Medium: %d Low: %d\n", i+1, name, critical, high, medium, low)

				if showDetails && len(complianceReport.Checks) > 0 {
					fmt.Printf("   Parsed %d checks (Showing first 3):\n", len(complianceReport.Checks))
					for i, c := range complianceReport.Checks {
						if i >= 3 {
							break
						}
						fmt.Printf("   %+v\n", c)
					}
				}
			}
		}

		// JSON output
		if output == "json" {
			jsonData, err := json.MarshalIndent(complianceReports, "", "  ")
			if err != nil {
				fmt.Printf("Error marshaling JSON: %v\n", err)
				return
			}
			fmt.Println(string(jsonData))
		}
	},
}

var queryFindingsCmd = &cobra.Command{
	Use:   "findings",
	Short: "Query all security findings (unified view)",
	Run: func(cmd *cobra.Command, args []string) {
		k8sClient, err := kubectl.NewClient()
		if err != nil {
			fmt.Printf("Error creating k8s client: %v\n", err)
			return
		}
		trivyClient := trivy.NewClient(k8sClient)

		ctx := context.Background()

		// Determine namespace
		ns := namespace
		if allNamespaces {
			ns = ""
		}

		// Create all scanners - they all implement the Scanner interface
		scanners := []trivy.Scanner{
			// Namespaced scanners
			trivy.NewTrivyVulnScanner(trivyClient),
			trivy.NewTrivyComplianceScanner(trivyClient),
			trivy.NewTrivySecretScanner(trivyClient),
			trivy.NewTrivyRbacScanner(trivyClient),
			trivy.NewTrivyInfraScanner(trivyClient),
			// Cluster-scoped scanners
			trivy.NewClusterVulnScanner(trivyClient),
			trivy.NewClusterComplianceScanner(trivyClient),
			trivy.NewClusterRbacScanner(trivyClient),
			trivy.NewClusterInfraScanner(trivyClient),
			// Benchmark scanner (CIS/NSA)
			trivy.NewBenchmarkScanner(trivyClient),
		}

		var allFindings []trivy.Finding

		// Run each scanner
		for _, scanner := range scanners {
			if output != "json" {
				fmt.Printf("Running %s scanner..\n", scanner.Name())
			}

			findings, err := scanner.Scan(ctx, ns)
			if err != nil {
				fmt.Printf("Error in %s: %v\n", scanner.Name(), err)
				continue
			}

			allFindings = append(allFindings, findings...)
		}

		// Output results
		if output == "json" {
			// Strip RawData by default to reduce output size (use --full to include)
			outputFindings := allFindings
			if !showFull {
				outputFindings = make([]trivy.Finding, len(allFindings))
				for i, f := range allFindings {
					outputFindings[i] = f
					outputFindings[i].RawData = nil
				}
			}
			jsonData, err := json.MarshalIndent(outputFindings, "", "  ")
			if err != nil {
				fmt.Printf("Error marshaling JSON: %v\n", err)
				return
			}
			fmt.Println(string(jsonData))
		} else {
			fmt.Printf("\nFound %d total findings:\n", len(allFindings))
			for i, f := range allFindings {
				fmt.Printf("%d. [%s] %s - %s (%s)\n", i+1, f.Severity, f.Type, f.Title, f.ResourceName)
			}
		}
	},
}

// Summary represents aggregated findings data
type Summary struct {
	BySeverity    map[string]int  `json:"bySeverity"`
	ByType        map[string]int  `json:"byType"`
	TopResources  []ResourceCount `json:"topResources"`
	TotalFindings int             `json:"totalFindings"`
}

// ResourceCount tracks findings per resource
type ResourceCount struct {
	Resource string `json:"resource"`
	Count    int    `json:"count"`
}

var querySummaryCmd = &cobra.Command{
	Use:   "summary",
	Short: "Show aggregated security findings summary",
	Run: func(cmd *cobra.Command, args []string) {
		k8sClient, err := kubectl.NewClient()
		if err != nil {
			fmt.Printf("Error creating k8s client: %v\n", err)
			return
		}
		trivyClient := trivy.NewClient(k8sClient)

		ctx := context.Background()

		ns := namespace
		if allNamespaces {
			ns = ""
		}

		// Create all scanners
		scanners := []trivy.Scanner{
			trivy.NewTrivyVulnScanner(trivyClient),
			trivy.NewTrivyComplianceScanner(trivyClient),
			trivy.NewTrivySecretScanner(trivyClient),
			trivy.NewTrivyRbacScanner(trivyClient),
			trivy.NewTrivyInfraScanner(trivyClient),
			trivy.NewClusterVulnScanner(trivyClient),
			trivy.NewClusterComplianceScanner(trivyClient),
			trivy.NewClusterRbacScanner(trivyClient),
			trivy.NewClusterInfraScanner(trivyClient),
			trivy.NewBenchmarkScanner(trivyClient),
		}

		var allFindings []trivy.Finding

		// Run each scanner
		for _, scanner := range scanners {
			findings, err := scanner.Scan(ctx, ns)
			if err != nil {
				continue
			}
			allFindings = append(allFindings, findings...)
		}

		// Aggregate by severity
		bySeverity := make(map[string]int)
		for _, f := range allFindings {
			bySeverity[string(f.Severity)]++
		}

		// Aggregate by type
		byType := make(map[string]int)
		for _, f := range allFindings {
			byType[string(f.Type)]++
		}

		// Count by resource (for top affected)
		// Exclude benchmark findings - they're framework-level, not resource-level
		resourceCounts := make(map[string]int)
		for _, f := range allFindings {
			if f.Type == trivy.FindingTypeBenchmark {
				continue // Skip benchmarks - not actual K8s resources
			}
			key := f.ResourceName
			if f.Namespace != "" {
				key = f.Namespace + "/" + f.ResourceName
			}
			resourceCounts[key]++
		}

		// Sort and get top 10
		topResources := getTopResources(resourceCounts, 10)

		summary := Summary{
			BySeverity:    bySeverity,
			ByType:        byType,
			TopResources:  topResources,
			TotalFindings: len(allFindings),
		}

		if output == "json" {
			jsonData, err := json.MarshalIndent(summary, "", "  ")
			if err != nil {
				fmt.Printf("Error marshaling JSON: %v\n", err)
				return
			}
			fmt.Println(string(jsonData))
			return
		}

		// Text output
		fmt.Printf("Security Findings Summary\n")
		fmt.Printf("=========================\n\n")

		fmt.Printf("Total Findings: %d\n\n", len(allFindings))

		fmt.Printf("By Severity:\n")
		for _, sev := range []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"} {
			if count, ok := bySeverity[sev]; ok {
				fmt.Printf("  %-10s %d\n", sev+":", count)
			}
		}

		fmt.Printf("\nBy Type:\n")
		for _, typ := range []string{"vulnerability", "compliance", "rbac", "secret", "infra", "benchmark"} {
			if count, ok := byType[typ]; ok {
				fmt.Printf("  %-15s %d\n", typ+":", count)
			}
		}

		if len(topResources) > 0 {
			fmt.Printf("\nTop Affected Resources:\n")
			for _, rc := range topResources {
				fmt.Printf("  %s - %d findings\n", rc.Resource, rc.Count)
			}
		}
	},
}

// getTopResources returns the top N resources by finding count
func getTopResources(counts map[string]int, n int) []ResourceCount {
	var result []ResourceCount
	for resource, count := range counts {
		result = append(result, ResourceCount{Resource: resource, Count: count})
	}

	// Simple bubble sort for top N (good enough for this use case)
	for i := 0; i < len(result); i++ {
		for j := i + 1; j < len(result); j++ {
			if result[j].Count > result[i].Count {
				result[i], result[j] = result[j], result[i]
			}
		}
	}

	if len(result) > n {
		result = result[:n]
	}
	return result
}

var queryNetworkCmd = &cobra.Command{
	Use:   "network",
	Short: "Analyze NetworkPolicy coverage",
	Run: func(cmd *cobra.Command, args []string) {
		k8sClient, err := kubectl.NewClient()
		if err != nil {
			fmt.Printf("Error creating k8s client: %v\n", err)
			return
		}

		ctx := context.Background()

		ns := namespace
		if allNamespaces {
			ns = ""
		}

		coverage, err := k8sClient.AnalyzeCoverage(ctx, ns)
		if err != nil {
			fmt.Printf("Error analyzing coverage: %v\n", err)
			return
		}

		if output == "json" {
			jsonData, _ := json.MarshalIndent(coverage, "", "  ")
			fmt.Println(string(jsonData))
			return
		}

		// Text output
		for _, c := range coverage {
			fmt.Printf("Namespace: %s\n", c.Namespace)
			fmt.Printf("  Policies: %d (%s)\n", len(c.Policies), strings.Join(c.Policies, ", "))
			fmt.Printf("  Pods: %d/%d covered\n", c.CoveredPods, c.TotalPods)
			if len(c.UncoveredPods) > 0 {
				fmt.Printf("  ⚠️  Uncovered pods: %s\n", strings.Join(c.UncoveredPods, ", "))
			}
		}
	},
}

var querySbomCmd = &cobra.Command{
	Use:   "sbom",
	Short: "List software components from SBOM reports",
	Run: func(cmd *cobra.Command, args []string) {
		k8sClient, err := kubectl.NewClient()
		if err != nil {
			fmt.Printf("Error creating K8s client: %v\n", err)
			return
		}
		trivyClient := trivy.NewClient(k8sClient)

		ctx := context.Background()

		ns := namespace
		if allNamespaces {
			ns = ""
		}

		reports, err := trivyClient.ListSbomReports(ctx, ns)
		if err != nil {
			fmt.Printf("Error listing SBOM reports: %v\n", err)
			return
		}

		// Also get cluster-scoped SBOMs
		clusterReports, err := trivyClient.ListClusterSbomReports(ctx)
		if err == nil {
			reports = append(reports, clusterReports...)
		}

		if output == "json" {
			var sboms []trivy.SBOMReport
			for _, report := range reports {
				sbom, err := trivyClient.ParseSBOMReport(report)
				if err != nil {
					continue
				}
				// Apply package filter to JSON output too
				if packageFilter != "" {
					var filtered []trivy.SBOMComponent
					for _, comp := range sbom.Components {
						if strings.Contains(strings.ToLower(comp.Name), strings.ToLower(packageFilter)) {
							filtered = append(filtered, comp)
						}
					}
					if len(filtered) == 0 {
						continue // Skip images with no matches
					}
					sbom.Components = filtered
				}
				sboms = append(sboms, *sbom)
			}
			jsonData, _ := json.MarshalIndent(sboms, "", "  ")
			fmt.Println(string(jsonData))
			return
		}

		// Text output
		totalComponents := 0
		for _, report := range reports {
			sbom, err := trivyClient.ParseSBOMReport(report)
			if err != nil {
				continue
			}

			// Filter by package name if specified
			if packageFilter != "" {
				for _, comp := range sbom.Components {
					if strings.Contains(strings.ToLower(comp.Name), strings.ToLower(packageFilter)) {
						fmt.Printf("%s: %s %s (%s)\n", sbom.Image, comp.Name, comp.Version, comp.Type)
						totalComponents++
					}
				}
			} else {
				fmt.Printf("\n%s (%d components)\n", sbom.Image, len(sbom.Components))
				totalComponents += len(sbom.Components)
				if showDetails {
					for _, comp := range sbom.Components {
						fmt.Printf("  - %s %s (%s)\n", comp.Name, comp.Version, comp.Type)
					}
				}
			}
		}

		if packageFilter == "" {
			fmt.Printf("\nTotal: %d images, %d components\n", len(reports), totalComponents)
		} else {
			fmt.Printf("\nFound %d matches for '%s'\n", totalComponents, packageFilter)
		}
	},
}

func init() {
	rootCmd.AddCommand(queryCmd)
	queryCmd.AddCommand(queryVulnsCmd)
	queryCmd.AddCommand(queryComplianceCmd)
	queryCmd.AddCommand(queryFindingsCmd)
	queryCmd.AddCommand(querySbomCmd)
	queryCmd.AddCommand(querySummaryCmd)
	queryCmd.AddCommand(queryNetworkCmd)

	// Global flag for all query subcommands
	queryCmd.PersistentFlags().StringVarP(&namespace, "namespace", "n", "default", "Kubernetes namespace")
	queryCmd.PersistentFlags().BoolVarP(&allNamespaces, "all-namespaces", "A", false, "Query across all namespaces")
	queryCmd.PersistentFlags().StringVarP(&output, "output", "o", "", "Output format (json)")
	querySbomCmd.Flags().StringVar(&packageFilter, "package", "", "Filter by package name")
	querySbomCmd.Flags().BoolVarP(&showDetails, "details", "d", false, "Show all components")
	queryVulnsCmd.Flags().BoolVarP(&showDetails, "details", "d", false, "Show detailed CVE information")
	queryFindingsCmd.Flags().BoolVar(&showFull, "full", false, "Include full RawData in JSON output")
}
