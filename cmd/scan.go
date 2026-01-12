package cmd

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/trixsec-dev/trix/internal/tools/kubectl"
	"github.com/trixsec-dev/trix/internal/tools/trivy"
)

var (
	scanYes           bool
	scanAllNamespaces bool
	scanNamespace     string
)

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Trigger Trivy rescans by deleting reports",
	Long: `Trigger Trivy Operator to rescan resources by deleting existing reports.
When a report is deleted, Trivy Operator automatically rescans the resource.`,
}

var scanVulnsCmd = &cobra.Command{
	Use:   "vulns",
	Short: "Trigger vulnerability rescan",
	Run: func(cmd *cobra.Command, args []string) {
		runScan("vulns")
	},
}

var scanComplianceCmd = &cobra.Command{
	Use:   "compliance",
	Short: "Trigger compliance rescan",
	Run: func(cmd *cobra.Command, args []string) {
		runScan("compliance")
	},
}

var scanSecretsCmd = &cobra.Command{
	Use:   "secrets",
	Short: "Trigger secrets rescan",
	Run: func(cmd *cobra.Command, args []string) {
		runScan("secrets")
	},
}

var scanRbacCmd = &cobra.Command{
	Use:   "rbac",
	Short: "Trigger RBAC rescan",
	Run: func(cmd *cobra.Command, args []string) {
		runScan("rbac")
	},
}

var scanInfraCmd = &cobra.Command{
	Use:   "infra",
	Short: "Trigger infrastructure rescan",
	Run: func(cmd *cobra.Command, args []string) {
		runScan("infra")
	},
}

var scanSbomCmd = &cobra.Command{
	Use:   "sbom",
	Short: "Trigger SBOM rescan",
	Run: func(cmd *cobra.Command, args []string) {
		runScan("sbom")
	},
}

var scanBenchmarkCmd = &cobra.Command{
	Use:   "benchmark",
	Short: "Trigger benchmark rescan (CIS/NSA)",
	Run: func(cmd *cobra.Command, args []string) {
		runScan("benchmark")
	},
}

var scanAllCmd = &cobra.Command{
	Use:   "all",
	Short: "Trigger rescan of all report types",
	Run: func(cmd *cobra.Command, args []string) {
		runScan("all")
	},
}

func runScan(scanType string) {
	k8sClient, err := kubectl.NewClient()
	if err != nil {
		fmt.Printf("Error creating k8s client: %v\n", err)
		return
	}
	trivyClient := trivy.NewClient(k8sClient)

	ctx := context.Background()

	// Determine namespace
	ns := scanNamespace
	if scanAllNamespaces {
		ns = ""
	}

	// Count reports first
	counts, err := trivyClient.CountAllReports(ctx, ns)
	if err != nil {
		fmt.Printf("Error counting reports: %v\n", err)
		return
	}

	// Calculate what will be deleted based on scan type
	var toDelete int
	var description string

	switch scanType {
	case "vulns":
		toDelete = counts.VulnerabilityReports + counts.ClusterVulnerabilityReports
		description = "vulnerability reports"
	case "compliance":
		toDelete = counts.ConfigAuditReports + counts.ClusterConfigAuditReports
		description = "compliance reports"
	case "secrets":
		toDelete = counts.ExposedSecretReports
		description = "secret reports"
	case "rbac":
		toDelete = counts.RbacAssessmentReports + counts.ClusterRbacAssessmentReports
		description = "RBAC reports"
	case "infra":
		toDelete = counts.InfraAssessmentReports + counts.ClusterInfraAssessmentReports
		description = "infrastructure reports"
	case "sbom":
		toDelete = counts.SbomReports
		description = "SBOM reports"
	case "benchmark":
		toDelete = counts.ClusterComplianceReports
		description = "benchmark reports"
	case "all":
		toDelete = counts.Total()
		description = "ALL reports"
	}

	if toDelete == 0 {
		fmt.Printf("No %s found to delete.\n", description)
		return
	}

	// Show what will be deleted
	nsDisplay := scanNamespace
	if scanAllNamespaces {
		nsDisplay = "all namespaces"
	}
	fmt.Printf("This will delete %d %s in %s and trigger Trivy rescans.\n", toDelete, description, nsDisplay)

	// Confirm unless --yes flag
	if !scanYes {
		fmt.Print("Continue? [y/N]: ")
		reader := bufio.NewReader(os.Stdin)
		response, _ := reader.ReadString('\n')
		response = strings.TrimSpace(strings.ToLower(response))
		if response != "y" && response != "yes" {
			fmt.Println("Aborted.")
			return
		}
	}

	// Perform the deletion
	var deleted int

	switch scanType {
	case "vulns":
		deleted += deleteWithCount(trivyClient.DeleteVulnerabilityReports(ctx, ns))
		deleted += deleteWithCount(trivyClient.DeleteClusterVulnerabilityReports(ctx))
	case "compliance":
		deleted += deleteWithCount(trivyClient.DeleteConfigAuditReports(ctx, ns))
		deleted += deleteWithCount(trivyClient.DeleteClusterConfigAuditReports(ctx))
	case "secrets":
		deleted += deleteWithCount(trivyClient.DeleteExposedSecretReports(ctx, ns))
	case "rbac":
		deleted += deleteWithCount(trivyClient.DeleteRbacAssessmentReports(ctx, ns))
		deleted += deleteWithCount(trivyClient.DeleteClusterRbacAssessmentReports(ctx))
	case "infra":
		deleted += deleteWithCount(trivyClient.DeleteInfraAssessmentReports(ctx, ns))
		deleted += deleteWithCount(trivyClient.DeleteClusterInfraAssessmentReports(ctx))
	case "sbom":
		deleted += deleteWithCount(trivyClient.DeleteSbomReports(ctx, ns))
	case "benchmark":
		deleted += deleteWithCount(trivyClient.DeleteClusterComplianceReports(ctx))
	case "all":
		deleted += deleteWithCount(trivyClient.DeleteVulnerabilityReports(ctx, ns))
		deleted += deleteWithCount(trivyClient.DeleteConfigAuditReports(ctx, ns))
		deleted += deleteWithCount(trivyClient.DeleteExposedSecretReports(ctx, ns))
		deleted += deleteWithCount(trivyClient.DeleteRbacAssessmentReports(ctx, ns))
		deleted += deleteWithCount(trivyClient.DeleteInfraAssessmentReports(ctx, ns))
		deleted += deleteWithCount(trivyClient.DeleteSbomReports(ctx, ns))
		deleted += deleteWithCount(trivyClient.DeleteClusterVulnerabilityReports(ctx))
		deleted += deleteWithCount(trivyClient.DeleteClusterConfigAuditReports(ctx))
		deleted += deleteWithCount(trivyClient.DeleteClusterRbacAssessmentReports(ctx))
		deleted += deleteWithCount(trivyClient.DeleteClusterInfraAssessmentReports(ctx))
		deleted += deleteWithCount(trivyClient.DeleteClusterComplianceReports(ctx))
	}

	fmt.Printf("Deleted %d reports. Trivy Operator will rescan automatically.\n", deleted)
}

func deleteWithCount(count int, err error) int {
	if err != nil {
		fmt.Printf("Warning: %v\n", err)
		return 0
	}
	return count
}

func init() {
	rootCmd.AddCommand(scanCmd)
	scanCmd.AddCommand(scanVulnsCmd)
	scanCmd.AddCommand(scanComplianceCmd)
	scanCmd.AddCommand(scanSecretsCmd)
	scanCmd.AddCommand(scanRbacCmd)
	scanCmd.AddCommand(scanInfraCmd)
	scanCmd.AddCommand(scanSbomCmd)
	scanCmd.AddCommand(scanBenchmarkCmd)
	scanCmd.AddCommand(scanAllCmd)

	// Flags for scan command
	scanCmd.PersistentFlags().BoolVarP(&scanYes, "yes", "y", false, "Skip confirmation prompt")
	scanCmd.PersistentFlags().BoolVarP(&scanAllNamespaces, "all-namespaces", "A", false, "Scan across all namespaces")
	scanCmd.PersistentFlags().StringVarP(&scanNamespace, "namespace", "n", "default", "Kubernetes namespace")
}
