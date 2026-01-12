package cmd

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"
	"github.com/trixsec-dev/trix/internal/tools/kubectl"
	"github.com/trixsec-dev/trix/internal/tools/trivy"
)

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Check status of security tools in the cluster",
	Long:  `Verify that Trivy Operator and other security tools are installed and working.`,
	Run: func(cmd *cobra.Command, args []string) {
		k8sClient, err := kubectl.NewClient()
		if err != nil {
			fmt.Printf("Error creating k8s client: %v\n", err)
			return
		}
		trivyClient := trivy.NewClient(k8sClient)

		ctx := context.Background()
		fmt.Println("Checking security tooling status..")

		// Check Trivy Operator
		trivyOk, trivyVersion := trivyClient.CheckTrivyOperator(ctx)
		if trivyOk {
			fmt.Printf("✅ Trivy Operator: installed (version: %s)\n", trivyVersion)

			// Simple version check (works for 0.x.y format)
			if trivyVersion != "unknown" && trivyVersion < trivy.MinTrivyOperatorVersion {
				fmt.Printf("   ⚠️  Warning: version %s is below minimum %s\n", trivyVersion, trivy.MinTrivyOperatorVersion)
			}
		} else {
			fmt.Printf("❌ Trivy Operator: not found or not working\n")
		}
	},
}

func init() {
	rootCmd.AddCommand(statusCmd)
}
