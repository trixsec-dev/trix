package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

// Version is set at build via ldflags or defaults to current release
var Version = "0.2.0"

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the version number",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("trix version %s\n", Version)
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
}
