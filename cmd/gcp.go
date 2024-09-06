package cmd

import (
	"os"

	"github.com/spf13/cobra"
)

var gcpCmd = &cobra.Command{
	Use:   "gcp",
	Short: "Interact with Google Cloud Platform",
	Long:  `This command allows you to interact with various services on Google Cloud Platform.`,
	Run: func(cmd *cobra.Command, args []string) {
		cmd.Help()
		os.Exit(1)
	},
}

var gcpReconCmd = &cobra.Command{
	Use:   "recon",
	Short: "GCP recon modules",
	Run: func(cmd *cobra.Command, args []string) {
		cmd.Help()
		os.Exit(1)
	},
}

func init() {
	gcpCmd.AddCommand(gcpReconCmd)
	rootCmd.AddCommand(gcpCmd)
}
