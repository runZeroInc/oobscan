package cmd

import (
	"github.com/spf13/cobra"
)

// Version is set at link-time via -ldflags "-X ...cmd.Version=...".
var Version = "0.0.1-dev"

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the oobscan version.",
	Run: func(cmd *cobra.Command, args []string) {
		log().Info("oobscan", "version", Version)
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
}
