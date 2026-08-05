package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var correlateCmd = &cobra.Command{
	Use:   "correlate <scan.jsonl[.gz]>",
	Short: "Match each out-of-band device to the server it manages",
	Long: "Re-read a finished scan and, for every out-of-band device in it, report the server it " +
		"manages as the BMC itself discloses it: hostname, address, NIC MAC addresses, chassis " +
		"serial, system UUID, model and host OS, each tagged with the check that produced it and " +
		"whether that check needed credentials.\n\n" +
		"Two confidences are reported separately and should not be conflated. A STATED address is " +
		"one the BMC named itself. A RESOLVED address is an identifier the BMC published that some " +
		"independent observation in the same scan located: a MAC found in another device's " +
		"neighbour cache, or a hostname answered by a scanned address. Everything else is IDENTITY " +
		"only, which is inventory, not a located host.\n\n" +
		"Read-only. No network traffic.",
	Args: cobra.ExactArgs(1),
	RunE: runCorrelateCmd,
}

var correlateOut string

func init() {
	correlateCmd.Flags().StringVarP(&correlateOut, "output", "o", "",
		"write results here (default: alongside the input as <scan>.managed.jsonl)")
	rootCmd.AddCommand(correlateCmd)
}

func runCorrelateCmd(_ *cobra.Command, args []string) error {
	sum, path, err := runCorrelateStageTo(args[0], correlateOut)
	if err != nil {
		return err
	}
	fmt.Fprintln(rootCmd.ErrOrStderr(), correlateSummaryLine(sum, path))
	return nil
}
