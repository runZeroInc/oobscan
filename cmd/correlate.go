package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

// The same pass `scan` runs on completion, exposed so an existing scan file can be
// reprocessed without re-probing anything. Correlation logic changes far more often
// than the collection does, and a sweep is expensive to repeat.
var correlateCmd = &cobra.Command{
	Use:   "correlate <scan.jsonl[.gz]>",
	Short: "Annotate each out-of-band device with the server it manages",
	Long: "Re-read a finished scan and, for every out-of-band device in it, record the server it " +
		"manages as the BMC itself discloses it: hostname, address, NIC MAC addresses, chassis " +
		"serial, system UUID, model and host OS, each tagged with the check that produced it and " +
		"whether that check needed credentials. The result is added to that device's own record " +
		"under managedHost; the scan file is rewritten in place unless --output names another one.\n\n" +
		"Two confidences are reported separately and should not be conflated. A STATED address is " +
		"one the BMC named itself. A RESOLVED address is an identifier the BMC published that some " +
		"independent observation in the same scan located: a MAC found in another device's " +
		"neighbour cache, or a hostname answered by a scanned address. Everything else is IDENTITY " +
		"only, which is inventory, not a located host.\n\n" +
		"Re-runnable: a scan that was already correlated has its managedHost replaced, not " +
		"duplicated. No network traffic.",
	Args: cobra.ExactArgs(1),
	RunE: runCorrelateCmd,
}

var correlateOut string

func init() {
	correlateCmd.Flags().StringVarP(&correlateOut, "output", "o", "",
		"write the annotated scan here instead of rewriting the input (a full scan file, not a "+
			"managed-device-only one; '-' is stdout)")
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
