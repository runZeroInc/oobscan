package cmd

import (
	"fmt"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/runZeroInc/oobscan/pkg/check"
	"github.com/runZeroInc/oobscan/pkg/oob"
)

// coverageCmd prints what oobscan covers: the OOB/BMC device inventory (which
// vendors/products and which protocol probes map to each), followed by the
// registered security checks and their applicability.
var coverageCmd = &cobra.Command{
	Use:   "coverage",
	Short: "Show the OOB/BMC vendors, products, and security checks oobscan covers.",
	Long:  "Print the oobscan device inventory grouped by vendor (with the probes wired up per device), then the registered security-check registry.",
	Run:   runCoverage,
}

func runCoverage(cmd *cobra.Command, args []string) {
	lg := log()
	vendors := oob.Vendors()
	sort.Strings(vendors)
	byV := oob.ByVendor()

	total := 0
	for _, v := range vendors {
		for _, d := range byV[v] {
			total++
			lg.Info("Device covered",
				"vendor", d.Vendor,
				"product", d.Product,
				"category", string(d.Category),
				"ipmi", tick(d.IPMI),
				"redfish", tick(d.Redfish),
				"ssh", tick(d.SSH),
				"snmp", tick(d.SNMP),
				"ssdp", tick(d.SSDP),
				"slp", tick(d.SLP),
				"wsman", tick(d.WSMAN),
				"fingerprints", fmt.Sprintf("%d", len(d.Fingerprints)))
		}
	}
	lg.Info("Device coverage summary", "products", fmt.Sprintf("%d", total), "vendors", fmt.Sprintf("%d", len(vendors)))

	printChecks()
}

// printChecks lists every registered security check: its category, whether it
// is enabled by default, whether it needs credentials or is destructive, and
// which device classes/vendors it applies to.
func printChecks() {
	lg := log()
	checks := check.All()
	for _, c := range checks {
		flags := ""
		if c.Authenticated {
			flags += "auth"
		}
		if c.Destructive {
			if flags != "" {
				flags += ","
			}
			flags += "destructive"
		}
		if flags == "" {
			flags = "-"
		}
		def := "-"
		if c.Enabled {
			def = "yes"
		}
		lg.Info("Check registered",
			"check", c.Name,
			"category", c.Category,
			"default", def,
			"flags", flags,
			"applies_to", strings.TrimSpace(appliesTo(c)),
			"description", c.Description)
	}
	lg.Info("Check registry summary", "checks", fmt.Sprintf("%d", len(checks)))
}

func appliesTo(c check.Check) string {
	if c.Applies.CrossVendor || (len(c.Applies.Classes) == 0 && len(c.Applies.Vendors) == 0) {
		return "any (cross-vendor)"
	}
	parts := make([]string, 0, len(c.Applies.Classes)+len(c.Applies.Vendors))
	for _, cl := range c.Applies.Classes {
		parts = append(parts, string(cl))
	}
	parts = append(parts, c.Applies.Vendors...)
	return strings.Join(parts, " ") + " "
}

func tick(b bool) string {
	if b {
		return "y"
	}
	return "-"
}

func init() {
	rootCmd.AddCommand(coverageCmd)
}
