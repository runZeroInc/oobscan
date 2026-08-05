package cmd

import (
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/spf13/cobra"

	"github.com/runZeroInc/oobscan/pkg/hashcrack"
	"github.com/runZeroInc/oobscan/pkg/ipmi"
	"github.com/runZeroInc/oobscan/pkg/output"
	"github.com/runZeroInc/oobscan/pkg/report"
	"github.com/runZeroInc/oobscan/pkg/scanfile"
)

var (
	reportOutput      string
	reportPotfile     string
	reportPotLabel    string
	reportNoArtifacts bool
	reportTitle       string
	reportSubtitle    string
	reportByline      string
	reportAdvisories  string
)

var reportCmd = &cobra.Command{
	Use:   "report -o <dir> [Name=]<file.jsonl> ...",
	Short: "Build an interactive HTML exposure report from one or more scan corpora.",
	Long: `report reads one or more oobscan NDJSON files and writes a self-contained,
offline-capable HTML report to a directory.

Each source is given a name with the Name=path form; a bare path uses the
file's base name. Naming two or more sources adds a cross-source comparison:

  oobscan report -o internal-vs-external \
      Internal=internal.jsonl External=data/oob41.jsonl

The report opens on a set of 16:9, deck-ready overview slides -- one snapshot,
the cross-source comparison (when more than one source is given), and one per
source -- navigable with the arrow keys, presentable fullscreen (Present / F),
and screenshottable to a 1920x1080 PNG with the controls hidden (Capture / P).
Deeper, scrollable detail views (full vendor and exposure tables, ports,
protocols, findings, IPMI/RAKP) sit under the per-source "Detail views" menu.

The bundle holds only aggregates -- no per-host rows and no addresses -- so the
HTML can be shared without exposing which specific systems were scanned.

Percentages are always relative to each source's own population, so two corpora
of very different size are compared on prevalence; absolute host counts are
shown alongside so the population gap stays visible.

Alongside the HTML, each source gets a subdirectory named after it holding the
research artifacts (unless --no-artifacts is given):

  <out>/<Name>/hashes/    cracker-ready RAKP hash files (hashcat -m 7300/7350,
                          John RAKP/-MD5/-SHA256), rakp-hashes.csv, README.txt.
                          The hash files match "oobscan hashdump" byte for byte.
  <out>/<Name>/overview/  vendor, class, product, os, hardware, port, protocol,
                          http-server, check and risk frequency CSVs.
  <out>/<Name>/exposure/  exposure_rates.csv and the per-vendor exposure matrix.
  <out>/<Name>/ipmi/      cipher ids/suites, versions, GUID vendors, OEM names,
                          RAKP users and recovered passwords.
  <out>/<Name>/snmp/      versions, communities, engine ids, sysDescr/OID.
  <out>/<Name>/vendors/   a per-vendor sub-report plus vendors_index.csv.

Inputs may be gzipped (.gz). A source produced by "oobscan convert --redact" is
detected and labelled, and only its already-anonymized values are carried into
the bundle (a redacted source carries no hash material, so its hash files are
empty).

Examples:
  oobscan report -o out results.jsonl
  oobscan report -o cmp Lab=lab.jsonl.gz Internet=oob41.jsonl`,
	Args: cobra.MinimumNArgs(1),
	RunE: runReport,
}

func init() {
	f := reportCmd.Flags()
	f.StringVarP(&reportOutput, "output", "o", "", "output directory for the report bundle (required)")
	f.StringVar(&reportPotfile, "potfile", "", "oobscan potfile to mark RAKP hashes already cracked (default: the app cache potfile; empty string disables)")
	f.BoolVar(&reportNoArtifacts, "no-artifacts", false, "skip the per-source artifact tree (RAKP hash files, overview/exposure/IPMI/SNMP/vendor CSVs) and write only the HTML bundle")
	f.StringVar(&reportPotLabel, "pot-label", "", "label for the crack run behind the potfile (e.g. 'one-day session'); the potfile has no timestamps, so this is an asserted run label")
	f.StringVar(&reportTitle, "title", "", "optional presentation title; adds a title slide")
	f.StringVar(&reportSubtitle, "subtitle", "", "optional presentation subtitle")
	f.StringVar(&reportByline, "byline", "", "optional presentation speaker or author byline")
	f.StringVar(&reportAdvisories, "advisories", "", "optional advisory directory; adds a separate firmware/source evidence slide")
	rootCmd.AddCommand(reportCmd)
}

func runReport(cmd *cobra.Command, args []string) error {
	lg := log()
	if reportOutput == "" {
		return fmt.Errorf("specify an output directory with -o")
	}

	potDisabled := cmd.Flags().Changed("potfile") && reportPotfile == ""
	potCheck := reportPotCheck(potDisabled)

	inputs := make([]report.Input, 0, len(args))
	seen := map[string]struct{}{}
	for _, arg := range args {
		in, err := report.ParseInput(arg)
		if err != nil {
			return err
		}
		if _, dup := seen[in.Name]; dup {
			return fmt.Errorf("duplicate source name %q -- give each source a distinct Name=path", in.Name)
		}
		in.PotCheck = potCheck
		in.PotLabel = reportPotLabel
		seen[in.Name] = struct{}{}
		inputs = append(inputs, in)
	}

	if err := os.MkdirAll(reportOutput, 0o755); err != nil {
		return err
	}

	sources := make([]*report.Source, 0, len(inputs))
	for _, in := range inputs {

		var art *report.Artifacts
		if !reportNoArtifacts {
			art = report.NewArtifacts(in.Name)
			art.SetPotCheck(in.PotCheck)
			in.Observe = art.Observe
		}

		prog := newStreamProgress("Reading", in.Path)
		src, st, err := report.LoadSourceProgress(in, prog.tick)
		prog.finish()
		if err != nil {
			return err
		}
		fields := []string{"name", in.Name, "hosts", strconv.Itoa(st.Records)}
		if src.Redacted {
			fields = append(fields, "redacted", "true")
		}
		if st.Skipped > 0 {
			fields = append(fields, "skipped", strconv.Itoa(st.Skipped))
		}
		lg.Info("Loaded source", fields...)
		sources = append(sources, src)

		if art != nil {
			artDir := filepath.Join(reportOutput, in.Name)
			if err := art.Write(artDir); err != nil {
				return fmt.Errorf("write artifacts for %s: %w", in.Name, err)
			}
			lg.Info("Artifacts written", "name", in.Name, "dir", artDir)
		}
	}

	data := report.Build(time.Now().UTC().Format("2006-01-02 15:04 UTC"), sources)
	data.Title = reportTitle
	data.Subtitle = reportSubtitle
	data.Byline = reportByline
	if reportAdvisories != "" {
		inventory, err := report.LoadAdvisoryInventory(reportAdvisories)
		if err != nil {
			return err
		}
		data.Advisories = &inventory
		lg.Info("Loaded advisory inventory", "path", reportAdvisories, "advisories", strconv.Itoa(inventory.Total), "vendors", strconv.Itoa(inventory.Vendors))
	}
	html, err := report.Render(data)
	if err != nil {
		return err
	}
	indexPath := filepath.Join(reportOutput, "index.html")
	if err := os.WriteFile(indexPath, []byte(html), 0o644); err != nil {
		return err
	}

	lg.Info("Report written", "index", indexPath, "sources", strconv.Itoa(len(sources)), "comparison", strconv.FormatBool(data.Compare != nil))
	return nil
}

func reportPotCheck(disabled bool) func(rec *scanfile.Record) []report.PotCrack {
	if disabled {
		return nil
	}
	path := resolvePotfilePath(reportPotfile)
	pot := loadPotfile(path)
	if len(pot) == 0 {
		return nil
	}
	log().Info("Loaded potfile", "path", path, "cracks", strconv.Itoa(len(pot)))
	return func(rec *scanfile.Record) []report.PotCrack {
		var out []report.PotCrack
		for i := range rec.RAKP {
			if key, ok := rakpPotKey(&rec.RAKP[i]); ok {
				if pw, hit := pot[key]; hit {
					out = append(out, report.PotCrack{Username: rec.RAKP[i].Username, Password: pw})
				}
			}
		}
		return out
	}
}

func rakpPotKey(r *output.RAKPRecord) (string, bool) {
	if r.RAKPHash == "" {
		return "", false
	}
	mac, err := hex.DecodeString(r.RAKPHash)
	if err != nil || len(mac) == 0 {
		return "", false
	}
	cRand, err1 := hex.DecodeString(r.ClientRand)
	bRand, err2 := hex.DecodeString(r.BMCRand)
	guid, err3 := hex.DecodeString(r.BMCGUID)
	if err1 != nil || err2 != nil || err3 != nil {
		return "", false
	}
	rr := &ipmi.RAKPResult{
		Username:   r.Username,
		AuthAlgo:   r.AuthAlgo,
		ClientSID:  r.ClientSID,
		BMCSID:     r.BMCSID,
		ClientRand: cRand,
		BMCRand:    bRand,
		BMCGUID:    guid,
		RAKPHash:   mac,
	}
	algo := hashcrack.AlgoName(r.AuthAlgo)
	if algo == "" {
		return "", false
	}
	return potKey(algo, fmt.Sprintf("%x", rr.Salt()), fmt.Sprintf("%x", mac)), true
}
