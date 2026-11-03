package cmd

import (
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/mattn/go-isatty"
	"github.com/spf13/cobra"

	"github.com/runZeroInc/oobscan/pkg/convert"
	"github.com/runZeroInc/oobscan/pkg/output"
)

var (
	convertFormat      string
	convertRedact      bool
	convertQuality     bool
	convertFailOnDirty bool
	convertMapping     string
	convertWorkers     int
)

// convertCmd normalizes a scan-adjacent corpus into the native oobscan NDJSON
// format. It is also where the older `scanaudit` command now lives, as
// --quality: auditing a file and rewriting it are the same read of the same
// records, and running them together means the file that gets audited is the
// file that gets written.
var convertCmd = &cobra.Command{
	Use:   "convert [flags] <input-file> [output-file]",
	Short: "Convert a scan corpus into the native oobscan format, optionally redacting or auditing it.",
	Long: `convert reads a scan corpus and writes it as native oobscan NDJSON.

Input formats (--format):

  oobscan     (default) an existing oobscan NDJSON file. Records are migrated
              to the current emission rules and re-serialized: legacy key
              spellings and check ids are folded onto their canonical form,
              "none"-risk findings move into attemptedChecks, and oversized
              fields are re-capped.
  rzsql       a runZero SQL export -- one JSON object per line holding an asset
			  and its services.
  rzservices  a runZero services export -- one JSON object per line holding a
              single service with its asset denormalized alongside it. These
              rows are not grouped, or even sorted, by asset, so the whole
              input is grouped in memory (roughly 3x the input size). rzsql and
              oobscan both stream.

The runZero formats are converted losslessly first: every service_data key and
every asset attribute is carried through verbatim into the per-service and host
attribute bags, including the recog fingerprint blobs and the underscore-
prefixed bookkeeping keys. The oobscan-native view -- identity, findings and
RAKP rows -- is then derived on top of the preserved data, so nothing is traded
away for the derivation. Captured RAKP-2 material is decomposed back into its
session ids, nonces and GUID, so a converted runZero corpus is directly usable
with "oobscan hashdump" and "oobscan hashcrack".

The derivation also retroactively projects oobscan's device-specific exposures
onto the preserved data, so a converted corpus and a live scan score the same
fleet and can be compared with "oobscan report": the Supermicro/ATEN SMCRAKP
fixed-key bypass and predictable session ids (from the captured RAKP hashes and
managed session ids), the HPE iLO 2/3/4 IPMI RAKP-none auth bypass and the
iLO <=5 mpSSH pre-auth overflow (from the iLO generation and mpSSH banner), the
version-gated iLO firmware CVEs, and the OpenBMC phosphor-net-ipmid default
userKey bypass (from an OpenBMC fingerprint on an IPMI 2.0 channel). Each such
finding names the observation it was derived from and is marked as a
generation/fingerprint projection rather than a live confirmation.

Both the input and the output are gzipped transparently when the path ends in
.gz. The output file is optional: "-" or omitting it writes NDJSON to stdout
(the log then goes to stderr). With --quality and no output file, nothing is
written -- the run is an audit only.

	--redact    prepare a corpus for sharing review. Addresses are renumbered in
              first-seen order (internal from 10.0.0.0, external from
              224.0.0.0), MACs keep their OUI and zero the last two octets,
              banners and other free-text captures are replaced with a
              placeholder, names become host-N.invalid, and fingerprints, GUIDs
              and serials become redacted-N. Every rewrite is a stable mapping,
              so hosts that shared a key or a name still share its stand-in and
              cross-host analysis survives. Credential and RAKP hash material
			  is dropped outright. The post-auth captures are walked too.
			  Review the result before distribution; retained metadata may
			  still be sensitive or identify a small population.
  --quality   run the data-hygiene, coverage and proof-completeness audit over
              the records as they were read (before any redaction) and report:
              the emitted-check histogram, checks that never fired, findings
              with mangled proof, critical/high findings with no proof at all,
              uncollapsed duplicate clusters, and crypto material reused across
              hosts. This was the "scanaudit" command.

Exit codes:
  0  converted (and, with --quality, no issues found or --fail-on-dirty unset)
  2  --quality found issues and --fail-on-dirty was set

Examples:
  oobscan convert results.jsonl shareable.jsonl.gz --redact
  oobscan convert --format rzservices services.jsonl internal.jsonl
  oobscan convert --quality --fail-on-dirty results.jsonl`,
	Args: cobra.RangeArgs(1, 2),
	RunE: runConvert,
}

func init() {
	f := convertCmd.Flags()
	f.StringVar(&convertFormat, "format", string(convert.FormatOOBScan),
		"input format ("+convert.FormatList()+")")
	f.BoolVar(&convertRedact, "redact", false,
		"renumber addresses and remove known identifying and credential values; review the result before sharing")
	f.BoolVar(&convertQuality, "quality", false,
		"run the data-hygiene, coverage and proof-completeness audit over the input")
	f.BoolVar(&convertFailOnDirty, "fail-on-dirty", false,
		"exit 2 when --quality finds issues")
	f.StringVar(&convertMapping, "redact-mapping", "",
		"write the --redact address mapping to this file (it reverses the redaction: keep it private)")
	f.IntVarP(&convertWorkers, "workers", "w", 0,
		"parallel transform workers for redaction / projection (0 = number of CPUs; 1 = serial)")
	rootCmd.AddCommand(convertCmd)
}

func runConvert(cmd *cobra.Command, args []string) error {
	format, err := convert.ParseFormat(convertFormat)
	if err != nil {
		return err
	}
	opts := convert.Options{
		Format:  format,
		Input:   args[0],
		Redact:  convertRedact,
		Quality: convertQuality,
		Workers: convertWorkers,
	}
	switch {
	case len(args) > 1:
		opts.Output = args[1]
	case convertQuality:
		// A --quality run with no output is an audit-only pass: write nothing.
	default:
		// No output file given: behave like a filter and write NDJSON to stdout.
		opts.Output = "-"
	}

	// The shared logger writes INFO to stdout, which is also where an output of
	// "-" sends the NDJSON. Move the whole log to stderr in that case so a piped
	// conversion never has a log line spliced into the record stream.
	if opts.Output == "-" {
		noColor := rootNoColor || os.Getenv("NO_COLOR") != "" || !isatty.IsTerminal(os.Stderr.Fd())
		output.SetDefault(output.NewLogger(os.Stderr, os.Stderr, noColor, rootVerbose))
	}
	lg := log()

	if convertMapping != "" && !opts.Redact {
		// Worded to start with a word, not a flag: the logger capitalizes the
		// first letter of a message and would render "--Redact-mapping".
		return fmt.Errorf("the --redact-mapping file is only produced by a redacting run: add --redact")
	}

	prog := newStreamProgress("Converting", opts.Input)
	opts.Progress = prog.tick

	st, err := convert.Run(opts)
	prog.finish()
	if err != nil {
		return err
	}

	reportConvertStats(st, opts)
	if st.Quality != nil {
		reportQuality(st.Quality)
		if st.Quality.Dirty() && convertFailOnDirty {
			os.Exit(2)
		}
	}
	if convertMapping != "" {
		if err := writeRedactionMapping(convertMapping, st); err != nil {
			return err
		}
		lg.Warnf("Redaction mapping written to %s -- it reverses the redaction, keep it private", convertMapping)
	}
	return nil
}

// reportConvertStats summarizes what the conversion read and wrote.
func reportConvertStats(st *convert.Stats, opts convert.Options) {
	lg := log()
	fields := []string{"format", string(st.Format), "read", strconv.Itoa(st.Read)}
	if st.Grouped > 0 {
		fields = append(fields, "assets", strconv.Itoa(st.Grouped))
	}
	if opts.Output != "" {
		fields = append(fields, "written", strconv.Itoa(st.Written), "output", opts.Output)
	}
	lg.Info("Converted", fields...)

	if st.Skipped > 0 {
		lg.Warnf("Skipped %d malformed line(s) in %s", st.Skipped, opts.Input)
	}
	if st.Truncated {
		lg.Warnf("%s is truncated -- the records read before the cut are still complete", opts.Input)
	}
	if r := st.Redaction; r != nil {
		lg.Info("Redacted",
			"internal_addrs", strconv.Itoa(r.InternalAddrs),
			"external_addrs", strconv.Itoa(r.ExternalAddrs),
			"macs", strconv.Itoa(r.MACs),
			"names", strconv.Itoa(r.Names),
			"identifiers", strconv.Itoa(r.Tokens),
			"values_dropped", strconv.Itoa(r.Dropped))
	}
}

// reportQuality renders the audit.
func reportQuality(q *convert.QualityReport) {
	lg := log()
	lg.Infof("Quality audit: %d records", q.Records)

	lg.Info("Check histogram (top 40)")
	for i, row := range q.SortedHistogram() {
		if i >= 40 {
			break
		}
		lg.Info("Check hit", "check", row.Check, "count", strconv.Itoa(row.Count))
	}

	lg.Infof("Dark checks (registered but 0 hits): %d", len(q.Dark))
	for _, c := range q.Dark {
		lg.Info("Dark check", "check", c)
	}

	reportIssue := func(sev output.Severity, title string, m map[string][]string) {
		if len(m) == 0 {
			return
		}
		keys := make([]string, 0, len(m))
		for k := range m {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		lg.Emitf(sev, "%s: %d field(s) affected", title, len(keys))
		for _, k := range keys {
			lg.Emit(sev, "Affected field", "field", k, "example_hosts", strings.Join(m[k], ","))
		}
	}
	reportIssue(output.SevHigh, "Null byte in proof (\\u0000)", q.NullByte)
	reportIssue(output.SevHigh, "U+FFFD replacement char in proof", q.ReplacementChar)
	reportIssue(output.SevHigh, "Invalid UTF-8 in proof", q.InvalidUTF8)
	reportIssue(output.SevHigh, "High-severity finding without proof field", q.MissingProof)
	reportIssue(output.SevHigh, "Binary body stored as proof text", q.BinaryEvidence)
	reportIssue(output.SevHigh, "Finding contradicts an unreachable-surface claim on the same port", q.Contradiction)
	reportIssue(output.SevHigh, "Post-auth under-reports with no coverage marker", q.SilentPartial)

	if len(q.ConstantEvidence) > 0 {
		lg.Highf("Evidence field that never varied: %d field(s) affected", len(q.ConstantEvidence))
		keys := make([]string, 0, len(q.ConstantEvidence))
		for k := range q.ConstantEvidence {
			keys = append(keys, k)
		}
		sort.SliceStable(keys, func(i, j int) bool {
			if q.ConstantEvidence[keys[i]] != q.ConstantEvidence[keys[j]] {
				return q.ConstantEvidence[keys[i]] > q.ConstantEvidence[keys[j]]
			}
			return keys[i] < keys[j]
		})
		for _, k := range keys {
			lg.High("Constant evidence", "field", k, "findings", strconv.Itoa(q.ConstantEvidence[k]))
		}
	}

	if len(q.DuplicateURL) > 0 {
		lg.Highf("Uncollapsed http.exposure duplicates: %d cluster(s)", len(q.DuplicateURL))
		keys := make([]string, 0, len(q.DuplicateURL))
		for k := range q.DuplicateURL {
			keys = append(keys, k)
		}
		sort.SliceStable(keys, func(i, j int) bool {
			return q.DuplicateURL[keys[i]] > q.DuplicateURL[keys[j]]
		})
		for _, k := range keys {
			lg.High("Duplicate cluster", "signature", k, "extra_findings", strconv.Itoa(q.DuplicateURL[k]))
		}
	}

	reportKeyReuse := func(title string, m map[string][]string) {
		if len(m) == 0 {
			return
		}
		keys := make([]string, 0, len(m))
		for k := range m {
			keys = append(keys, k)
		}
		sort.SliceStable(keys, func(i, j int) bool {
			if len(m[keys[i]]) != len(m[keys[j]]) {
				return len(m[keys[i]]) > len(m[keys[j]])
			}
			return keys[i] < keys[j]
		})
		lg.Infof("%s: %d reused fingerprint(s) (triage only; reuse does not prove the private key is publicly known)", title, len(keys))
		for _, k := range keys {
			lg.Info("Reused fingerprint", "fingerprint", k, "example_hosts", strings.Join(m[k], ","))
		}
	}
	reportKeyReuse("Cross-host SSH key reuse", q.ReusedSSHKey)
	reportKeyReuse("Cross-host TLS certificate reuse", q.ReusedTLSCert)

	if !q.Dirty() {
		lg.Info("No data-hygiene issues detected")
	}
}

// writeRedactionMapping persists the address mapping, which is the only way to
// reverse a redaction.
func writeRedactionMapping(path string, st *convert.Stats) error {
	if st.Mapping == nil {
		return fmt.Errorf("no redaction mapping was produced")
	}
	body := strings.Join(st.Mapping, "\n")
	if body != "" {
		body += "\n"
	}
	return os.WriteFile(path, []byte(body), 0o600)
}
