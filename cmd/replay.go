package cmd

import (
	"bufio"
	"fmt"
	"os"

	"github.com/mattn/go-isatty"
	"github.com/spf13/cobra"

	"github.com/runZeroInc/oobscan/pkg/convert"
	"github.com/runZeroInc/oobscan/pkg/output"
)

var (
	replayFormat string
	replayField  string
	replayHosts  string
	replayOut    string
)

// replayCmd re-runs the record-pure detection logic over a stored corpus and prints a
// deterministic table, so a change to that logic can be measured against real data in
// minutes instead of against a fresh scan.
var replayCmd = &cobra.Command{
	Use:   "replay [flags] <corpus>",
	Short: "Re-run the record-pure detection logic over a stored corpus and print a diffable table.",
	Long: `replay streams a corpus and re-evaluates the parts of oobscan's detection
logic that are a pure function of a stored record, then prints one tab-separated,
key-sorted table. Two builds are compared by diffing two tables; nothing here opens a
network connection and nothing is written back to the corpus.

What replays, and what does not:

  replays   the quality-audit rules (the contradiction detector, the proof
            predicates, the silent-partial rule, the binary-body rule, the
            mangled-bytes rules, the duplicate-collapse rule); record migration
            (canonical check ids and field keys, the fold of "none"-risk findings
            into attemptedChecks, the per-field caps); and, for a runZero corpus,
            the finding emitters, which derive their findings from the preserved
            service data on every read.
  does not  anything that needs a socket. On a native oobscan corpus the findings
            were emitted by whichever binary ran the scan and are read back from the
            file, so a change to a probe or to a live check cannot be measured here.
            Measuring that needs a scan.

Output sections, all tab-separated:

  count  <key> <events> <hosts>                  every rule outcome, by key
  field  <check.field> <findings> <hosts> <distinct> <constant>
  value  <check.field> <count> <value>           only with --field
  host   <address>                               only with --hosts

Distinct value counts are exact up to a per-field cap and are reported with a
trailing "+" past it; "constant" means the field held one value on every finding
that carried it.

Comparing two builds:

  git stash && go build -o /tmp/oobscan.base . && git stash pop
  go build -o /tmp/oobscan.head .
  /tmp/oobscan.base replay data/oob80.jsonl > /tmp/base.txt
  /tmp/oobscan.head replay data/oob80.jsonl > /tmp/head.txt
  diff -u /tmp/base.txt /tmp/head.txt

Examples:
  oobscan replay data/oob80.jsonl
  oobscan replay data/oob80.jsonl | grep -E '^count\tcontradiction'
  oobscan replay data/oob80.jsonl --field kvm.usbAnywhere
  oobscan replay data/oob80.jsonl --hosts finding/kvm.usbAnywhere -o /tmp/head.hosts`,
	Args: cobra.ExactArgs(1),
	RunE: runReplay,
}

func init() {
	f := replayCmd.Flags()
	f.StringVar(&replayFormat, "format", "",
		"input format ("+convert.FormatList()+"); empty sniffs it from the first record")
	f.StringVar(&replayField, "field", "",
		"report the most common values of a field slot (\"check.field\") or of every field of a check (\"check\")")
	f.StringVar(&replayHosts, "hosts", "",
		"list the hosts behind one key from the counts table, e.g. finding/kvm.usbAnywhere")
	f.StringVarP(&replayOut, "out", "o", "-",
		"write the table here (\"-\" is stdout)")
	rootCmd.AddCommand(replayCmd)
}

func runReplay(cmd *cobra.Command, args []string) error {
	var (
		format convert.Format
		err    error
	)
	if replayFormat != "" {
		if format, err = convert.ParseFormat(replayFormat); err != nil {
			return err
		}
	}

	// The table is the product of this command, so keep stdout clean: move the log to
	// stderr whenever the table is going to stdout.
	if replayOut == "-" {
		noColor := rootNoColor || os.Getenv("NO_COLOR") != "" || !isatty.IsTerminal(os.Stderr.Fd())
		output.SetDefault(output.NewLogger(os.Stderr, os.Stderr, noColor, rootVerbose))
	}

	prog := newStreamProgress("Replaying", args[0])
	res, err := convert.Replay(convert.ReplayOptions{
		Format:   format,
		Input:    args[0],
		Field:    replayField,
		Hosts:    replayHosts,
		Progress: prog.tick,
	})
	prog.finish()
	if err != nil {
		return err
	}

	out := os.Stdout
	if replayOut != "-" {
		if out, err = os.Create(replayOut); err != nil {
			return err
		}
		defer out.Close()
	}
	bw := bufio.NewWriterSize(out, 1<<16)
	if err := convert.WriteReplay(bw, res); err != nil {
		return err
	}
	if err := bw.Flush(); err != nil {
		return err
	}

	lg := log()
	lg.Info("Replayed",
		"format", string(res.Format),
		"records", fmt.Sprintf("%d", res.Records),
		"keys", fmt.Sprintf("%d", len(res.Rows)),
		"fields", fmt.Sprintf("%d", len(res.Fields)))
	if res.Skipped > 0 {
		lg.Warnf("Skipped %d malformed line(s) in %s", res.Skipped, args[0])
	}
	if res.Truncated {
		lg.Warnf("%s is truncated -- the records read before the cut are still complete", args[0])
	}
	if replayHosts != "" && len(res.Hosts) == 0 {
		lg.Warnf("No host produced the key %q -- check it against the count column of the table", replayHosts)
	}
	return nil
}
