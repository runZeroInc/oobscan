package cmd

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/runZeroInc/oobscan/pkg/explain"
	"github.com/runZeroInc/oobscan/pkg/output"
)

var (
	explainMatch []string
	explainOut   string
)

var explainCmd = &cobra.Command{
	Use:   "explain [flags] <scan.jsonl>...",
	Short: "Generate a detailed guide from scan results in markdown format.",
	Long: `explain reads one or more oobscan scan NDJSON files and writes a detailed
markdown guide describing how to validate every identified finding against the
specific host on which it was observed.

For each finding the guide shows:
  * What was found and why it matters
  * The exact ipmitool / curl / snmpwalk / hashcat command to reproduce it
  * Additional exploitation steps where applicable

Use --match to scope the output to findings whose summary line contains a given
substring (case-insensitive). The match string is compared against the full
finding description including host, check name, risk level, port, protocol,
field keys and values -- you can pass an IP address, a check name fragment, a
risk level, or any field value.  --match may be repeated; a finding matches if
ANY of the provided strings is found in its summary line.

Examples:
  oobscan explain results.jsonl
  oobscan explain results.jsonl --match 192.168.0.1
  oobscan explain results.jsonl --match cipherZero --match authNone
  oobscan explain results.jsonl --match critical --out guide.md
  oobscan explain oob1.jsonl oob2.jsonl --match rakpHash`,
	Args: cobra.MinimumNArgs(1),
	RunE: runExplain,
}

func init() {
	rootCmd.AddCommand(explainCmd)
	f := explainCmd.Flags()
	f.StringArrayVar(&explainMatch, "match", nil,
		"only explain findings whose summary line contains this substring (repeatable, case-insensitive; matches on host, check, risk, port, protocol, field values, CVE IDs)")
	f.StringVarP(&explainOut, "out", "o", "",
		"write markdown to this file instead of stdout")
}

func runExplain(cmd *cobra.Command, args []string) error {

	var needles []string
	for _, m := range explainMatch {
		if m != "" {
			needles = append(needles, strings.ToLower(m))
		}
	}

	out := cmd.OutOrStdout()
	if explainOut != "" {
		fh, err := os.Create(explainOut)
		if err != nil {
			return fmt.Errorf("open --out: %w", err)
		}
		defer fh.Close()
		out = fh
	}
	bw := bufio.NewWriter(out)
	defer bw.Flush()

	total := 0
	written := 0

	processRecord := func(line []byte) {
		var r output.Result
		if err := json.Unmarshal(line, &r); err != nil {
			return
		}
		if len(r.Findings) == 0 {
			return
		}
		for _, f := range r.Findings {
			if f.Risk == "none" {
				continue
			}
			total++
			matchLine := explain.MatchLine(r.Host, f)
			if !matchesAny(matchLine, needles) {
				continue
			}
			section := explain.Section(r.Host, &r, f)
			if section == "" {
				continue
			}
			written++
			fmt.Fprintln(bw, section)
		}
	}

	for _, path := range args {
		fh, err := os.Open(path)
		if err != nil {
			return fmt.Errorf("open %s: %w", path, err)
		}

		rdr := bufio.NewReaderSize(fh, 1<<20)
		var readErr error
		for {
			line, rerr := rdr.ReadBytes('\n')
			if t := bytes.TrimSpace(line); len(t) > 0 {
				processRecord(t)
			}
			if rerr != nil {
				if rerr != io.EOF {
					readErr = rerr
				}
				break
			}
		}
		fh.Close()
		if readErr != nil {
			return fmt.Errorf("read %s: %w", path, readErr)
		}
	}

	if written == 0 {
		if total == 0 {
			return fmt.Errorf("no non-trivial findings found in the given scan file(s)")
		}
		if len(needles) > 0 {
			return fmt.Errorf("no findings matched --match filter %q (checked %d findings)", strings.Join(explainMatch, ", "), total)
		}
	}

	if written > 0 && explainOut != "" {
		log().Infof("Wrote %d finding explanation(s) to %s", written, explainOut)
	}

	return nil
}

func matchesAny(line string, needles []string) bool {
	if len(needles) == 0 {
		return true
	}
	lower := strings.ToLower(line)
	for _, n := range needles {
		if strings.Contains(lower, n) {
			return true
		}
	}
	return false
}
