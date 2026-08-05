package cmd

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/runZeroInc/oobscan/pkg/hashcrack"
)

var (
	hashdumpOutput  string
	hashdumpCiphers string
	hashdumpShow    bool
	hashdumpPotfile string
)

var hashdumpCmd = &cobra.Command{
	Use:   "hashdump [flags] <scan.jsonl>...",
	Short: "Write hashcat / John input files from RAKP hashes in scan results.",
	Long: `hashdump reads one or more oobscan scan JSONL files, reconstructs every
captured IPMI RAKP HMAC (auth algorithms 1=SHA1, 2=MD5, 3=SHA256), and writes
them to disk in cracker-ready formats.

	--output NAME    write all files derived from NAME:
						NAME-sha1.7300.hc with "salt:hmac" (hashcat -m 7300),
						NAME-md5.7350.hc with "hmac:salt" (hashcat -m 7350),
						NAME-md5.jtr / NAME-sha1.jtr / NAME-sha256.jtr.
						SHA256 is not supported by hashcat and is reported as skipped.
	--show           lookup loaded hashes in the potfile and print cracked
						user:password rows (potfile-only, no cracking).
	--potfile FILE   potfile path for --show (default: ~/.cache/oobscan/oobscan.pot).
    --ciphers LIST   restrict to a subset (default md5,sha1,sha256).

Examples:
  oobscan hashdump --output rakp results.jsonl
  oobscan hashdump --output sha1-only --ciphers sha1 oob*.json`,
	Args: cobra.MinimumNArgs(1),
	RunE: runHashdump,
}

func runHashdump(cmd *cobra.Command, args []string) error {
	lg := log()
	if hashdumpOutput == "" {
		return fmt.Errorf("specify --output NAME")
	}
	want, unknown := hashcrack.ParseCiphers(csvFields(hashdumpCiphers))
	for _, u := range unknown {
		lg.Warnf("Unknown cipher %q (use md5,sha1,sha256)", u)
	}
	if want == nil {
		return fmt.Errorf("--ciphers must list at least one of md5,sha1,sha256")
	}

	hashes, tally, err := hashcrack.LoadScans(args, want, false)
	if err != nil {
		return err
	}
	lg.Info("Loaded RAKP hashes",
		"total", fmt.Sprintf("%d", len(hashes)),
		"sha1", fmt.Sprintf("%d", tally[hashcrack.AlgoSHA1]),
		"md5", fmt.Sprintf("%d", tally[hashcrack.AlgoMD5]),
		"sha256", fmt.Sprintf("%d", tally[hashcrack.AlgoSHA256]),
		"files", fmt.Sprintf("%d", len(args)))
	if len(hashes) == 0 {
		return fmt.Errorf("no RAKP hashes found in the given scan file(s)")
	}

	sha1HCPath, md5HCPath := hashcatOutputPaths(hashdumpOutput)
	md5JTRPath, sha1JTRPath, sha256JTRPath := johnOutputPaths(hashdumpOutput)

	n7300, err := writeLines(sha1HCPath, hashes, func(h *hashcrack.Hash) (string, bool) {
		if h.Algo != hashcrack.AlgoSHA1 || h.SMCFixedKey {
			return "", false
		}
		return h.SaltHashLine(), true
	})
	if err != nil {
		return err
	}

	n7350, err := writeLines(md5HCPath, hashes, func(h *hashcrack.Hash) (string, bool) {
		if h.Algo != hashcrack.AlgoMD5 || h.SMCFixedKey {
			return "", false
		}

		return fmt.Sprintf("%x:%x", h.MAC, h.Salt), true
	})
	if err != nil {
		return err
	}

	nJTRMD5, err := writeLines(md5JTRPath, hashes, func(h *hashcrack.Hash) (string, bool) {
		if h.Algo != hashcrack.AlgoMD5 || h.SMCFixedKey {
			return "", false
		}
		return h.JohnLine(), true
	})
	if err != nil {
		return err
	}
	nJTRSHA1, err := writeLines(sha1JTRPath, hashes, func(h *hashcrack.Hash) (string, bool) {
		if h.Algo != hashcrack.AlgoSHA1 || h.SMCFixedKey {
			return "", false
		}
		return h.JohnLine(), true
	})
	if err != nil {
		return err
	}
	nJTRSHA256, err := writeLines(sha256JTRPath, hashes, func(h *hashcrack.Hash) (string, bool) {
		if h.Algo != hashcrack.AlgoSHA256 || h.SMCFixedKey {
			return "", false
		}
		return h.JohnLine(), true
	})
	if err != nil {
		return err
	}

	if n7300 > 0 {
		lg.Info("Wrote hashcat file", "path", sha1HCPath, "lines", fmt.Sprintf("%d", n7300), "mode", "7300", "algo", "SHA1")
		lg.Info("Run", "cmd", fmt.Sprintf("hashcat -m 7300 %s -a 0 <wordlist>", sha1HCPath))
	}

	if n7350 > 0 {
		lg.Info("Wrote hashcat file", "path", md5HCPath, "lines", fmt.Sprintf("%d", n7350), "mode", "7350", "algo", "MD5")
		lg.Info("Run", "cmd", fmt.Sprintf("hashcat -m 7350 %s -a 0 <wordlist>", md5HCPath))
	}

	if nJTRMD5 > 0 {
		lg.Info("Wrote John $rakp$ file", "path", md5JTRPath, "lines", fmt.Sprintf("%d", nJTRMD5), "algo", "MD5")
		lg.Info("Run", "cmd", fmt.Sprintf("john --format=RAKP-MD5 %s", md5JTRPath))
	}

	if nJTRSHA1 > 0 {
		lg.Info("Wrote John $rakp$ file", "path", sha1JTRPath, "lines", fmt.Sprintf("%d", nJTRSHA1), "algo", "SHA1")
		lg.Info("Run", "cmd", fmt.Sprintf("john --format=RAKP %s", sha1JTRPath))
	}

	if nJTRSHA256 > 0 {
		lg.Info("Wrote John $rakp$ file", "path", sha256JTRPath, "lines", fmt.Sprintf("%d", nJTRSHA256), "algo", "SHA256")
		lg.Info("Run", "cmd", fmt.Sprintf("john --format=RAKP-SHA256 %s", sha256JTRPath))
	}

	if tally[hashcrack.AlgoSHA256] > 0 {
		lg.Warnf("Hashcat does not support SHA256, omitted %d hashes", tally[hashcrack.AlgoSHA256])
	}

	if hashdumpShow {
		potPath := resolvePotfilePath(hashdumpPotfile)
		pot := loadPotfile(potPath)
		lg.Info("Using oobscan potfile", "path", potPath)

		shown := 0
		for _, h := range hashes {
			if pw, ok := pot[hashcrack.AlgoName(h.Algo)+":"+h.SaltHashLine()]; ok {
				lg.Info("Cracked credential",
					"ip", h.IP,
					"vendor_product", cut(h.Vendor+"/"+h.Product, 24),
					"user", h.Username,
					"pass", pw,
					"algo", hashcrack.AlgoName(h.Algo),
					"source", h.Source)
				shown++
			}
		}
		lg.Infof("Matched %d cracked credential(s) from potfile for %d loaded hash(es)", shown, len(hashes))
	}
	return nil
}

func writeLines(path string, hashes []*hashcrack.Hash, render func(*hashcrack.Hash) (string, bool)) (int, error) {
	f, err := os.Create(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	w := bufio.NewWriter(f)
	n := 0
	for _, h := range hashes {
		line, ok := render(h)
		if !ok {
			continue
		}
		if _, err := fmt.Fprintln(w, line); err != nil {
			return n, err
		}
		n++
	}
	return n, w.Flush()
}

func hashcatOutputPaths(path string) (sha1Path, md5Path string) {
	stem := outputStem(path)
	dir := filepath.Dir(path)
	return filepath.Join(dir, stem+"-sha1.7300.hc"), filepath.Join(dir, stem+"-md5.7350.hc")
}

func johnOutputPaths(path string) (md5Path, sha1Path, sha256Path string) {
	stem := outputStem(path)
	dir := filepath.Dir(path)
	return filepath.Join(dir, stem+"-md5.jtr"), filepath.Join(dir, stem+"-sha1.jtr"), filepath.Join(dir, stem+"-sha256.jtr")
}

func outputStem(path string) string {
	base := filepath.Base(path)
	stem := strings.TrimSuffix(base, filepath.Ext(base))
	if stem == "" {
		stem = base
	}
	return stem
}

func init() {
	hashdumpCmd.Flags().StringVarP(&hashdumpOutput, "output", "o", "", "output base name; writes NAME-sha1.7300.hc, NAME-md5.7350.hc, NAME-md5.jtr, NAME-sha1.jtr, and NAME-sha256.jtr")
	hashdumpCmd.Flags().BoolVar(&hashdumpShow, "show", false, "show cracked credentials for loaded hashes from potfile only")
	hashdumpCmd.Flags().StringVar(&hashdumpPotfile, "potfile", "", "potfile path for --show (default: ~/.cache/oobscan/oobscan.pot)")
	hashdumpCmd.Flags().StringVar(&hashdumpCiphers, "ciphers", "md5,sha1,sha256", "comma-separated cipher subset to include")
	rootCmd.AddCommand(hashdumpCmd)
}
