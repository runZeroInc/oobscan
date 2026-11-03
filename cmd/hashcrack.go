package cmd

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/spf13/cobra"

	"github.com/runZeroInc/oobscan/pkg/hashcrack"
)

var (
	hashcrackCiphers     string
	hashcrackWordlists   []string
	hashcrackPatterns    []string
	hashcrackWorkers     int
	hashcrackOut         string
	hashcrackPotfile     string
	hashcrackLimit       int
	hashcrackBatch       int
	hashcrackDeep        bool
	hashcrackNoDefault   bool
	hashcrackNoScanCreds bool
	hashcrackAll         bool
	hashcrackC1          string
	hashcrackC2          string
	hashcrackC3          string
	hashcrackC4          string
	hashcrackMatch       string
	hashcrackShow        bool
	hashcrackImportPots  []string
)

// hashcrackCmd cracks the RAKP HMAC hashes captured in scan JSONL, natively for
// all three algorithms (SHA1/MD5/SHA256).
var hashcrackCmd = &cobra.Command{
	Use:   "hashcrack [flags] <scan.jsonl>...",
	Short: "Audit captured IPMI RAKP hashes for weak passwords offline.",
	Long: `hashcrack audits IPMI RAKP HMAC hashes from authorized scan results for
recoverable passwords. It supports HMAC-SHA1, HMAC-MD5, and HMAC-SHA256 and uses
all CPU cores. This operation does not contact the scanned devices.

Use only authentication material within the assessment scope. Recovered
passwords, terminal output, and potfiles are sensitive evidence: restrict access
and retention, and rotate exposed credentials through an approved process.

Candidate sources, tried in order:
  1. common BMC defaults + light variations (always on; --no-defaults to skip,
     --deep to also try year/digit/symbol affixes)
  2. cleartext user/pass observed in the scans -- RAKP usernames, cracked
     passwords, default-login hits, enumerated accounts -- plus every password
     already cracked in the potfile (always on when present; --no-scan-creds to
     skip; --deep also permutes them)
  3. --wordlist FILE   dictionary file (repeatable)
  4. --pattern MASK    hashcat/John mask, e.g. ?d?d?d?d?d?d?d?d (repeatable)

Use --ciphers to scope the algorithms: default md5,sha1,sha256, or e.g.
--ciphers md5,sha256 when hashcat / an older John handles the SHA1 subset.

Cracked passwords are stored in a potfile and reused to skip already-solved
hashes on the next run. Two flags work on the potfile alone (no scan file
needed):

  --show              print every cracked hash in the potfile. Given scan
                      file(s) as well, it instead prints the cracked
                      credentials for those hosts (with host / vendor / user).
  --import-pot FILE   merge cracks from an external hashcat or John potfile
                      (repeatable). The flavor is auto-detected per line --
                      hashcat -m 7300 (SHA1) and -m 7350 (MD5), and John
                      $rakp$ / $rakp-md5$ / $rakp-sha256$ -- so a run offloaded
                      to a GPU can be folded back in and reused here.

Examples:
  oobscan hashcrack results.jsonl
	oobscan hashcrack --wordlist audit-passwords.txt --pattern '?d?d?d?d?d?d' results.jsonl
  oobscan hashcrack --ciphers md5,sha256 --potfile rakp.pot results.jsonl
  oobscan hashcrack --import-pot hashcat.potfile --import-pot john.pot results.jsonl
  oobscan hashcrack --show`,
	Args: cobra.ArbitraryArgs,
	RunE: runHashcrack,
}

type crackOut struct {
	IP       string `json:"ip"`
	Vendor   string `json:"vendor"`
	Product  string `json:"product"`
	Version  string `json:"version"`
	Services string `json:"services"`
	Username string `json:"username"`
	Password string `json:"password"`
	Algo     string `json:"algo"`
	Source   string `json:"source"`
}

func tsNow() string {
	return time.Now().Format("15:04:05")
}

func runHashcrack(cmd *cobra.Command, args []string) error {
	lg := log()
	logf := func(format string, a ...any) {
		lg.Info(strings.TrimRight(fmt.Sprintf(format, a...), "\n"))
	}
	warnf := func(format string, a ...any) {
		lg.Warn(strings.TrimRight(fmt.Sprintf(format, a...), "\n"))
	}

	// Resolve and load the potfile up front: --import-pot writes into it, and
	// both --show and resume read from it.
	hashcrackPotfile = resolvePotfilePath(hashcrackPotfile)
	pot := loadPotfile(hashcrackPotfile)

	// Import external hashcat/John pot files before anything else, so imported
	// cracks are immediately available to --show and to resume-skip.
	if len(hashcrackImportPots) > 0 {
		added, parsed, unparsed, ierr := importPotfiles(hashcrackImportPots, hashcrackPotfile, pot)
		if ierr != nil {
			return fmt.Errorf("import potfile: %w", ierr)
		}
		lg.Info("Imported cracked hashes",
			"new", strconv.Itoa(added),
			"parsed", strconv.Itoa(parsed),
			"unparsed", strconv.Itoa(unparsed),
			"potfile", hashcrackPotfile)
	}

	// Potfile-only modes need no scan files: --show dumps every cracked hash,
	// and a bare --import-pot just merges and exits.
	if len(args) == 0 {
		switch {
		case hashcrackShow:
			showEntirePot(pot)
			return nil
		case len(hashcrackImportPots) > 0:
			return nil
		default:
			return fmt.Errorf("provide scan file(s) to crack, or use --show / --import-pot to work on the potfile alone")
		}
	}

	want, unknown := hashcrack.ParseCiphers(csvFields(hashcrackCiphers))
	for _, u := range unknown {
		warnf("Unknown cipher %q (use md5,sha1,sha256)", u)
	}
	if want == nil {
		return fmt.Errorf("--ciphers must list at least one of md5,sha1,sha256")
	}
	if hashcrackWorkers < 1 {
		hashcrackWorkers = runtime.NumCPU()
	}
	custom := map[byte]string{}
	for k, v := range map[byte]string{'1': hashcrackC1, '2': hashcrackC2, '3': hashcrackC3, '4': hashcrackC4} {
		if v != "" {
			custom[k] = v
		}
	}

	loadStart := time.Now()
	hashes, tally, err := hashcrack.LoadScans(args, want, !hashcrackAll)
	if err != nil {
		return err
	}
	if hashcrackMatch != "" {
		needle := strings.ToLower(hashcrackMatch)
		filtered := make([]*hashcrack.Hash, 0, len(hashes))
		newTally := hashcrack.Tally{}
		for _, h := range hashes {
			if strings.Contains(strings.ToLower(h.Username), needle) || strings.Contains(strings.ToLower(h.IP), needle) {
				filtered = append(filtered, h)
				newTally[h.Algo]++
			}
		}
		hashes = filtered
		tally = newTally
	}
	loadDur := time.Since(loadStart).Round(time.Millisecond)
	if len(hashes) == 0 {
		if hashcrackMatch != "" {
			return fmt.Errorf("no RAKP hashes matched --match %q", hashcrackMatch)
		}
		return fmt.Errorf("no RAKP hashes found in the given scan file(s)")
	}

	// --show is read-only: display the cracked credentials for the loaded hosts
	// and stop, without opening the potfile for append or running the SMC / pot
	// pre-solve pass (which would mutate the potfile).
	if hashcrackShow {
		showCrackedFromPot(hashes, pot)
		return nil
	}

	// Potfile resume uses the pot loaded (and possibly imported into) up top.
	var potMu sync.Mutex
	var potFH *os.File
	if hashcrackPotfile != "" {
		if err := ensureParentDir(hashcrackPotfile); err != nil {
			return fmt.Errorf("potfile dir: %w", err)
		}
		potFH, _ = os.OpenFile(hashcrackPotfile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
		if potFH != nil {
			defer potFH.Close()
		}
	}

	// Results sink.
	var results []crackOut
	var resMu sync.Mutex
	var outFH *os.File
	var outWriteErr error
	if hashcrackOut != "" {
		outFH, err = os.Create(hashcrackOut)
		if err != nil {
			return fmt.Errorf("open --out: %w", err)
		}
		defer outFH.Close()
	}

	// record captures a newly cracked password (append to potfile + print live).
	record := func(h *hashcrack.Hash, pw string) {
		co := crackOut{IP: h.IP, Vendor: h.Vendor, Product: h.Product, Version: h.Version,
			Services: h.Services, Username: h.Username, Password: pw, Algo: hashcrack.AlgoName(h.Algo), Source: h.Source}
		resMu.Lock()
		results = append(results, co)
		if outFH != nil && outWriteErr == nil {
			b, _ := json.Marshal(co)
			_, outWriteErr = outFH.Write(append(b, '\n'))
		}
		resMu.Unlock()
		if potFH != nil {
			potMu.Lock()
			fmt.Fprintf(potFH, "%s:%x:%x:%s\n", hashcrack.AlgoName(h.Algo), h.Salt, h.MAC, pw)
			potMu.Unlock()
		}
		lg.Critical("Cracked credential",
			"ts", tsNow(),
			"ip", h.IP,
			"vendor_product", cut(h.Vendor+"/"+h.Product, 18),
			"algo", hashcrack.AlgoName(h.Algo),
			"user", h.Username,
			"pass", pw)
	}

	// Apply potfile pre-solves; drop those hashes from the active set.
	active := hashes[:0]
	preSolved := 0
	fixedKeySolved := 0
	uniqUsers := map[string]struct{}{}
	uniqIPs := map[string]struct{}{}
	for _, h := range hashes {
		if h.Username != "" {
			uniqUsers[h.Username] = struct{}{}
		}
		if h.IP != "" {
			uniqIPs[h.IP] = struct{}{}
		}
		if _, ok := pot[hashcrack.AlgoName(h.Algo)+":"+h.SaltHashLine()]; ok {
			preSolved++
			continue
		}
		if h.SMCFixedKey {
			fixedKeySolved++
			record(h, hashcrack.SMCRAKPOEMKeyLabel)
			continue
		}
		active = append(active, h)
	}
	if outWriteErr != nil {
		return fmt.Errorf("write --out: %w", outWriteErr)
	}
	lg.Info("Loaded RAKP hashes",
		"total", strconv.Itoa(len(hashes)),
		"sha1", strconv.Itoa(tally[hashcrack.AlgoSHA1]),
		"md5", strconv.Itoa(tally[hashcrack.AlgoMD5]),
		"sha256", strconv.Itoa(tally[hashcrack.AlgoSHA256]),
		"users", strconv.Itoa(len(uniqUsers)),
		"ips", strconv.Itoa(len(uniqIPs)),
		"files", strconv.Itoa(len(args)),
		"load", loadDur.String(),
		"pot", strconv.Itoa(preSolved),
		"smcrakp_fixed", strconv.Itoa(fixedKeySolved),
		"active", strconv.Itoa(len(active)),
		"workers", strconv.Itoa(hashcrackWorkers))
	if len(active) == 0 {
		lg.Info("No active hashes left after pre-solve filtering")
		printCrackSummary(results, tally, preSolved, 0, 0, 0)
		return nil
	}

	validPatterns := make([]string, 0, len(hashcrackPatterns))
	for _, p := range hashcrackPatterns {
		_, perr := hashcrack.ParseMask(p, custom)
		if perr != nil {
			warnf("%s", perr)
			continue
		}
		validPatterns = append(validPatterns, p)
	}
	for _, wl := range hashcrackWordlists {
		lg.Info("Proceeding with wordlist", "path", wl)
	}

	// Harvest cleartext user/pass observed in the scans (RAKP usernames, cracked
	// passwords, default-login hits, enumerated accounts) plus every password
	// already cracked in the potfile, and reuse them as always-on candidates. In
	// --deep they also seed permutations. --no-scan-creds opts out.
	var extraSeeds []string
	if !hashcrackNoScanCreds {
		seedSet := map[string]struct{}{}
		addSeed := func(v string) {
			v = strings.TrimSpace(v)
			if v == "" || v == hashcrack.SMCRAKPOEMKeyLabel {
				return
			}
			if _, dup := seedSet[v]; dup {
				return
			}
			seedSet[v] = struct{}{}
			extraSeeds = append(extraSeeds, v)
		}
		harvested, herr := hashcrack.HarvestSeeds(args)
		if herr != nil {
			warnf("harvest scan credentials: %s", herr)
		}
		for _, s := range harvested {
			addSeed(s)
		}
		scanSeeds := len(extraSeeds)
		// Cracked passwords already in the potfile: a password recovered on any
		// prior run is worth trying against every remaining host+account.
		for _, pw := range pot {
			addSeed(pw)
		}
		if len(extraSeeds) > 0 {
			lg.Info("Harvested credentials as candidates",
				"scan", strconv.Itoa(scanSeeds),
				"potfile", strconv.Itoa(len(extraSeeds)-scanSeeds),
				"total", strconv.Itoa(len(extraSeeds)),
				"deep_permute", strconv.FormatBool(hashcrackDeep))
		}
	}

	// Candidate producer -> batched channel.
	stop := make(chan struct{})
	rawCands := make(chan []string, 64)
	cands := make(chan []string, 64)
	var sampleMu sync.RWMutex
	sampleA := ""
	sampleB := ""
	go hashcrack.Produce(rawCands, stop, hashcrack.Options{
		Wordlists:       hashcrackWordlists,
		Patterns:        validPatterns,
		Custom:          custom,
		ExtraSeeds:      extraSeeds,
		BatchSize:       hashcrackBatch,
		Limit:           hashcrackLimit,
		IncludeDefaults: !hashcrackNoDefault,
		Deep:            hashcrackDeep,
		Warn:            func(msg string) { warnf("%s", msg) },
		Info:            func(msg string) { logf("%s", formatPatternInfo(msg)) },
	})
	go func() {
		defer close(cands)
		for batch := range rawCands {
			if len(batch) > 0 {
				sampleMu.Lock()
				sampleA = batch[0]
				sampleB = batch[len(batch)-1]
				sampleMu.Unlock()
			}
			cands <- batch
		}
	}()

	// Progress ticker + on-demand status (press Enter in TTY mode).
	start := time.Now()
	stats := &hashcrack.CrackStats{}
	doneCh := make(chan struct{})
	enterCh := make(chan struct{}, 1)
	stdinIsTTY := false
	if fi, statErr := os.Stdin.Stat(); statErr == nil {
		stdinIsTTY = (fi.Mode() & os.ModeCharDevice) != 0
	}
	if stdinIsTTY {
		go func() {
			r := bufio.NewReader(os.Stdin)
			for {
				if _, e := r.ReadString('\n'); e != nil {
					return
				}
				select {
				case enterCh <- struct{}{}:
				default:
				}
			}
		}()
	}
	candidateCap := hashcrack.EstimateCandidateCap(hashcrack.Options{
		Wordlists:       hashcrackWordlists,
		Patterns:        validPatterns,
		Custom:          custom,
		Limit:           hashcrackLimit,
		IncludeDefaults: !hashcrackNoDefault,
		Deep:            hashcrackDeep,
		Warn:            func(msg string) { warnf("%s", msg) },
	})
	hmacCap := int64(-1)
	if candidateCap > 0 {
		if candidateCap > (1<<63-1)/int64(len(active)) {
			hmacCap = -1
		} else {
			hmacCap = candidateCap * int64(len(active))
		}
	}
	go func() {
		t := time.NewTicker(15 * time.Second)
		defer t.Stop()
		lastAt := start
		lastHmac := int64(0)
		printStatus := func(_ bool) {
			now := time.Now()
			elapsed := now.Sub(start)
			if elapsed <= 0 {
				elapsed = time.Millisecond
			}
			tried := stats.HMAC.Load()
			cand := stats.Candidates.Load()
			newSolved := stats.Cracked.Load()
			totalSolved := int64(preSolved) + newSolved
			avgMh := float64(tried) / elapsed.Seconds() / 1e6
			deltaT := now.Sub(lastAt)
			instMh := 0.0
			if deltaT > 0 {
				instMh = float64(tried-lastHmac) / deltaT.Seconds() / 1e6
			}
			lastAt = now
			lastHmac = tried
			etaClock := "n/a"
			pct := 0.0
			if hmacCap > 0 && instMh > 0 {
				left := hmacCap - tried
				pct = (float64(tried) * 100.0) / float64(hmacCap)
				if pct > 100.0 {
					pct = 100.0
				}
				if left <= 0 {
					etaClock = now.Format("2006-01-02 15:04")
				} else {
					etaDur := (time.Duration(float64(left)/(instMh*1e6)) * time.Second).Round(time.Second)
					etaClock = now.Add(etaDur).Format("2006-01-02 15:04")
				}
			}
			sampleMu.RLock()
			exA := sampleA
			exB := sampleB
			sampleMu.RUnlock()
			candPerSec := float64(cand) / elapsed.Seconds()
			lg.Info("Cracking progress",
				"solved", strconv.FormatInt(totalSolved, 10),
				"elapsed", formatJTRElapsed(elapsed.Round(time.Second)),
				"pct", fmt.Sprintf("%.2f%%", pct),
				"new", strconv.FormatInt(newSolved, 10),
				"resumed", strconv.Itoa(preSolved),
				"eta", etaClock,
				"avg", fmt.Sprintf("%.1fMH/s", avgMh),
				"inst", fmt.Sprintf("%.1fMH/s", instMh),
				"cand_rate", formatCandRate(candPerSec),
				"sample", samplePair(exA, exB))
		}
		for {
			select {
			case <-doneCh:
				return
			case <-t.C:
				printStatus(false)
			case <-enterCh:
				printStatus(true)
			}
		}
	}()

	newCrack := func(h *hashcrack.Hash, pw string) { record(h, pw) }
	_, nHmac := hashcrack.CrackWithStats(active, cands, hashcrackWorkers, newCrack, stats)
	close(stop)
	close(doneCh)
	if outWriteErr != nil {
		return fmt.Errorf("write --out: %w", outWriteErr)
	}
	dur := time.Since(start)
	rate := 0.0
	if dur.Seconds() > 0 {
		rate = float64(nHmac) / dur.Seconds() / 1e6
	}

	printCrackSummary(results, tally, preSolved, nHmac, dur, rate)
	return nil
}

func printCrackSummary(results []crackOut, tally hashcrack.Tally, preSolved int, nHmac int64, dur time.Duration, rate float64) {
	newSolved := len(results)
	totalSolved := preSolved + newSolved
	log().Info("Hashcrack summary",
		"solved", fmt.Sprintf("%d/%d", totalSolved, tally.Total()),
		"new", strconv.Itoa(newSolved),
		"resumed", strconv.Itoa(preSolved),
		"hmac", commaDigits(fmt.Sprintf("%d", nHmac)),
		"speed", fmt.Sprintf("%.1fMH/s", rate),
		"elapsed", dur.Round(time.Millisecond).String())
	log().Info("Tip: use hashcrack --show to display cracked results from the potfile")
}

// showEntirePot prints every cracked password in the potfile, independent of
// any scan. Without scan context there is no host/username to attribute, so it
// keys each row on the HMAC (the hash's stable identity) plus its algorithm.
func showEntirePot(pot map[string]string) {
	lg := log()
	keys := make([]string, 0, len(pot))
	for k := range pot {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		// k = "algo:salt:mac"
		algo, rest, _ := strings.Cut(k, ":")
		mac := k
		if _, m, ok := strings.Cut(rest, ":"); ok {
			mac = m
		}
		lg.Info("Cracked hash",
			"algo", algo,
			"mac", cut(mac, 24),
			"pass", pot[k])
	}
	lg.Infof("Potfile %s holds %d cracked hash(es)", hashcrackPotfile, len(pot))
}

func showCrackedFromPot(hashes []*hashcrack.Hash, pot map[string]string) {
	lg := log()
	shown := 0
	for _, h := range hashes {
		pw, ok := pot[hashcrack.AlgoName(h.Algo)+":"+h.SaltHashLine()]
		if !ok {
			// A Supermicro fixed-key hash is cracked-equivalent (the account
			// authenticates against a known firmware key, not a password), so
			// surface it even if it was never written to the potfile.
			if !h.SMCFixedKey {
				continue
			}
			pw = hashcrack.SMCRAKPOEMKeyLabel
		}
		shown++
		lg.Info("Cracked credential",
			"ip", h.IP,
			"vendor_product", cut(h.Vendor+"/"+h.Product, 24),
			"user", h.Username,
			"pass", pw,
			"algo", hashcrack.AlgoName(h.Algo),
			"source", h.Source)
	}
	lg.Infof("Showed %d cracked credential(s) for %d loaded hash(es)", shown, len(hashes))
}

func compactInt(n int64) string {
	if n < 1000 {
		return fmt.Sprintf("%d", n)
	}
	units := []string{"k", "M", "G", "T", "P", "E"}
	v := float64(n)
	for i, u := range units {
		v /= 1000
		if v < 1000 || i == len(units)-1 {
			if v >= 100 {
				return fmt.Sprintf("%.0f%s", v, u)
			}
			return fmt.Sprintf("%.1f%s", v, u)
		}
	}
	return fmt.Sprintf("%d", n)
}

func formatJTRElapsed(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	t := int64(d / time.Second)
	days := t / 86400
	hours := (t % 86400) / 3600
	mins := (t % 3600) / 60
	secs := t % 60
	return fmt.Sprintf("%d:%02d:%02d:%02d", days, hours, mins, secs)
}

func formatCandRate(cps float64) string {
	if cps < 1000 {
		return fmt.Sprintf("%.0fc/s", cps)
	}
	if cps < 1e6 {
		return fmt.Sprintf("%.1fKc/s", cps/1e3)
	}
	if cps < 1e9 {
		return fmt.Sprintf("%.1fMc/s", cps/1e6)
	}
	return fmt.Sprintf("%.1fGc/s", cps/1e9)
}

func samplePair(a, b string) string {
	a = trimSample(a, 14)
	b = trimSample(b, 14)
	if a == "-" && b == "-" {
		return "-"
	}
	if b == "-" || a == b {
		return a
	}
	return a + ".." + b
}

func trimSample(s string, n int) string {
	if s == "" {
		return "-"
	}
	if len(s) <= n {
		return s
	}
	if n <= 3 {
		return s[:n]
	}
	return s[:n-3] + "..."
}

func formatPatternInfo(msg string) string {
	const pfx = "pattern "
	const sep = " keyspace="
	if !strings.HasPrefix(msg, pfx) || !strings.Contains(msg, sep) {
		return msg
	}
	i := strings.LastIndex(msg, sep)
	pat := strings.Trim(strings.TrimPrefix(msg[:i], pfx), "\"")
	ks := strings.TrimSpace(strings.TrimPrefix(msg[i:], sep))
	pretty := commaDigits(ks)
	if n, err := strconv.ParseInt(ks, 10, 64); err == nil {
		pretty = fmt.Sprintf("%s (%s)", compactInt(n), pretty)
	}
	return fmt.Sprintf("Using pattern '%s' with a keyspace of %s guesses", pat, pretty)
}

func commaDigits(s string) string {
	if s == "" {
		return s
	}
	sign := ""
	if s[0] == '-' {
		sign = "-"
		s = s[1:]
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return sign + s
		}
	}
	if len(s) <= 3 {
		return sign + s
	}
	b := strings.Builder{}
	b.Grow(len(s) + len(s)/3)
	for i, r := range s {
		if i > 0 && (len(s)-i)%3 == 0 {
			b.WriteByte(',')
		}
		b.WriteRune(r)
	}
	return sign + b.String()
}

// cut truncates s to n runes with an ellipsis.
func cut(s string, n int) string {
	if len(s) <= n {
		return s
	}
	if n <= 1 {
		return s[:n]
	}
	return s[:n-1] + "..."
}

func init() {
	f := hashcrackCmd.Flags()
	f.StringVar(&hashcrackCiphers, "ciphers", "md5,sha1,sha256", "comma-separated cipher subset to crack")
	f.StringArrayVarP(&hashcrackWordlists, "wordlist", "w", nil, "dictionary file (repeatable)")
	f.StringArrayVarP(&hashcrackPatterns, "pattern", "p", nil, "hashcat/John mask, e.g. ?d?d?d?d?d?d (repeatable)")
	f.IntVarP(&hashcrackWorkers, "workers", "j", runtime.NumCPU(), "worker goroutines")
	f.StringVar(&hashcrackOut, "out", "", "write cracked results as JSONL to this file")
	f.StringVar(&hashcrackPotfile, "potfile", "", "potfile path (default: ~/.cache/oobscan/oobscan.pot); skip already-cracked, append new")
	f.IntVar(&hashcrackLimit, "limit", 0, "stop after N candidates (0 = unlimited; guard for huge masks)")
	f.IntVar(&hashcrackBatch, "batch", 64, "candidates per work batch")
	f.BoolVar(&hashcrackDeep, "deep", false, "deep variations: also try year/digit/symbol affixes on defaults")
	f.BoolVar(&hashcrackNoDefault, "no-defaults", false, "skip the always-on common-defaults pass")
	f.BoolVar(&hashcrackNoScanCreds, "no-scan-creds", false, "skip reusing cleartext user/pass observed in the scans as candidates")
	f.BoolVar(&hashcrackAll, "all", false, "crack every distinct hash (default: one per host+user using cheapest selected cipher)")
	f.StringVarP(&hashcrackC1, "custom1", "1", "", "custom mask charset referenced as ?1")
	f.StringVarP(&hashcrackC2, "custom2", "2", "", "custom mask charset referenced as ?2")
	f.StringVarP(&hashcrackC3, "custom3", "3", "", "custom mask charset referenced as ?3")
	f.StringVarP(&hashcrackC4, "custom4", "4", "", "custom mask charset referenced as ?4")
	f.StringVar(&hashcrackMatch, "match", "", "only crack hashes whose username or IP contains this substring")
	f.BoolVar(&hashcrackShow, "show", false, "show cracked hashes from the potfile (whole potfile with no scan file; matched to hosts when scan file(s) are given) and exit")
	f.StringArrayVar(&hashcrackImportPots, "import-pot", nil, "merge cracks from an external hashcat or John potfile into the potfile (repeatable; flavor auto-detected)")
	rootCmd.AddCommand(hashcrackCmd)
}
