package cmd

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/runZeroInc/oobscan/pkg/hashcrack"
)

func defaultPotfilePath() string {
	return filepath.Join(userCacheDir(), "oobscan", "oobscan.pot")
}

func resolvePotfilePath(explicit string) string {
	if strings.TrimSpace(explicit) != "" {
		return explicit
	}
	return defaultPotfilePath()
}

func ensureParentDir(path string) error {
	d := filepath.Dir(path)
	if d == "." || d == "" {
		return nil
	}
	return os.MkdirAll(d, 0o755)
}

func loadPotfile(path string) map[string]string {
	m := map[string]string{}
	f, err := os.Open(path)
	if err != nil {
		return m
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for sc.Scan() {
		parts := strings.SplitN(sc.Text(), ":", 4)
		if len(parts) != 4 {
			continue
		}
		m[parts[0]+":"+parts[1]+":"+parts[2]] = parts[3]
	}
	if err := sc.Err(); err != nil {
		log().Warnf("Potfile %s: %v", path, err)
	}
	return m
}

func potKey(algo, salt, mac string) string { return algo + ":" + salt + ":" + mac }

func parsePotLine(line string) (algo, salt, mac, pass string, ok bool) {
	line = strings.TrimRight(line, "\r\n")
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return "", "", "", "", false
	}
	if strings.HasPrefix(line, "$") {
		return parseJohnPot(line)
	}

	if i := strings.IndexByte(line, ':'); i > 0 {
		if a, isAlgo := hashcrack.AlgoFromName(line[:i]); isAlgo {
			p := strings.SplitN(line[i+1:], ":", 3)
			if len(p) == 3 && isHexStr(p[0]) && isHexStr(p[1]) {
				return hashcrack.AlgoName(a), lc(p[0]), lc(p[1]), p[2], true
			}
			return "", "", "", "", false
		}
	}
	return parseHashcatPot(line)
}

func parseHashcatPot(line string) (algo, salt, mac, pass string, ok bool) {
	p := strings.SplitN(line, ":", 3)
	if len(p) != 3 || !isHexStr(p[0]) || !isHexStr(p[1]) {
		return "", "", "", "", false
	}
	f1, f2, pw := p[0], p[1], p[2]
	switch {
	case macAlgo(len(f2)) != "" && len(f1) > len(f2):

		return macAlgo(len(f2)), lc(f1), lc(f2), pw, true
	case macAlgo(len(f1)) != "" && len(f2) > len(f1):

		return macAlgo(len(f1)), lc(f2), lc(f1), pw, true
	}
	return "", "", "", "", false
}

func parseJohnPot(line string) (algo, salt, mac, pass string, ok bool) {
	if !strings.HasPrefix(strings.ToLower(line), "$rakp") {
		return "", "", "", "", false
	}
	body := line[1:]
	_, rest, ok := strings.Cut(body, "$")
	if !ok {
		return "", "", "", "", false
	}
	saltHex, macPass, ok := strings.Cut(rest, "$")
	if !ok {
		return "", "", "", "", false
	}
	macHex, pw, ok := strings.Cut(macPass, ":")
	if !ok || !isHexStr(saltHex) || !isHexStr(macHex) {
		return "", "", "", "", false
	}
	a := macAlgo(len(macHex))
	if a == "" {
		return "", "", "", "", false
	}
	return a, lc(saltHex), lc(macHex), pw, true
}

func importPotfiles(paths []string, potPath string, pot map[string]string) (added, parsed, unparsed int, err error) {
	if err := ensureParentDir(potPath); err != nil {
		return 0, 0, 0, err
	}
	fh, err := os.OpenFile(potPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return 0, 0, 0, err
	}
	defer fh.Close()

	for _, path := range paths {
		f, oerr := os.Open(path)
		if oerr != nil {
			return added, parsed, unparsed, oerr
		}
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
		for sc.Scan() {
			algo, salt, mac, pass, okLine := parsePotLine(sc.Text())
			if !okLine {

				if t := strings.TrimSpace(sc.Text()); t != "" && !strings.HasPrefix(t, "#") {
					unparsed++
				}
				continue
			}
			parsed++
			key := potKey(algo, salt, mac)
			if _, exists := pot[key]; exists {
				continue
			}
			pot[key] = pass
			if _, werr := fmt.Fprintf(fh, "%s:%s:%s:%s\n", algo, salt, mac, pass); werr != nil {
				f.Close()
				return added, parsed, unparsed, werr
			}
			added++
		}
		f.Close()
		if serr := sc.Err(); serr != nil {
			return added, parsed, unparsed, fmt.Errorf("%s: %w", path, serr)
		}
	}
	return added, parsed, unparsed, nil
}

func macAlgo(hexLen int) string {
	switch hexLen {
	case 40:
		return "sha1"
	case 32:
		return "md5"
	case 64:
		return "sha256"
	}
	return ""
}

func isHexStr(s string) bool {
	if s == "" || len(s)%2 != 0 {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}

func lc(s string) string { return strings.ToLower(s) }
