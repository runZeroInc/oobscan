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

// defaultPotfilePath returns the per-app cache potfile location:
//
//	$HOME/.cache/oobscan/oobscan.pot
func defaultPotfilePath() string {
	return filepath.Join(userCacheDir(), "oobscan", "oobscan.pot")
}

// resolvePotfilePath returns explicit when set, else the default cache path.
func resolvePotfilePath(explicit string) string {
	if strings.TrimSpace(explicit) != "" {
		return explicit
	}
	return defaultPotfilePath()
}

// ensureParentDir creates the parent directory for path when needed.
func ensureParentDir(path string) error {
	d := filepath.Dir(path)
	if d == "." || d == "" {
		return nil
	}
	return os.MkdirAll(d, 0o755)
}

// loadPotfile reads "algo:salt:mac:password" records (password may contain ':').
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

// potKey renders the map key ("algo:salt:mac") used to look a crack up. It is
// exactly the key oobscan builds from a captured hash (AlgoName + SaltHashLine),
// so an imported crack matches a loaded hash byte for byte.
func potKey(algo, salt, mac string) string { return algo + ":" + salt + ":" + mac }

// parsePotLine parses one line of a hashcat, John, or native oobscan potfile
// into its (algo, salt, mac, password) parts, all hex lower-cased. It
// auto-detects the flavor:
//
//   - native oobscan  "algo:salt:mac:password"   (first field is a cipher name)
//   - John            "$rakp$salt$mac:password"   (also $rakp-md5$ / $rakp-sha256$)
//   - hashcat -m 7300 "salt:mac:password"         (RAKP HMAC-SHA1)
//   - hashcat -m 7350 "mac:salt:password"         (RAKP HMAC-MD5, salt/mac swapped)
//
// The algorithm is taken from the HMAC length (40/32/64 hex = SHA1/MD5/SHA256),
// which is unambiguous, and the salt/mac order in the hashcat forms is resolved
// by length too: an RAKP salt is always far longer than any HMAC, so whichever
// hex field is short is the HMAC regardless of which mode wrote the line.
func parsePotLine(line string) (algo, salt, mac, pass string, ok bool) {
	line = strings.TrimRight(line, "\r\n")
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return "", "", "", "", false
	}
	if strings.HasPrefix(line, "$") {
		return parseJohnPot(line)
	}
	// Native oobscan: the first field is a cipher name (md5/sha1/sha256).
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

// parseHashcatPot parses a "hex:hex:password" hashcat line, resolving which hex
// field is the salt and which the HMAC by length.
func parseHashcatPot(line string) (algo, salt, mac, pass string, ok bool) {
	p := strings.SplitN(line, ":", 3)
	if len(p) != 3 || !isHexStr(p[0]) || !isHexStr(p[1]) {
		return "", "", "", "", false
	}
	f1, f2, pw := p[0], p[1], p[2]
	switch {
	case macAlgo(len(f2)) != "" && len(f1) > len(f2):
		// salt:mac (hashcat 7300 SHA1, and the SHA256 salt:mac form).
		return macAlgo(len(f2)), lc(f1), lc(f2), pw, true
	case macAlgo(len(f1)) != "" && len(f2) > len(f1):
		// mac:salt (hashcat 7350 MD5).
		return macAlgo(len(f1)), lc(f2), lc(f1), pw, true
	}
	return "", "", "", "", false
}

// parseJohnPot parses a "$rakp[...]$salt$mac:password" John line.
func parseJohnPot(line string) (algo, salt, mac, pass string, ok bool) {
	if !strings.HasPrefix(strings.ToLower(line), "$rakp") {
		return "", "", "", "", false
	}
	body := line[1:] // drop the leading '$'
	_, rest, ok := strings.Cut(body, "$")
	if !ok { // rest = salt$mac:password
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

// importPotfiles merges cracked passwords from external hashcat/John potfiles
// into potPath and the in-memory pot map, appending only entries not already
// present. It returns the number of new records added, the number of lines that
// parsed as a RAKP crack, and the number that did not parse.
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
				// Blank and comment lines are not parse failures; anything else
				// non-empty that did not yield a crack is counted so a wholly
				// wrong --import-pot file is visible rather than silently empty.
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

// macAlgo maps an HMAC hex length to its cipher name (40=sha1, 32=md5,
// 64=sha256); "" for anything else.
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

// isHexStr reports whether s is a non-empty, even-length hex string.
func isHexStr(s string) bool {
	if s == "" || len(s)%2 != 0 {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}

func lc(s string) string { return strings.ToLower(s) }
