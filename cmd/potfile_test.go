package cmd

import (
	"os"
	"path/filepath"
	"testing"
)

// A real RAKP-2 salt is 58+ bytes; these fixtures use a representative length so
// the length-based salt/mac disambiguation is exercised.
const (
	testSalt   = "a4a3a2a00007fb0f000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f1405414d494e" // 62 bytes
	testSHA1   = "0123456789abcdef0123456789abcdef01234567"                                                                                     // 20 bytes
	testMD5    = "0123456789abcdef0123456789abcdef"                                                                                             // 16 bytes
	testSHA256 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"                                                             // 32 bytes
)

func TestParsePotLine(t *testing.T) {
	cases := []struct {
		name, line            string
		algo, salt, mac, pass string
		ok                    bool
	}{
		{
			name: "hashcat 7300 sha1 (salt:mac:pass)",
			line: testSalt + ":" + testSHA1 + ":ADMIN",
			algo: "sha1", salt: testSalt, mac: testSHA1, pass: "ADMIN", ok: true,
		},
		{
			name: "hashcat 7350 md5 (mac:salt:pass, swapped)",
			line: testMD5 + ":" + testSalt + ":password1",
			algo: "md5", salt: testSalt, mac: testMD5, pass: "password1", ok: true,
		},
		{
			name: "sha256 salt:mac form",
			line: testSalt + ":" + testSHA256 + ":s3cret",
			algo: "sha256", salt: testSalt, mac: testSHA256, pass: "s3cret", ok: true,
		},
		{
			name: "john $rakp$ sha1",
			line: "$rakp$" + testSalt + "$" + testSHA1 + ":calvin",
			algo: "sha1", salt: testSalt, mac: testSHA1, pass: "calvin", ok: true,
		},
		{
			name: "john $rakp-md5$ (algo from mac length, not tag)",
			line: "$rakp-md5$" + testSalt + "$" + testMD5 + ":root",
			algo: "md5", salt: testSalt, mac: testMD5, pass: "root", ok: true,
		},
		{
			name: "john $rakp$ carrying an md5 mac (oobscan emits $rakp$ for all algos)",
			line: "$rakp$" + testSalt + "$" + testMD5 + ":root",
			algo: "md5", salt: testSalt, mac: testMD5, pass: "root", ok: true,
		},
		{
			name: "native oobscan algo:salt:mac:pass",
			line: "sha1:" + testSalt + ":" + testSHA1 + ":ADMIN",
			algo: "sha1", salt: testSalt, mac: testSHA1, pass: "ADMIN", ok: true,
		},
		{
			name: "password containing a colon is preserved",
			line: testSalt + ":" + testSHA1 + ":pa:ss:word",
			algo: "sha1", salt: testSalt, mac: testSHA1, pass: "pa:ss:word", ok: true,
		},
		{
			name: "uppercase hex is lower-cased to match the loaded key",
			line: "$rakp$" + testSalt + "$0123456789ABCDEF0123456789ABCDEF01234567:x",
			algo: "sha1", salt: testSalt, mac: testSHA1, pass: "x", ok: true,
		},
		{name: "comment line", line: "# a comment", ok: false},
		{name: "blank line", line: "   ", ok: false},
		{name: "garbage", line: "not a hash at all", ok: false},
		{name: "wrong mac length", line: testSalt + ":abcd:pw", ok: false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			algo, salt, mac, pass, ok := parsePotLine(c.line)
			if ok != c.ok {
				t.Fatalf("ok = %v, want %v", ok, c.ok)
			}
			if !ok {
				return
			}
			if algo != c.algo || salt != c.salt || mac != c.mac || pass != c.pass {
				t.Errorf("got {%q %q %q %q}, want {%q %q %q %q}",
					algo, salt, mac, pass, c.algo, c.salt, c.mac, c.pass)
			}
		})
	}
}

// TestImportPotfilesMergesAndDedupes checks that importing populates the pot map
// and the potfile with native-format lines, skips duplicates, and that a second
// import of the same data adds nothing.
func TestImportPotfilesMergesAndDedupes(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "hashcat.potfile")
	body := "" +
		testSalt + ":" + testSHA1 + ":ADMIN\n" + // hashcat 7300
		testMD5 + ":" + testSalt + ":password1\n" + // hashcat 7350
		"$rakp$" + testSalt + "$" + testSHA256 + ":s3cret\n" + // john sha256
		"# comment\n\ngarbage line\n"
	if err := os.WriteFile(src, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	potPath := filepath.Join(dir, "oobscan.pot")
	pot := map[string]string{}

	added, parsed, unparsed, err := importPotfiles([]string{src}, potPath, pot)
	if err != nil {
		t.Fatalf("importPotfiles: %v", err)
	}
	if added != 3 || parsed != 3 {
		t.Errorf("added=%d parsed=%d, want 3/3", added, parsed)
	}
	if unparsed != 1 {
		t.Errorf("unparsed = %d, want 1 (the garbage line)", unparsed)
	}
	if pot[potKey("sha1", testSalt, testSHA1)] != "ADMIN" ||
		pot[potKey("md5", testSalt, testMD5)] != "password1" ||
		pot[potKey("sha256", testSalt, testSHA256)] != "s3cret" {
		t.Errorf("pot map not populated as expected: %v", pot)
	}

	// The written potfile must be loadable by the native loader and agree.
	reloaded := loadPotfile(potPath)
	if len(reloaded) != 3 {
		t.Errorf("reloaded potfile has %d entries, want 3", len(reloaded))
	}
	if reloaded[potKey("md5", testSalt, testMD5)] != "password1" {
		t.Errorf("reloaded md5 crack = %q, want password1", reloaded[potKey("md5", testSalt, testMD5)])
	}

	// Re-importing the same file adds nothing new.
	added2, _, _, err := importPotfiles([]string{src}, potPath, pot)
	if err != nil {
		t.Fatal(err)
	}
	if added2 != 0 {
		t.Errorf("re-import added %d, want 0 (all duplicates)", added2)
	}
}
