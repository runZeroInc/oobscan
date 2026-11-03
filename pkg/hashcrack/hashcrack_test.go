package hashcrack

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/runZeroInc/oobscan/pkg/ipmi"
)

// makeHash builds a solvable RAKP hash for algo/username/password using the
// authoritative ipmi salt layout, and cross-checks that ipmi's own verifier
// agrees -- so the offline engine and the live probe stay in lock-step.
func makeHash(t *testing.T, gid int, algo byte, user, pw string) *Hash {
	t.Helper()
	guid, _ := hex.DecodeString("9c6b005ece21a701d311debffaf09966")
	rr := &ipmi.RAKPResult{
		Username:   user,
		AuthAlgo:   algo,
		ClientSID:  0x6f8a7c3f,
		BMCSID:     0x51484a7e,
		ClientRand: []byte("0123456789abcdef"),
		BMCRand:    []byte("fedcba9876543210"),
		BMCGUID:    guid,
	}
	salt := rr.Salt()
	mac := hmac.New(hashCtor(algo), []byte(pw))
	mac.Write(salt)
	rr.RAKPHash = mac.Sum(nil)

	// Cross-check against ipmi's verifier: the offline salt must be the exact
	// input ipmi.VerifyRAKPPassword keys over.
	if !rr.VerifyRAKPPassword(pw) {
		t.Fatalf("algo %s: ipmi.VerifyRAKPPassword rejected the correct password -- salt layout drift", AlgoName(algo))
	}
	return &Hash{GID: gid, Algo: algo, Username: user, Salt: salt, MAC: rr.RAKPHash}
}

func crackOnce(hashes []*Hash, candidates []string) map[int]string {
	got := map[int]string{}
	cands := make(chan []string, 1)
	cands <- candidates
	close(cands)
	Crack(hashes, cands, 2, func(h *Hash, pw string) { got[h.GID] = pw })
	return got
}

func TestCrackAllAlgos(t *testing.T) {
	pw := "ADMIN"
	for i, algo := range AllAlgos {
		h := makeHash(t, i, algo, "ADMIN", pw)
		got := crackOnce([]*Hash{h}, []string{"root", "wrong", pw, "admin"})
		if got[i] != pw {
			t.Errorf("algo %s: cracked %q, want %q", AlgoName(algo), got[i], pw)
		}
	}
}

func TestCrackWrongPasswordNoFalsePositive(t *testing.T) {
	h := makeHash(t, 0, AlgoMD5, "ADMIN", "secret123")
	got := crackOnce([]*Hash{h}, []string{"root", "admin", "password"})
	if _, ok := got[0]; ok {
		t.Errorf("false positive: got %q for an absent password", got[0])
	}
}

func TestParseMaskKeyspace(t *testing.T) {
	m, err := ParseMask("?d?d?d?d", nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := m.Keyspace().Int64(); got != 10000 {
		t.Errorf("?d?d?d?d keyspace = %d, want 10000", got)
	}
	// Literal + custom charset.
	m2, err := ParseMask("pw?1?1", map[byte]string{'1': "ab"})
	if err != nil {
		t.Fatal(err)
	}
	if got := m2.Keyspace().Int64(); got != 4 {
		t.Errorf("pw?1?1 keyspace = %d, want 4", got)
	}
	if _, err := ParseMask("?z", nil); err == nil {
		t.Error("expected error for unknown charset ?z")
	}
	if _, err := ParseMask("?1", nil); err == nil {
		t.Error("expected error for undefined custom charset ?1")
	}
}

func TestMaskStreamEnumerates(t *testing.T) {
	m, _ := ParseMask("?d?d", nil)
	out := make(chan string, 128)
	stop := make(chan struct{})
	go m.Stream(out, stop)
	seen := map[string]bool{}
	for s := range out {
		seen[s] = true
	}
	if len(seen) != 100 {
		t.Fatalf("?d?d produced %d unique candidates, want 100", len(seen))
	}
	if !seen["00"] || !seen["99"] || !seen["42"] {
		t.Error("mask stream missing expected candidates")
	}
}

func TestParseCiphers(t *testing.T) {
	want, unknown := ParseCiphers([]string{"md5", "sha256"})
	if len(unknown) != 0 || !want[AlgoMD5] || !want[AlgoSHA256] || want[AlgoSHA1] {
		t.Errorf("md5,sha256 -> want=%v unknown=%v", want, unknown)
	}
	want, unknown = ParseCiphers([]string{"7300", "bogus"})
	if !want[AlgoSHA1] || len(unknown) != 1 || unknown[0] != "bogus" {
		t.Errorf("7300,bogus -> want=%v unknown=%v", want, unknown)
	}
	if w, _ := ParseCiphers([]string{"nope"}); w != nil {
		t.Errorf("all-unknown should yield nil want, got %v", w)
	}
}

func TestDefaultsProduceCracksBMCDefault(t *testing.T) {
	// A host whose password is a common BMC default must fall to the always-on
	// defaults pass (no wordlist/pattern given).
	h := makeHash(t, 0, AlgoSHA1, "ADMIN", "calvin")
	cands := make(chan []string, 64)
	stop := make(chan struct{})
	go Produce(cands, stop, Options{IncludeDefaults: true, BatchSize: 64})
	got := ""
	Crack([]*Hash{h}, cands, 2, func(_ *Hash, pw string) { got = pw })
	close(stop)
	if got != "calvin" {
		t.Errorf("defaults pass cracked %q, want calvin", got)
	}
}

func TestDefaultsLightVariation(t *testing.T) {
	// A leetspeak variation of a default (PASSW0RD -> P4SSW0RD via a->4) must be
	// reachable through the light-variation pass.
	h := makeHash(t, 0, AlgoMD5, "ADMIN", "0penBmc")
	cands := make(chan []string, 64)
	stop := make(chan struct{})
	go Produce(cands, stop, Options{IncludeDefaults: true, BatchSize: 64})
	got := ""
	Crack([]*Hash{h}, cands, 2, func(_ *Hash, pw string) { got = pw })
	close(stop)
	if got != "0penBmc" {
		t.Errorf("defaults pass cracked %q, want 0penBmc", got)
	}
}

func TestLoadScansDedupChoosesCheapestCipherPerHostUser(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "scan.jsonl")

	mk := func(algo byte) map[string]any {
		t.Helper()
		guid, _ := hex.DecodeString("9c6b005ece21a701d311debffaf09966")
		rr := &ipmi.RAKPResult{
			Username:   "ADMIN",
			AuthAlgo:   algo,
			ClientSID:  0x6f8a7c3f,
			BMCSID:     0x51484a7e,
			ClientRand: []byte("0123456789abcdef"),
			BMCRand:    []byte("fedcba9876543210"),
			BMCGUID:    guid,
		}
		m := hmac.New(hashCtor(algo), []byte("ADMIN"))
		m.Write(rr.Salt())
		rr.RAKPHash = m.Sum(nil)
		return map[string]any{
			"username":    rr.Username,
			"auth_algo":   int(algo),
			"client_sid":  rr.ClientSID,
			"bmc_sid":     rr.BMCSID,
			"client_rand": hex.EncodeToString(rr.ClientRand),
			"bmc_rand":    hex.EncodeToString(rr.BMCRand),
			"bmc_guid":    hex.EncodeToString(rr.BMCGUID),
			"rakp_hash":   hex.EncodeToString(rr.RAKPHash),
		}
	}

	rec := map[string]any{
		"host": "198.51.100.11",
		"identity": map[string]any{
			"vendor":  "ami",
			"product": "MegaRAC",
		},
		"rakp": []map[string]any{mk(AlgoSHA256), mk(AlgoMD5)},
	}
	b, err := json.Marshal(rec)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(b, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}

	got, tally, err := LoadScans([]string{path}, map[byte]bool{AlgoMD5: true, AlgoSHA256: true}, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("dedup host+user produced %d hashes, want 1", len(got))
	}
	if got[0].Algo != AlgoMD5 {
		t.Fatalf("selected algo %s, want %s", AlgoName(got[0].Algo), AlgoName(AlgoMD5))
	}
	if tally[AlgoMD5] != 1 || tally[AlgoSHA256] != 0 {
		t.Fatalf("tally md5=%d sha256=%d, want md5=1 sha256=0", tally[AlgoMD5], tally[AlgoSHA256])
	}
}

func TestMatchSMCRAKPFixedKey(t *testing.T) {
	h := makeHash(t, 0, AlgoSHA1, "ADMIN", "wrong-password")
	mac := hmac.New(sha1.New, smcRAKPFixedKey)
	mac.Write(h.Salt)
	h.MAC = mac.Sum(nil)
	if !MatchSMCRAKPFixedKey(h) {
		t.Fatal("expected fixed-key match")
	}
}

func TestLoadScansLabelsSMCRAKPOEMKey(t *testing.T) {
	h := makeHash(t, 0, AlgoSHA1, "ADMIN", "wrong-password")
	mac := hmac.New(sha1.New, smcRAKPFixedKey)
	mac.Write(h.Salt)
	h.MAC = mac.Sum(nil)

	rec := map[string]any{
		"host": "198.51.100.20",
		"identity": map[string]any{
			"vendor":  "supermicro",
			"product": "X9SPU-F",
		},
		"rakp": []map[string]any{{
			"username":    h.Username,
			"auth_algo":   int(h.Algo),
			"client_sid":  0x6f8a7c3f,
			"bmc_sid":     0x51484a7e,
			"client_rand": hex.EncodeToString([]byte("0123456789abcdef")),
			"bmc_rand":    hex.EncodeToString([]byte("fedcba9876543210")),
			"bmc_guid":    hex.EncodeToString([]byte{0x9c, 0x6b, 0x00, 0x5e, 0xce, 0x21, 0xa7, 0x01, 0xd3, 0x11, 0xde, 0xbf, 0xfa, 0xf0, 0x99, 0x66}),
			"rakp_hash":   hex.EncodeToString(h.MAC),
		}},
	}
	b, err := json.Marshal(rec)
	if err != nil {
		t.Fatal(err)
	}

	path := filepath.Join(t.TempDir(), "scan.jsonl")
	if err := os.WriteFile(path, append(b, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}

	hashes, tally, err := LoadScans([]string{path}, map[byte]bool{AlgoSHA1: true}, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(hashes) != 1 {
		t.Fatalf("LoadScans returned %d hashes, want 1", len(hashes))
	}
	if hashes[0].Username != "ADMIN" {
		t.Fatalf("Username=%q, want %q (real account must be preserved)", hashes[0].Username, "ADMIN")
	}
	if !hashes[0].SMCFixedKey {
		t.Fatal("loaded hash should be flagged SMCFixedKey")
	}
	if !MatchSMCRAKPFixedKey(hashes[0]) {
		t.Fatal("loaded hash should still validate with the fixed OEM key")
	}
	if tally[AlgoSHA1] != 1 {
		t.Fatalf("tally[sha1]=%d, want 1", tally[AlgoSHA1])
	}
}

func TestHarvestSeeds(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "scan.jsonl")
	lines := []string{
		`{"host":"10.0.0.1","rakp":[{"username":"operator","authAlgo":1,"rakpHash":"aa"}],"findings":[{"check":"ipmi.v20.rakpHash","fields":{"cracked":"S3cretPass"}}]}`,
		`{"host":"10.0.0.2","findings":[{"check":"redfish.default","fields":{"username":"root","password":"calvin"}},{"check":"ipmi.postauth","fields":{"usernames":"admin,svc-backup"}}]}`,
		`{"host":"10.0.0.3","findings":[{"check":"ipmi.v20.rakpHash","fields":{"cracked":"(SMC-RAKP-OEM-KEY)"}}]}`,
	}
	if err := os.WriteFile(path, []byte(joinLines(lines)), 0o600); err != nil {
		t.Fatal(err)
	}
	seeds, err := HarvestSeeds([]string{path})
	if err != nil {
		t.Fatal(err)
	}
	set := map[string]bool{}
	for _, s := range seeds {
		set[s] = true
	}
	for _, want := range []string{"operator", "S3cretPass", "root", "calvin", "admin", "svc-backup"} {
		if !set[want] {
			t.Errorf("HarvestSeeds missing %q; got %v", want, seeds)
		}
	}
	if set["(SMC-RAKP-OEM-KEY)"] {
		t.Errorf("HarvestSeeds should drop the synthetic SMCRAKP label")
	}
}

func TestExtraSeedsCrackNormalMode(t *testing.T) {
	// A password recovered on one host (fed via ExtraSeeds) must crack another
	// host's hash in normal mode, without permutation and without defaults.
	h := makeHash(t, 0, AlgoSHA1, "operator", "S3cretPass")
	cands := make(chan []string, 64)
	stop := make(chan struct{})
	go Produce(cands, stop, Options{ExtraSeeds: []string{"S3cretPass"}, BatchSize: 64})
	got := ""
	Crack([]*Hash{h}, cands, 2, func(_ *Hash, pw string) { got = pw })
	close(stop)
	if got != "S3cretPass" {
		t.Errorf("extra-seed normal pass cracked %q, want S3cretPass", got)
	}
}

func TestExtraSeedsDeepPermutes(t *testing.T) {
	// In --deep mode an observed seed is permuted; a leet/affix variant of the
	// seed must crack. Normal mode (no permute) must not.
	h := makeHash(t, 0, AlgoSHA1, "admin", "Summer2023")
	seed := "summer"

	// Normal mode: verbatim seed only -> no crack.
	c1 := make(chan []string, 256)
	s1 := make(chan struct{})
	go Produce(c1, s1, Options{ExtraSeeds: []string{seed}, BatchSize: 64})
	gotNormal := ""
	Crack([]*Hash{h}, c1, 2, func(_ *Hash, pw string) { gotNormal = pw })
	close(s1)
	if gotNormal != "" {
		t.Errorf("normal mode unexpectedly cracked %q", gotNormal)
	}

	// Deep mode: permutations of the seed -> crack.
	c2 := make(chan []string, 4096)
	s2 := make(chan struct{})
	go Produce(c2, s2, Options{ExtraSeeds: []string{seed}, Deep: true, BatchSize: 64})
	gotDeep := ""
	Crack([]*Hash{h}, c2, 2, func(_ *Hash, pw string) { gotDeep = pw })
	close(s2)
	if gotDeep != "Summer2023" {
		t.Errorf("deep extra-seed permutation cracked %q, want Summer2023", gotDeep)
	}
}

func joinLines(lines []string) string {
	out := ""
	for _, l := range lines {
		out += l + "\n"
	}
	return out
}
