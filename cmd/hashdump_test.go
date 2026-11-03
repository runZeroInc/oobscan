package cmd

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/runZeroInc/oobscan/pkg/ipmi"
)

func TestHashcatOutputPaths(t *testing.T) {
	sha1, md5 := hashcatOutputPaths("/tmp/rakp.hc")
	if sha1 != "/tmp/rakp-sha1.7300.hc" {
		t.Fatalf("sha1 path = %q, want %q", sha1, "/tmp/rakp-sha1.7300.hc")
	}
	if md5 != "/tmp/rakp-md5.7350.hc" {
		t.Fatalf("md5 path = %q, want %q", md5, "/tmp/rakp-md5.7350.hc")
	}
}

func TestHashcatOutputPathsNoExt(t *testing.T) {
	sha1, md5 := hashcatOutputPaths("rakp")
	if sha1 != "rakp-sha1.7300.hc" {
		t.Fatalf("sha1 path = %q, want %q", sha1, "rakp-sha1.7300.hc")
	}
	if md5 != "rakp-md5.7350.hc" {
		t.Fatalf("md5 path = %q, want %q", md5, "rakp-md5.7350.hc")
	}
}

func TestJohnOutputPaths(t *testing.T) {
	md5Path, sha1Path, sha256Path := johnOutputPaths("/tmp/rakp.hc")
	if md5Path != "/tmp/rakp-md5.jtr" {
		t.Fatalf("md5 jtr path = %q, want %q", md5Path, "/tmp/rakp-md5.jtr")
	}
	if sha1Path != "/tmp/rakp-sha1.jtr" {
		t.Fatalf("sha1 jtr path = %q, want %q", sha1Path, "/tmp/rakp-sha1.jtr")
	}
	if sha256Path != "/tmp/rakp-sha256.jtr" {
		t.Fatalf("sha256 jtr path = %q, want %q", sha256Path, "/tmp/rakp-sha256.jtr")
	}
}

func TestHashdumpHashcatWrites7300And7350(t *testing.T) {
	tmp := t.TempDir()
	scanPath := filepath.Join(tmp, "scan.jsonl")

	type rakpFixture struct {
		rec      map[string]any
		line7300 string
		line7350 string
	}
	mk := func() rakpFixture {
		guid, _ := hex.DecodeString("9c6b005ece21a701d311debffaf09966")

		rr1 := &ipmi.RAKPResult{
			Username:   "ADMIN",
			AuthAlgo:   1,
			ClientSID:  0x6f8a7c3f,
			BMCSID:     0x51484a7e,
			ClientRand: []byte("0123456789abcdef"),
			BMCRand:    []byte("fedcba9876543210"),
			BMCGUID:    guid,
		}
		h1 := hmac.New(sha1.New, []byte("ADMIN"))
		h1.Write(rr1.Salt())
		rr1.RAKPHash = h1.Sum(nil)

		rr2 := &ipmi.RAKPResult{
			Username:   "ADMIN",
			AuthAlgo:   2,
			ClientSID:  0x6f8a7c40,
			BMCSID:     0x51484a7f,
			ClientRand: []byte("1123456789abcdee"),
			BMCRand:    []byte("eedcba9876543211"),
			BMCGUID:    guid,
		}
		h2 := hmac.New(md5.New, []byte("ADMIN"))
		h2.Write(rr2.Salt())
		rr2.RAKPHash = h2.Sum(nil)

		entry := func(rr *ipmi.RAKPResult) map[string]any {
			return map[string]any{
				"username":    rr.Username,
				"auth_algo":   int(rr.AuthAlgo),
				"client_sid":  rr.ClientSID,
				"bmc_sid":     rr.BMCSID,
				"client_rand": hex.EncodeToString(rr.ClientRand),
				"bmc_rand":    hex.EncodeToString(rr.BMCRand),
				"bmc_guid":    hex.EncodeToString(rr.BMCGUID),
				"rakp_hash":   hex.EncodeToString(rr.RAKPHash),
			}
		}

		return rakpFixture{
			rec: map[string]any{
				"host": "198.51.100.20",
				"identity": map[string]any{
					"vendor":  "ami",
					"product": "MegaRAC",
				},
				"rakp": []map[string]any{entry(rr1), entry(rr2)},
			},
			line7300: hex.EncodeToString(rr1.Salt()) + ":" + hex.EncodeToString(rr1.RAKPHash),
			line7350: hex.EncodeToString(rr2.RAKPHash) + ":" + hex.EncodeToString(rr2.Salt()),
		}
	}
	fx := mk()
	b, err := json.Marshal(fx.rec)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(scanPath, append(b, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}

	oldOutput, oldShow, oldCiphers := hashdumpOutput, hashdumpShow, hashdumpCiphers
	defer func() {
		hashdumpOutput, hashdumpShow, hashdumpCiphers = oldOutput, oldShow, oldCiphers
	}()

	base := filepath.Join(tmp, "rakp.hc")
	hashdumpOutput = base
	hashdumpShow = false
	hashdumpCiphers = "md5,sha1"

	if err := runHashdump(nil, []string{scanPath}); err != nil {
		t.Fatal(err)
	}

	sha1Path, md5Path := hashcatOutputPaths(base)
	b7300, err := os.ReadFile(sha1Path)
	if err != nil {
		t.Fatal(err)
	}
	b7350, err := os.ReadFile(md5Path)
	if err != nil {
		t.Fatal(err)
	}

	if got := strings.TrimSpace(string(b7300)); got != fx.line7300 {
		t.Fatalf("7300 line = %q, want %q", got, fx.line7300)
	}
	if got := strings.TrimSpace(string(b7350)); got != fx.line7350 {
		t.Fatalf("7350 line = %q, want %q", got, fx.line7350)
	}

	md5JTRPath, sha1JTRPath, sha256JTRPath := johnOutputPaths(base)
	bmd5, err := os.ReadFile(md5JTRPath)
	if err != nil {
		t.Fatal(err)
	}
	bsha1, err := os.ReadFile(sha1JTRPath)
	if err != nil {
		t.Fatal(err)
	}
	bsha256, err := os.ReadFile(sha256JTRPath)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(string(bmd5)); got == "" {
		t.Fatal("md5 .jtr should contain one line")
	}
	if got := strings.TrimSpace(string(bsha1)); got == "" {
		t.Fatal("sha1 .jtr should contain one line")
	}
	if got := strings.TrimSpace(string(bsha256)); got != "" {
		t.Fatalf("sha256 .jtr should be empty, got %q", got)
	}
}

func TestHashdumpSkipsSMCRAKPOEMKey(t *testing.T) {
	tmp := t.TempDir()
	scanPath := filepath.Join(tmp, "scan.jsonl")
	guid, _ := hex.DecodeString("9c6b005ece21a701d311debffaf09966")
	rr := &ipmi.RAKPResult{
		Username:   "ADMIN",
		AuthAlgo:   1,
		ClientSID:  0x6f8a7c3f,
		BMCSID:     0x51484a7e,
		ClientRand: []byte("0123456789abcdef"),
		BMCRand:    []byte("fedcba9876543210"),
		BMCGUID:    guid,
	}
	h := hmac.New(sha1.New, []byte("ADMIN"))
	h.Write(rr.Salt())
	rr.RAKPHash = h.Sum(nil)
	oemKey, _ := hex.DecodeString("fab979d849be933dd0c41fd2c9d77a30aa8d3f50")
	hFixed := hmac.New(sha1.New, oemKey)
	hFixed.Write(rr.Salt())
	rr.RAKPHash = hFixed.Sum(nil)
	rec := map[string]any{
		"host": "198.51.100.20",
		"identity": map[string]any{
			"vendor":  "supermicro",
			"product": "X9SPU-F",
		},
		"rakp": []map[string]any{{
			"username":    rr.Username,
			"auth_algo":   int(rr.AuthAlgo),
			"client_sid":  rr.ClientSID,
			"bmc_sid":     rr.BMCSID,
			"client_rand": hex.EncodeToString(rr.ClientRand),
			"bmc_rand":    hex.EncodeToString(rr.BMCRand),
			"bmc_guid":    hex.EncodeToString(rr.BMCGUID),
			"rakp_hash":   hex.EncodeToString(rr.RAKPHash),
		}},
	}
	b, err := json.Marshal(rec)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(scanPath, append(b, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}

	oldOutput, oldShow, oldCiphers := hashdumpOutput, hashdumpShow, hashdumpCiphers
	defer func() {
		hashdumpOutput, hashdumpShow, hashdumpCiphers = oldOutput, oldShow, oldCiphers
	}()

	base := filepath.Join(tmp, "rakp.hc")
	hashdumpOutput = base
	hashdumpShow = false
	hashdumpCiphers = "sha1"

	if err := runHashdump(nil, []string{scanPath}); err != nil {
		t.Fatal(err)
	}

	sha1Path, md5Path := hashcatOutputPaths(base)
	for _, path := range []string{sha1Path, md5Path} {
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if got := strings.TrimSpace(string(b)); got != "" {
			t.Fatalf("expected %s to be empty, got %q", filepath.Base(path), got)
		}
	}
	md5JTRPath, sha1JTRPath, sha256JTRPath := johnOutputPaths(base)
	for _, path := range []string{md5JTRPath, sha1JTRPath, sha256JTRPath} {
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if got := strings.TrimSpace(string(b)); got != "" {
			t.Fatalf("expected %s to be empty, got %q", filepath.Base(path), got)
		}
	}
}

func TestRunHashdumpRequiresOutput(t *testing.T) {
	oldOutput, oldShow := hashdumpOutput, hashdumpShow
	defer func() { hashdumpOutput, hashdumpShow = oldOutput, oldShow }()
	hashdumpOutput = ""
	hashdumpShow = false
	err := runHashdump(nil, []string{"/tmp/does-not-matter.jsonl"})
	if err == nil || !strings.Contains(err.Error(), "--output") {
		t.Fatalf("expected --output error, got %v", err)
	}
}
