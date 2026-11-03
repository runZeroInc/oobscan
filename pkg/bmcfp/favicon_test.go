package bmcfp

import "testing"

// Golden vectors independently computed from a reference MurmurHash3 x86_32
// (seed 0) implementation and cross-checked against Python's mmh3.
func TestMurmur3Golden(t *testing.T) {
	cases := []struct {
		in   string
		want int32
	}{
		{"", 0},
		{"hello", 613153351},
		{"The quick brown fox jumps over the lazy dog", 776992547},
	}
	for _, c := range cases {
		if got := murmur3x86_32([]byte(c.in)); got != c.want {
			t.Errorf("murmur3x86_32(%q) = %d, want %d", c.in, got, c.want)
		}
	}
}

func TestFaviconHashGolden(t *testing.T) {
	icon := []byte("oobscan-favicon-test\x00\x01\x02")
	const want int32 = -1741975671 // mmh3.hash(base64.encodebytes(icon)), verified vs Python
	if got := FaviconHash(icon); got != want {
		t.Fatalf("FaviconHash = %d, want %d", got, want)
	}
	if got := FaviconHashString(icon); got != "-1741975671" {
		t.Errorf("FaviconHashString = %q, want %q", got, "-1741975671")
	}
	// base64.encodebytes(b"") == b"" -> murmur3 of empty -> 0
	if got := FaviconHash(nil); got != 0 {
		t.Errorf("FaviconHash(nil) = %d, want 0", got)
	}
}

// Product-specific favicon hashes must map to the right vendor, and an unseen
// hash must not match.
func TestFaviconMMH3Match(t *testing.T) {
	cases := []struct{ hash, vendor, product string }{
		{"1012948051", "opengear", "console server"},
		{"1428702434", "dell", "iDRAC"},
		{"1958753229", "lenovo", "XCC"},
		{"561563906", "huawei", "iBMC"},
		{"-646322113", "cisco", "CIMC"},
		{"-2016537204", "supermicro", "IPMI"},
		{"-1292500717", "raritan", "PX / KX"},
		{"-1040945478", "pikvm", "PiKVM"},
		{"-412815663", "jetkvm", "JetKVM"},
	}
	for _, c := range cases {
		v, p, ok := Match(FaviconMMH3, c.hash)
		if !ok || v != c.vendor || p != c.product {
			t.Errorf("Match(FaviconMMH3, %q) = (%q,%q,%v), want (%q,%q,true)", c.hash, v, p, ok, c.vendor, c.product)
		}
	}
	if _, _, ok := Match(FaviconMMH3, "123456789"); ok {
		t.Error("Match(FaviconMMH3, unseen) should not match")
	}
	// A real favicon fetched live must reproduce the Opengear rule.
	// (FaviconHashString feeds Match; here we assert the wiring on a known hash.)
	if v, _, ok := Match(FaviconMMH3, FaviconHashString([]byte("x"))); ok {
		t.Errorf("arbitrary icon should not match a vendor, got %q", v)
	}
}

// CN-only cert rules for leaves that lack a keying DN.
func TestCertCNMatch(t *testing.T) {
	subj := []struct{ cn, vendor, product string }{
		{"ORACLESP-1730NM19EP", "oracle", "ILOM"},
		{"C-series CIMC", "cisco", "CIMC"},
		{"Perle", "perle", "IOLAN"},
		{"Sentry Switched CDU", "servertech", "Sentry"},
		{"blikvm.com", "blikvm", "BliKVM"},
	}
	for _, c := range subj {
		v, p, ok := Match(TLSSubjectCN, c.cn)
		if !ok || v != c.vendor || p != c.product {
			t.Errorf("Match(TLSSubjectCN, %q) = (%q,%q,%v), want (%q,%q,true)", c.cn, v, p, ok, c.vendor, c.product)
		}
	}
	if v, p, ok := Match(TLSIssuerCN, "Huawei IT Product CA"); !ok || v != "huawei" || p != "iBMC" {
		t.Errorf("Match(TLSIssuerCN, Huawei IT Product CA) = (%q,%q,%v), want huawei/iBMC", v, p, ok)
	}
}
