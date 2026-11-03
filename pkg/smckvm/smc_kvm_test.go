package smckvm

import "testing"

// TestGlibcRandFirst pins the generator to glibc's documented behavior: after
// srand(1) the first rand() is 1804289383. A mismatch means the PRNG diverged
// from glibc (for example if it were accidentally modeling BSD/macOS rand()).
func TestGlibcRandFirst(t *testing.T) {
	if got := NewStream(1).Next(); got != 1804289383 {
		t.Fatalf("glibc srand(1) first rand() = %d, want 1804289383", got)
	}
}

// TestLiveToken pins the full token reconstruction to a field observation: on a
// live X13 (2401MS 01.07.01) on 2026-07-16, the iKVM launch minted token
// "TFqgekVS3CZJt7W", which reconstructs from seed 1784182645 (06:17:25 UTC).
func TestLiveToken(t *testing.T) {
	const seed = 1784182645
	const want = "TFqgekVS3CZJt7W"
	if got := Token(seed); got != want {
		t.Fatalf("Token(%d) = %q, want %q", seed, got, want)
	}
	if got := TokenPath(seed); got != "/redfish/"+want+".IKVM" {
		t.Fatalf("TokenPath(%d) = %q", seed, got)
	}
}

// TestTokenShape checks structural invariants: length and alphabet membership.
func TestTokenShape(t *testing.T) {
	tok := Token(1784182645)
	if len(tok) != TokenLen {
		t.Fatalf("token length = %d, want %d", len(tok), TokenLen)
	}
	for i := range tok {
		found := false
		for j := range len(Charset) {
			if tok[i] == Charset[j] {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("token char %q not in charset", tok[i])
		}
	}
}
