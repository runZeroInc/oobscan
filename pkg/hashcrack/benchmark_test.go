package hashcrack

import (
	"fmt"
	"runtime"
	"testing"

	"github.com/runZeroInc/oobscan/pkg/ipmi"
)

// buildBenchHashes builds n never-matching hashes for algo, each with a distinct
// salt (mirrors a real RAKP dump: one unique salt per host). The MAC is the
// correct digest length but a fixed non-matching value, so every HMAC is
// computed and compared but nothing is ever "cracked".
func buildBenchHashes(algo byte, n int) []*Hash {
	nomatch := make([]byte, macLen(algo))
	for i := range nomatch {
		nomatch[i] = 0xEE
	}
	guid := make([]byte, 16)
	cr := []byte("0123456789abcdef")
	br := []byte("fedcba9876543210")
	hashes := make([]*Hash, n)
	for i := range hashes {
		rr := &ipmi.RAKPResult{
			Username: "ADMIN", AuthAlgo: algo,
			ClientSID: uint32(i), BMCSID: uint32(i*7 + 1),
			ClientRand: cr, BMCRand: br, BMCGUID: guid,
		}
		hashes[i] = &Hash{GID: i, Algo: algo, Salt: rr.Salt(), MAC: append([]byte(nil), nomatch...)}
	}
	return hashes
}

// benchThroughput measures many-salts HMAC throughput: b.N candidates, each
// tried against nSalts salts => b.N*nSalts HMACs. Reports MH/s, directly
// comparable to John's "Many salts" c/s figure.
func benchThroughput(b *testing.B, algo byte, nSalts int) {
	hashes := buildBenchHashes(algo, nSalts)
	workers := runtime.NumCPU()
	cands := make(chan []string, 128)
	go func() {
		defer close(cands)
		batch := make([]string, 0, 64)
		for i := 0; i < b.N; i++ {
			batch = append(batch, fmt.Sprintf("cand%09d", i))
			if len(batch) == 64 {
				cands <- batch
				batch = make([]string, 0, 64)
			}
		}
		if len(batch) > 0 {
			cands <- batch
		}
	}()
	b.ResetTimer()
	_, nHmac := Crack(hashes, cands, workers, func(*Hash, string) {})
	b.StopTimer()
	secs := b.Elapsed().Seconds()
	if secs > 0 {
		b.ReportMetric(float64(nHmac)/secs/1e6, "MH/s")
	}
}

// BenchmarkCrack reports many-salts throughput per algorithm (the metric that
// matters for real RAKP dumps, where every host carries a unique salt).
func BenchmarkCrack(b *testing.B) {
	const nSalts = 20000
	for _, algo := range []byte{AlgoSHA1, AlgoMD5, AlgoSHA256} {
		b.Run(AlgoName(algo), func(b *testing.B) { benchThroughput(b, algo, nSalts) })
	}
}
