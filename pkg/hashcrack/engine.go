package hashcrack

import (
	"bytes"
	"crypto/hmac"
	"hash"
	"sync"
	"sync/atomic"
)

// CrackStats exposes live counters from CrackWithStats for progress UIs.
type CrackStats struct {
	Candidates atomic.Int64 // candidate passwords consumed from the producer
	HMAC       atomic.Int64 // total HMAC evaluations performed
	Cracked    atomic.Int64 // newly cracked hashes in this run
	Remaining  atomic.Int64 // unresolved hashes still active
}

type algoGroup struct {
	algo byte
	ctor func() hash.Hash
	full []*Hash
}

// Crack runs CPU-parallel offline password recovery over batched candidate streams and
// returns (#solved, #hmac computations) for throughput reporting.
//
// Design for throughput:
//   - Candidates are the outer loop, salts the inner loop. One crypto/hmac.New per
//     candidate precomputes the ipad/opad key-block state and Reset() restores it
//     per salt, so each HMAC costs the minimal three block compressions.
//   - Candidates arrive in batches to amortize channel sync over the large inner
//     salt loop.
//   - Each worker keeps a per-algo local active list, rebuilt only when a new crack
//     lands (generation counter), so the hot inner loop touches a plain slice with
//     no per-salt atomic load and skips already-solved salts.
func Crack(hashes []*Hash, batches <-chan []string, workers int, onCrack func(h *Hash, password string)) (int, int64) {
	return CrackWithStats(hashes, batches, workers, onCrack, nil)
}

// CrackWithStats is Crack plus optional live counters for progress reporting.
func CrackWithStats(hashes []*Hash, batches <-chan []string, workers int, onCrack func(h *Hash, password string), stats *CrackStats) (int, int64) {
	groups := map[byte]*algoGroup{}
	var order []byte
	maxGID := 0
	for _, h := range hashes {
		g := groups[h.Algo]
		if g == nil {
			g = &algoGroup{algo: h.Algo, ctor: hashCtor(h.Algo)}
			groups[h.Algo] = g
			order = append(order, h.Algo)
		}
		g.full = append(g.full, h)
		if h.GID > maxGID {
			maxGID = h.GID
		}
	}
	solved := make([]atomic.Bool, maxGID+1)
	var solvedCount, totalHmac atomic.Int64
	var gen atomic.Uint64
	var remaining atomic.Int64
	remaining.Store(int64(len(hashes)))
	if stats != nil {
		stats.Remaining.Store(int64(len(hashes)))
	}

	var wg sync.WaitGroup
	for range workers {
		wg.Go(func() {
			var localHmac int64
			sum := make([]byte, 0, 64)
			// Local active lists per algo (own backing arrays, cap = full len).
			local := make([][]*Hash, len(order))
			for i, a := range order {
				local[i] = make([]*Hash, 0, len(groups[a].full))
			}
			localGen := ^uint64(0) // force a rebuild before first use
			for batch := range batches {
				if remaining.Load() == 0 {
					return
				}
				if stats != nil {
					stats.Candidates.Add(int64(len(batch)))
				}
				batchHmac := int64(0)
				if g := gen.Load(); g != localGen {
					for i, a := range order {
						la := local[i][:0]
						for _, h := range groups[a].full {
							if !solved[h.GID].Load() {
								la = append(la, h)
							}
						}
						local[i] = la
					}
					localGen = g
				}
				for _, cand := range batch {
					key := []byte(cand)
					for i := range order {
						la := local[i]
						if len(la) == 0 {
							continue
						}
						mac := hmac.New(groups[order[i]].ctor, key) // precompute key-block state
						for _, h := range la {
							mac.Reset() // restore key-block state (no re-key)
							mac.Write(h.Salt)
							sum = mac.Sum(sum[:0])
							localHmac++
							batchHmac++
							if bytes.Equal(sum, h.MAC) {
								if solved[h.GID].CompareAndSwap(false, true) {
									solvedCount.Add(1)
									left := remaining.Add(-1)
									if stats != nil {
										stats.Cracked.Add(1)
										stats.Remaining.Store(left)
									}
									gen.Add(1)
									onCrack(h, cand)
								}
							}
						}
					}
				}
				if stats != nil && batchHmac > 0 {
					stats.HMAC.Add(batchHmac)
				}
			}
			totalHmac.Add(localHmac)
		})
	}
	wg.Wait()
	return int(solvedCount.Load()), totalHmac.Load()
}
