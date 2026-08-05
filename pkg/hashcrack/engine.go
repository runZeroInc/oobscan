package hashcrack

import (
	"bytes"
	"crypto/hmac"
	"hash"
	"sync"
	"sync/atomic"
)

type CrackStats struct {
	Candidates atomic.Int64
	HMAC       atomic.Int64
	Cracked    atomic.Int64
	Remaining  atomic.Int64
}

type algoGroup struct {
	algo byte
	ctor func() hash.Hash
	full []*Hash
}

func Crack(hashes []*Hash, batches <-chan []string, workers int, onCrack func(h *Hash, password string)) (int, int64) {
	return CrackWithStats(hashes, batches, workers, onCrack, nil)
}

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

			local := make([][]*Hash, len(order))
			for i, a := range order {
				local[i] = make([]*Hash, 0, len(groups[a].full))
			}
			localGen := ^uint64(0)
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
						mac := hmac.New(groups[order[i]].ctor, key)
						for _, h := range la {
							mac.Reset()
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
