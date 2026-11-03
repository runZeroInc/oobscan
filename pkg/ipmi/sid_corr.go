package ipmi

import (
	"encoding/binary"
	"fmt"
	"math"
	"math/bits"
	"math/rand"
	"time"
)

// SIDCorrelationConfig controls optional validation behavior for the session-ID correlation.
type SIDCorrelationConfig struct {
	// RandomizeInputOrder shuffles chosen-input SID samples before probing.
	RandomizeInputOrder bool
	// Seed controls RNG when RandomizeInputOrder is enabled.
	// If zero, current time is used.
	Seed int64
	// ConfidenceLevel controls per-bit confidence interval width.
	// If zero, 0.95 is used.
	ConfidenceLevel float64
	// Logf receives optional progress messages during the trial loop.
	Logf func(string)
}

// SIDCorrelationResult is the output of MeasureSIDClientCorrelation.
// A non-zero MutualInfoBits or any entry in BitCorrelation with |r| > 0.05
// signals that the BMC's PRNG is influenced by client input - a novel finding.
type SIDCorrelationResult struct {
	Host string
	// Trials is the number of completed Open-Session exchanges.
	Trials int
	// ClientSIDs and ManagedSIDs are parallel slices of the raw 32-bit values.
	ClientSIDs  []uint32
	ManagedSIDs []uint32
	// MutualInfoBits is the estimated mutual information I(client; managed)
	// in bits, approximated via empirical joint entropy.
	MutualInfoBits float64
	// BitCorrelation[i] is the Pearson correlation between bit i of the
	// client SID and bit i of the managed SID, for i in [0,31].
	BitCorrelation [32]float64
	// MaxBitCorr is max(|BitCorrelation[i]|) across all 32 bits.
	MaxBitCorr float64
	// PerBitPValue[i] is the two-sided p-value for bit i correlation.
	PerBitPValue [32]float64
	// PerBitCILow/High are Fisher-transform confidence bounds for r at bit i.
	PerBitCILow  [32]float64
	PerBitCIHigh [32]float64
	// ConfidenceLevel used for PerBitCI* (typically 0.95).
	ConfidenceLevel float64
	// SignificantBits lists bits where p < 0.05.
	SignificantBits []int
	// Finding is non-empty when any bit leaks >=1 effective bit.
	Finding string
}

// clientSIDDistributions returns the four chosen-input distributions:
//
//	all-zero, all-one, walking-bit, and incrementing.
//
// The total count per distribution is n/4 (rounded down).
func clientSIDDistributions(n int) []uint32 {
	out := make([]uint32, 0, n)
	perDist := n / 4

	// Distribution 1: all-zero
	for range perDist {
		out = append(out, 0x00000000)
	}
	// Distribution 2: all-one
	for range perDist {
		out = append(out, 0xFFFFFFFF)
	}
	// Distribution 3: walking bit (32 values repeated)
	for i := range perDist {
		out = append(out, 1<<(uint(i)%32))
	}
	// Distribution 4: incrementing from 1
	for i := range perDist {
		out = append(out, uint32(i+1))
	}
	return out
}

// MeasureSIDClientCorrelation measures whether the BMC's managed session ID
// correlates with the client SID. For each chosen-input client SID it sends an
// Open Session Request only (no RAKP continuation) and records the managed SID
// from the response. trials should be in the thousands; a 500ms timeout suits
// LAN, 2s WAN.
func MeasureSIDClientCorrelation(host string, port int, trials int, timeout time.Duration) (*SIDCorrelationResult, error) {
	return MeasureSIDClientCorrelationWithConfig(host, port, trials, timeout, nil)
}

// MeasureSIDClientCorrelationWithConfig runs the session-ID correlation with optional validation
// controls (randomized input ordering + per-bit p-values / confidence bounds).
func MeasureSIDClientCorrelationWithConfig(host string, port int, trials int, timeout time.Duration, cfg *SIDCorrelationConfig) (*SIDCorrelationResult, error) {
	if port == 0 {
		port = DefaultPort
	}
	if timeout == 0 {
		timeout = 500 * time.Millisecond
	}

	res := &SIDCorrelationResult{Host: host, ConfidenceLevel: 0.95}
	if cfg != nil && cfg.ConfidenceLevel > 0.0 && cfg.ConfidenceLevel < 1.0 {
		res.ConfidenceLevel = cfg.ConfidenceLevel
	}
	clientInputs := clientSIDDistributions(trials)
	if cfg != nil && cfg.RandomizeInputOrder {
		seed := cfg.Seed
		if seed == 0 {
			seed = time.Now().UnixNano()
		}
		rng := rand.New(rand.NewSource(seed))
		rng.Shuffle(len(clientInputs), func(i, j int) {
			clientInputs[i], clientInputs[j] = clientInputs[j], clientInputs[i]
		})
	}

	for _, cSID := range clientInputs {
		if cfg != nil && cfg.Logf != nil && (res.Trials == 0 || res.Trials%16 == 0) {
			cfg.Logf(fmt.Sprintf("ipmi.sid_corr: trial %d/%d", res.Trials+1, len(clientInputs)))
		}
		bmcSID, err := openSessionWithClientSID(host, port, cSID, timeout)
		if err != nil {
			// Skip failed exchanges rather than aborting; the BMC may rate-limit or
			// reset. Excessive failures yield an error at the end.
			continue
		}
		res.ClientSIDs = append(res.ClientSIDs, cSID)
		res.ManagedSIDs = append(res.ManagedSIDs, bmcSID)
		res.Trials++
	}

	if res.Trials == 0 {
		return res, fmt.Errorf("all %d open-session attempts failed", trials)
	}
	if cfg != nil && cfg.Logf != nil {
		cfg.Logf(fmt.Sprintf("ipmi.sid_corr: collected %d/%d samples", res.Trials, trials))
	}
	if res.Trials < trials/2 {
		return res, fmt.Errorf("too many failures: %d/%d succeeded", res.Trials, trials)
	}

	computeSIDCorrelation(res)
	return res, nil
}

// openSessionWithClientSID sends a single Open Session Request with the
// provided client SID and returns the BMC's managed SID from the response.
func openSessionWithClientSID(host string, port int, clientSID uint32, timeout time.Duration) (uint32, error) {
	c, err := NewClient(host, port, timeout)
	if err != nil {
		return 0, err
	}
	defer c.Close()

	// Request an auth algo the BMC will actually accept (HMAC-SHA1) rather than
	// auth-None: many BMCs (e.g. Supermicro ATEN) reject a cipher-0 / auth-None
	// Open Session outright, which makes every SID sample fail and the whole
	// Track-B correlation case ERROR out. We only need the managed SID from the
	// Open Session Response, which the BMC returns regardless of the negotiated
	// auth algo, so SHA1 is a safe choice that maximizes acceptance.
	body := buildOpenSessionMinimal(clientSID, RAKPHMACSHA1, IntegrityNone, ConfNone)
	pkt := buildRMCPPlus(PayloadOpenSessionReq, 0, 0, body)
	resp, err := c.Send(pkt)
	if err != nil {
		return 0, err
	}
	return parseOpenSessionResp(resp)
}

// buildOpenSessionMinimal builds a bare-minimum Open Session Request body.
func buildOpenSessionMinimal(clientSID uint32, authAlgo, intAlgo, confAlgo byte) []byte {
	var b [32]byte
	// [0] msg tag, [1] req priv=0x04, [2-3] reserved
	b[1] = 0x04
	binary.LittleEndian.PutUint32(b[4:], clientSID)
	// Auth payload descriptor: type=0x00, len=8, algo
	b[8] = 0x00
	b[11] = 0x08
	b[12] = authAlgo
	// Integrity payload descriptor
	b[16] = 0x01
	b[19] = 0x08
	b[20] = intAlgo
	// Confidentiality payload descriptor
	b[24] = 0x02
	b[27] = 0x08
	b[28] = confAlgo
	return b[:]
}

// computeSIDCorrelation fills MutualInfoBits, BitCorrelation, MaxBitCorr,
// and Finding on res.
func computeSIDCorrelation(res *SIDCorrelationResult) {
	n := len(res.ClientSIDs)
	if n == 0 {
		return
	}

	// Per-bit Pearson correlation between client bit i and managed bit i.
	for i := range 32 {
		shift := uint(i)
		var sx, sy, sxy, sx2, sy2 float64
		for j := range n {
			x := float64((res.ClientSIDs[j] >> shift) & 1)
			y := float64((res.ManagedSIDs[j] >> shift) & 1)
			sx += x
			sy += y
			sxy += x * y
			sx2 += x * x
			sy2 += y * y
		}
		fn := float64(n)
		num := sxy - sx*sy/fn
		denom := math.Sqrt((sx2 - sx*sx/fn) * (sy2 - sy*sy/fn))
		if denom < 1e-12 {
			res.BitCorrelation[i] = 0
		} else {
			res.BitCorrelation[i] = num / denom
		}
		if abs := math.Abs(res.BitCorrelation[i]); abs > res.MaxBitCorr {
			res.MaxBitCorr = abs
		}
		res.PerBitPValue[i] = corrPValue(res.BitCorrelation[i], n)
		lo, hi := fisherRCI(res.BitCorrelation[i], n, res.ConfidenceLevel)
		res.PerBitCILow[i] = lo
		res.PerBitCIHigh[i] = hi
		if res.PerBitPValue[i] < 0.05 {
			res.SignificantBits = append(res.SignificantBits, i)
		}
	}

	// Empirical mutual information via joint 2-bit symbol counts across
	// all 32 bit positions, marginalised independently.
	res.MutualInfoBits = empiricalMI(res.ClientSIDs, res.ManagedSIDs)

	// Finding: any bit with |r| > 0.05 or MI > 0.1 bits is noteworthy.
	if res.MaxBitCorr > 0.05 || res.MutualInfoBits > 0.1 {
		// Report which bits are correlated.
		leaked := []int{}
		for i, r := range res.BitCorrelation {
			if math.Abs(r) > 0.05 {
				leaked = append(leaked, i)
			}
		}
		res.Finding = fmt.Sprintf(
			"client SID leaks to managed SID: MI=%.3f bits, maxBitCorr=%.3f, correlated bits=%v",
			res.MutualInfoBits, res.MaxBitCorr, leaked,
		)
	}
}

func corrPValue(r float64, n int) float64 {
	if n < 4 {
		return 1.0
	}
	ar := math.Abs(r)
	if ar >= 0.999999 {
		return 0.0
	}
	t := ar * math.Sqrt(float64(n-2)/(1.0-ar*ar))
	// Normal approximation for two-sided p-value.
	p := 2.0 * (1.0 - normalCDF(t))
	if p < 0 {
		return 0
	}
	if p > 1 {
		return 1
	}
	return p
}

func fisherRCI(r float64, n int, conf float64) (float64, float64) {
	if n < 4 {
		return -1.0, 1.0
	}
	if conf <= 0.0 || conf >= 1.0 {
		conf = 0.95
	}
	// Clamp to avoid infinities in atanh.
	if r > 0.999999 {
		r = 0.999999
	}
	if r < -0.999999 {
		r = -0.999999
	}
	z := 0.5 * math.Log((1.0+r)/(1.0-r))
	se := 1.0 / math.Sqrt(float64(n-3))
	alpha := 1.0 - conf
	q := 1.0 - alpha/2.0
	zcrit := normalInv(q)
	lo := math.Tanh(z - zcrit*se)
	hi := math.Tanh(z + zcrit*se)
	return lo, hi
}

func normalCDF(x float64) float64 {
	return 0.5 * (1.0 + math.Erf(x/math.Sqrt2))
}

func normalInv(p float64) float64 {
	if p <= 0 {
		return math.Inf(-1)
	}
	if p >= 1 {
		return math.Inf(1)
	}
	return -math.Sqrt2 * math.Erfcinv(2.0*p)
}

// empiricalMI estimates I(X;Y) = H(X) + H(Y) - H(X,Y) using the 32-bit
// values directly, quantised to 256 bins (top 8 bits) to keep the histogram
// tractable. Returns estimated mutual information in bits.
func empiricalMI(xs, ys []uint32) float64 {
	type xy struct{ x, y uint8 }
	jointCnt := make(map[xy]int)
	xCnt := make(map[uint8]int)
	yCnt := make(map[uint8]int)
	n := len(xs)
	for i := range n {
		// Use top-byte + popcount byte as a 2-dimensional fingerprint.
		xk := uint8(bits.OnesCount32(xs[i]))
		yk := uint8(bits.OnesCount32(ys[i]))
		jointCnt[xy{xk, yk}]++
		xCnt[xk]++
		yCnt[yk]++
	}
	fn := float64(n)
	var hx, hy, hxy float64
	for _, c := range xCnt {
		p := float64(c) / fn
		hx -= p * math.Log2(p)
	}
	for _, c := range yCnt {
		p := float64(c) / fn
		hy -= p * math.Log2(p)
	}
	for _, c := range jointCnt {
		p := float64(c) / fn
		hxy -= p * math.Log2(p)
	}
	mi := hx + hy - hxy
	if mi < 0 {
		return 0
	}
	return mi
}
