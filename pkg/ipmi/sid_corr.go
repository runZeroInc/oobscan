package ipmi

import (
	"encoding/binary"
	"fmt"
	"math"
	"math/bits"
	"math/rand"
	"time"
)

type SIDCorrelationConfig struct {
	RandomizeInputOrder bool

	Seed int64

	ConfidenceLevel float64

	Logf func(string)
}

type SIDCorrelationResult struct {
	Host string

	Trials int

	ClientSIDs  []uint32
	ManagedSIDs []uint32

	MutualInfoBits float64

	BitCorrelation [32]float64

	MaxBitCorr float64

	PerBitPValue [32]float64

	PerBitCILow  [32]float64
	PerBitCIHigh [32]float64

	ConfidenceLevel float64

	SignificantBits []int

	Finding string
}

func clientSIDDistributions(n int) []uint32 {
	out := make([]uint32, 0, n)
	perDist := n / 4

	for range perDist {
		out = append(out, 0x00000000)
	}

	for range perDist {
		out = append(out, 0xFFFFFFFF)
	}

	for i := range perDist {
		out = append(out, 1<<(uint(i)%32))
	}

	for i := range perDist {
		out = append(out, uint32(i+1))
	}
	return out
}

func MeasureSIDClientCorrelation(host string, port int, trials int, timeout time.Duration) (*SIDCorrelationResult, error) {
	return MeasureSIDClientCorrelationWithConfig(host, port, trials, timeout, nil)
}

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

func openSessionWithClientSID(host string, port int, clientSID uint32, timeout time.Duration) (uint32, error) {
	c, err := NewClient(host, port, timeout)
	if err != nil {
		return 0, err
	}
	defer c.Close()

	body := buildOpenSessionMinimal(clientSID, RAKPHMACSHA1, IntegrityNone, ConfNone)
	pkt := buildRMCPPlus(PayloadOpenSessionReq, 0, 0, body)
	resp, err := c.Send(pkt)
	if err != nil {
		return 0, err
	}
	return parseOpenSessionResp(resp)
}

func buildOpenSessionMinimal(clientSID uint32, authAlgo, intAlgo, confAlgo byte) []byte {
	var b [32]byte

	b[1] = 0x04
	binary.LittleEndian.PutUint32(b[4:], clientSID)

	b[8] = 0x00
	b[11] = 0x08
	b[12] = authAlgo

	b[16] = 0x01
	b[19] = 0x08
	b[20] = intAlgo

	b[24] = 0x02
	b[27] = 0x08
	b[28] = confAlgo
	return b[:]
}

func computeSIDCorrelation(res *SIDCorrelationResult) {
	n := len(res.ClientSIDs)
	if n == 0 {
		return
	}

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

	res.MutualInfoBits = empiricalMI(res.ClientSIDs, res.ManagedSIDs)

	if res.MaxBitCorr > 0.05 || res.MutualInfoBits > 0.1 {

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

func empiricalMI(xs, ys []uint32) float64 {
	type xy struct{ x, y uint8 }
	jointCnt := make(map[xy]int)
	xCnt := make(map[uint8]int)
	yCnt := make(map[uint8]int)
	n := len(xs)
	for i := range n {

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
