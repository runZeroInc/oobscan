package convert

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/hex"
	"slices"
	"testing"

	"github.com/runZeroInc/oobscan/pkg/engine"
	"github.com/runZeroInc/oobscan/pkg/ipmi"
)

// smcRAKPFixedKey is the known Supermicro/ATEN fixed SMCRAKP HMAC key (mirrors
// the unexported constant in pkg/ipmi). A RAKP-2 HMAC that verifies against it
// is forgeable, which is exactly what ipmi.smc.integrityBypass reports.
var smcRAKPFixedKey, _ = hex.DecodeString("fab979d849be933dd0c41fd2c9d77a30aa8d3f50")

// TestConvertSMCRAKPFromHashData covers the "SMCRAKP detected by reviewing the
// reported hash data" rule: a captured RAKP-2 whose HMAC verifies against the
// Supermicro fixed key is already the whole precondition for the forged
// session, so it converts directly into the command-capable
// ipmi.v20.smcrakpBypass, without any live probe, on any host whose generation
// does not resolve to a confirmed X14 (see TestConvertSMCRAKPX14StaysIntegrityBypass).
func TestConvertSMCRAKPFromHashData(t *testing.T) {
	r := &ipmi.RAKPResult{
		Username:   "ADMIN",
		AuthAlgo:   ipmi.RAKPHMACSHA1,
		ClientSID:  0x11223344,
		BMCSID:     0x55667788,
		ClientRand: repeat(0x11, 16),
		BMCRand:    repeat(0x22, 16),
		BMCGUID:    repeat(0x33, 16),
	}
	mac := hmac.New(sha1.New, smcRAKPFixedKey)
	mac.Write(r.Salt())
	entry := "ADMIN:1$" + hex.EncodeToString(r.Salt()) + ":" + hex.EncodeToString(mac.Sum(nil))

	line := `{"asset":{"type":"BMC","hw_vendor":"Super Micro Computer","addresses":["192.0.2.60"]},` +
		`"services":[{"port":623,"transport":"udp","protocols":["ipmi"],` +
		`"service_data":{"ipmi.rakp.hashes":` + jsonString(entry) + `}}]}`

	recs := convertToRecords(t, FormatRZSQL, writeLines(t, "smcrakp.jsonl", line))
	if len(recs) != 1 {
		t.Fatalf("records = %d, want 1", len(recs))
	}
	got := findingChecks(recs[0].Findings)
	if !got["ipmi.v20.rakpHash"] {
		t.Error("captured RAKP hash did not produce ipmi.v20.rakpHash")
	}
	if !got["ipmi.v20.smcrakpBypass"] {
		t.Errorf("fixed-key RAKP-2 on an unresolved (pre-X14 default) generation did not produce ipmi.v20.smcrakpBypass (got %v)", keys(got))
	}
	if got["ipmi.smc.integrityBypass"] {
		t.Errorf("fixed-key RAKP-2 on an unresolved generation should not stay at the weaker ipmi.smc.integrityBypass (got %v)", keys(got))
	}
}

// TestConvertSMCRAKPX14StaysIntegrityBypass covers the one carve-out: a
// confirmed Supermicro X14 board (the generation that moved to an
// OpenBMC-based stack and enforces per-session integrity) still gets the
// weaker ipmi.smc.integrityBypass instead of the command-capable
// ipmi.v20.smcrakpBypass, since X14 forges the session but rejects the
// unprotected command that makes the bypass exploitable.
func TestConvertSMCRAKPX14StaysIntegrityBypass(t *testing.T) {
	r := &ipmi.RAKPResult{
		Username:   "ADMIN",
		AuthAlgo:   ipmi.RAKPHMACSHA1,
		ClientSID:  0x11223344,
		BMCSID:     0x55667788,
		ClientRand: repeat(0x11, 16),
		BMCRand:    repeat(0x22, 16),
		BMCGUID:    repeat(0x33, 16),
	}
	mac := hmac.New(sha1.New, smcRAKPFixedKey)
	mac.Write(r.Salt())
	entry := "ADMIN:1$" + hex.EncodeToString(r.Salt()) + ":" + hex.EncodeToString(mac.Sum(nil))

	line := `{"asset":{"type":"BMC","hw_vendor":"Super Micro Computer","hw_product":"X14DAi-cpu","addresses":["192.0.2.63"]},` +
		`"services":[{"port":623,"transport":"udp","protocols":["ipmi"],` +
		`"service_data":{"ipmi.rakp.hashes":` + jsonString(entry) + `}}]}`

	recs := convertToRecords(t, FormatRZSQL, writeLines(t, "smcrakpx14.jsonl", line))
	if len(recs) != 1 {
		t.Fatalf("records = %d, want 1", len(recs))
	}
	got := findingChecks(recs[0].Findings)
	if !got["ipmi.smc.integrityBypass"] {
		t.Errorf("fixed-key RAKP-2 on a confirmed X14 board did not produce ipmi.smc.integrityBypass (got %v)", keys(got))
	}
	if got["ipmi.v20.smcrakpBypass"] {
		t.Errorf("fixed-key RAKP-2 on a confirmed X14 board wrongly got the command-capable ipmi.v20.smcrakpBypass upgrade (got %v)", keys(got))
	}
}

// TestConvertSMCRAKPX14ViaRandomSessionIDs covers the session-ID entropy
// signal standing in for a board SKU or GUID code: a Supermicro host with no
// resolvable board identity, but whose captured RMCP+ session IDs are
// well-distributed (X14's OpenBMC-style RNG, not the ATEN fixed +0x10 step),
// is treated as a confirmed X14 and stays at ipmi.smc.integrityBypass.
func TestConvertSMCRAKPX14ViaRandomSessionIDs(t *testing.T) {
	r := &ipmi.RAKPResult{
		Username:   "ADMIN",
		AuthAlgo:   ipmi.RAKPHMACSHA1,
		ClientSID:  0x11223344,
		BMCSID:     0x55667788,
		ClientRand: repeat(0x11, 16),
		BMCRand:    repeat(0x22, 16),
		BMCGUID:    repeat(0x33, 16),
	}
	mac := hmac.New(sha1.New, smcRAKPFixedKey)
	mac.Write(r.Salt())
	entry := "ADMIN:1$" + hex.EncodeToString(r.Salt()) + ":" + hex.EncodeToString(mac.Sum(nil))

	line := `{"asset":{"type":"BMC","hw_vendor":"Super Micro Computer","addresses":["192.0.2.64"]},` +
		`"services":[{"port":623,"transport":"udp","protocols":["ipmi"],"service_data":{` +
		`"ipmi.rakp.hashes":` + jsonString(entry) + `,` +
		`"ipmi.rakp.sessionIDs":"c6562d24 3ad4440a 90345216 961bc815 26828b32 c4acbc21 c34d381b 09ebb63f 3bbe8136"}}]}`

	recs := convertToRecords(t, FormatRZSQL, writeLines(t, "smcrakprandsid.jsonl", line))
	if len(recs) != 1 {
		t.Fatalf("records = %d, want 1", len(recs))
	}
	got := findingChecks(recs[0].Findings)
	if !got["ipmi.smc.integrityBypass"] {
		t.Errorf("fixed-key RAKP-2 with well-distributed session IDs did not produce ipmi.smc.integrityBypass (got %v)", keys(got))
	}
	if got["ipmi.v20.smcrakpBypass"] {
		t.Errorf("fixed-key RAKP-2 with well-distributed (X14-signature) session IDs wrongly got the command-capable ipmi.v20.smcrakpBypass upgrade (got %v)", keys(got))
	}
}

// TestConvertSMCRAKPPreX14ViaFixedStepSessionIDs covers the contrasting
// signature: a Supermicro host with no resolvable board identity, whose
// captured RMCP+ session IDs advance by the ATEN stack's fixed +0x10 step,
// still gets the command-capable ipmi.v20.smcrakpBypass upgrade.
func TestConvertSMCRAKPPreX14ViaFixedStepSessionIDs(t *testing.T) {
	r := &ipmi.RAKPResult{
		Username:   "ADMIN",
		AuthAlgo:   ipmi.RAKPHMACSHA1,
		ClientSID:  0x11223344,
		BMCSID:     0x55667788,
		ClientRand: repeat(0x11, 16),
		BMCRand:    repeat(0x22, 16),
		BMCGUID:    repeat(0x33, 16),
	}
	mac := hmac.New(sha1.New, smcRAKPFixedKey)
	mac.Write(r.Salt())
	entry := "ADMIN:1$" + hex.EncodeToString(r.Salt()) + ":" + hex.EncodeToString(mac.Sum(nil))

	// SIDs 0x1000, 0x1010, 0x1020, 0x1030 (LE-encoded) -- a constant +0x10 step.
	line := `{"asset":{"type":"BMC","hw_vendor":"Super Micro Computer","addresses":["192.0.2.65"]},` +
		`"services":[{"port":623,"transport":"udp","protocols":["ipmi"],"service_data":{` +
		`"ipmi.rakp.hashes":` + jsonString(entry) + `,` +
		`"ipmi.rakp.sessionIDs":"00100000 10100000 20100000 30100000"}}]}`

	recs := convertToRecords(t, FormatRZSQL, writeLines(t, "smcrakpfixedstepsid.jsonl", line))
	if len(recs) != 1 {
		t.Fatalf("records = %d, want 1", len(recs))
	}
	got := findingChecks(recs[0].Findings)
	if !got["ipmi.v20.smcrakpBypass"] {
		t.Errorf("fixed-key RAKP-2 with a +0x10-step session ID (ATEN signature) did not produce ipmi.v20.smcrakpBypass (got %v)", keys(got))
	}
	if got["ipmi.smc.integrityBypass"] {
		t.Errorf("fixed-key RAKP-2 with a +0x10-step (confirmed pre-X14) session ID wrongly stayed at ipmi.smc.integrityBypass (got %v)", keys(got))
	}
}

// TestConvertILOIPMIBypassAndKnownCVE covers the two generation/version-gated
// iLO4 detections: the RAKP-none IPMI auth bypass (all iLO2/3/4 firmware) and
// the version-gated known CVEs (CVE-2017-12542 among them, for iLO4 firmware
// below 2.53). iLO4/2.40 is old enough to also be affected by several later
// iLO4 CVEs (2018-7078, 2018-7105, 2020-7202, 2023-28083), so more than one
// CVE is expected to be projected.
func TestConvertILOIPMIBypassAndKnownCVE(t *testing.T) {
	// iLO4, firmware 2.40 (< 2.53), with a reachable IPMI channel and a web port
	// whose Server header names the generation and firmware.
	line := `{"asset":{"type":"BMC","hw_vendor":"HPE","hw_product":"Integrated Lights-Out 4","addresses":["192.0.2.61"]},` +
		`"services":[` +
		`{"port":623,"transport":"udp","protocols":["ipmi"],"service_data":{"ipmi.connVersions":"ipmi-2.0"}},` +
		`{"port":443,"transport":"tcp","protocols":["http"],"service_data":{"http.head.server":"HP-iLO-4/2.40"}}` +
		`]}`

	recs := convertToRecords(t, FormatRZSQL, writeLines(t, "ilo4.jsonl", line))
	if len(recs) != 1 {
		t.Fatalf("records = %d, want 1", len(recs))
	}
	got := findingChecks(recs[0].Findings)
	if !got["ipmi.ilo.rakpNoneBypass"] {
		t.Errorf("iLO4 + IPMI did not produce ipmi.ilo.rakpNoneBypass (got %v)", keys(got))
	}
	if !got["http.ilo.knownCVEs"] {
		t.Errorf("iLO4/2.40 did not produce http.ilo.knownCVEs (got %v)", keys(got))
	}
	// CVE-2017-12542 must be among the projected CVEs.
	cves := map[string]bool{}
	for _, f := range recs[0].Findings {
		if f.Check == "http.ilo.knownCVEs" {
			cves[findingField(f, "cve")] = true
		}
	}
	if !cves["CVE-2017-12542"] {
		t.Errorf("knownCVEs cves = %v, want CVE-2017-12542 among them", cves)
	}
	// Every derived finding must name the observation it came from.
	for _, f := range recs[0].Findings {
		if findingField(f, "proof") == "" {
			t.Errorf("derived finding %q carries no proof", f.Check)
		}
	}
}

// TestConvertILO4FirmwareAtFixDoesNotFlagCVE checks the version gate: an iLO4
// at CVE-2017-12542's fix (2.53) still gets the generation-wide IPMI bypass
// and is still flagged for later iLO4 CVEs fixed above 2.53, but an iLO4
// beyond every fixed iLO4 band (2.90, past CVE-2023-28083's 2.82) is flagged
// only for the 2026 CVEs HPE never fixed on iLO4.
func TestConvertILO4FirmwareAtFixDoesNotFlagCVE(t *testing.T) {
	line := `{"asset":{"type":"BMC","hw_vendor":"HPE","hw_product":"Integrated Lights-Out 4","addresses":["192.0.2.62"]},` +
		`"services":[` +
		`{"port":623,"transport":"udp","protocols":["ipmi"],"service_data":{"ipmi.connVersions":"ipmi-2.0"}},` +
		`{"port":443,"transport":"tcp","protocols":["http"],"service_data":{"http.head.server":"HP-iLO-4/2.90"}}` +
		`]}`

	recs := convertToRecords(t, FormatRZSQL, writeLines(t, "ilo4fixed.jsonl", line))
	got := findingChecks(recs[0].Findings)
	if !got["ipmi.ilo.rakpNoneBypass"] {
		t.Errorf("iLO4 IPMI bypass is firmware-independent and should still fire (got %v)", keys(got))
	}
	want := []string{"CVE-2026-65204", "CVE-2026-65205", "CVE-2026-65206", "CVE-2026-65207", "CVE-2026-65209"}
	if cves := knownILOCVEs(recs[0].Findings); !slices.Equal(cves, want) {
		t.Errorf("iLO4 at firmware 2.90 flagged %v, want only the unfixed %v", cves, want)
	}
}

// TestConvertILOSSHOverflow covers the mpSSH overflow rule: an iLO5
// running mpSSH is flagged (pre-iLO6), and because it is iLO5 the iLO2/3/4-only
// IPMI bypass is not emitted.
func TestConvertILOSSHOverflow(t *testing.T) {
	line := `{"asset":{"type":"BMC","hw_vendor":"HPE","hw_product":"Integrated Lights-Out 5","addresses":["192.0.2.63"]},` +
		`"services":[` +
		`{"port":22,"transport":"tcp","protocols":["ssh"],"service_data":{"banner.ssh":"SSH-2.0-mpSSH_0.2.1"}},` +
		`{"port":623,"transport":"udp","protocols":["ipmi"],"service_data":{"ipmi.connVersions":"ipmi-2.0"}}` +
		`]}`

	recs := convertToRecords(t, FormatRZSQL, writeLines(t, "ilo5ssh.jsonl", line))
	got := findingChecks(recs[0].Findings)
	if !got["ssh.hpe.iloSSHOverflow"] {
		t.Errorf("iLO5 mpSSH did not produce ssh.hpe.iloSSHOverflow (got %v)", keys(got))
	}
	if got["ipmi.ilo.rakpNoneBypass"] {
		t.Error("iLO5 wrongly flagged the iLO2/3/4-only IPMI auth bypass")
	}
}

// TestConvertILO6SSHNotFlagged checks the generation ceiling: iLO6 changed the
// SSH stack, so an mpSSH banner on iLO6 must not be flagged as the overflow.
func TestConvertILO6SSHNotFlagged(t *testing.T) {
	line := `{"asset":{"type":"BMC","hw_vendor":"HPE","hw_product":"Integrated Lights-Out 6","addresses":["192.0.2.64"]},` +
		`"services":[{"port":22,"transport":"tcp","protocols":["ssh"],"service_data":{"banner.ssh":"SSH-2.0-mpSSH_0.3.0"}}]}`

	recs := convertToRecords(t, FormatRZSQL, writeLines(t, "ilo6ssh.jsonl", line))
	if findingChecks(recs[0].Findings)["ssh.hpe.iloSSHOverflow"] {
		t.Error("iLO6 mpSSH wrongly flagged the pre-iLO6 SSH overflow")
	}
}

// TestConvertUnknownGenNoILOFindings checks the honesty gate: an mpSSH banner
// with no way to place the generation (a bare model, no iLO Server header) must
// attribute nothing -- we cannot rule out iLO6, so we stay silent.
func TestConvertUnknownGenNoILOFindings(t *testing.T) {
	line := `{"asset":{"type":"BMC","hw_product":"ProLiant DL380","addresses":["192.0.2.65"]},` +
		`"services":[` +
		`{"port":22,"transport":"tcp","protocols":["ssh"],"service_data":{"banner.ssh":"SSH-2.0-mpSSH_0.2.1"}},` +
		`{"port":623,"transport":"udp","protocols":["ipmi"],"service_data":{"ipmi.connVersions":"ipmi-2.0"}}` +
		`]}`

	recs := convertToRecords(t, FormatRZSQL, writeLines(t, "unknowngen.jsonl", line))
	got := findingChecks(recs[0].Findings)
	for _, c := range []string{"ssh.hpe.iloSSHOverflow", "ipmi.ilo.rakpNoneBypass", "http.ilo.knownCVEs"} {
		if got[c] {
			t.Errorf("unknown-generation host wrongly emitted %q", c)
		}
	}
}

// TestConvertOpenBMCBypass covers the fingerprint-based OpenBMC projection: a
// host runZero typed as OpenBMC with an IPMI 2.0 channel must convert into the
// phosphor-net-ipmid default-userKey auth bypass, and a non-OpenBMC IPMI host
// must not.
func TestConvertOpenBMCBypass(t *testing.T) {
	openbmc := `{"asset":{"type":"BMC","os":"OpenBMC","os_vendor":"OpenBMC","hw_vendor":"OpenBMC","addresses":["192.0.2.70"]},` +
		`"services":[{"port":623,"transport":"udp","protocols":["ipmi"],` +
		`"service_data":{"ipmi.connVersions":"ipmi-2.0","ipmi.ciphers":"17\t3"}}]}`
	recs := convertToRecords(t, FormatRZSQL, writeLines(t, "openbmc.jsonl", openbmc))
	if !findingChecks(recs[0].Findings)["ipmi.openbmc.defaultUserKeyAuthBypass"] {
		t.Errorf("OpenBMC + IPMI 2.0 did not produce the default-userKey bypass (got %v)", keys(findingChecks(recs[0].Findings)))
	}

	// A Supermicro IPMI host (not OpenBMC) must not get the OpenBMC finding.
	smc := `{"asset":{"type":"BMC","hw_vendor":"Super Micro","addresses":["192.0.2.71"]},` +
		`"services":[{"port":623,"transport":"udp","protocols":["ipmi"],` +
		`"service_data":{"ipmi.connVersions":"ipmi-2.0"}}]}`
	recs = convertToRecords(t, FormatRZSQL, writeLines(t, "notopenbmc.jsonl", smc))
	if findingChecks(recs[0].Findings)["ipmi.openbmc.defaultUserKeyAuthBypass"] {
		t.Error("non-OpenBMC host wrongly flagged the OpenBMC bypass")
	}
}

// TestConvertWeakSessionID covers the predictable-session-ID projection: a
// Supermicro host whose captured RMCP+ session IDs are confined to a tiny window
// of the 32-bit space is flagged critical, while a host whose session IDs are
// well-distributed is not flagged.
func TestConvertWeakSessionID(t *testing.T) {
	// The nine managed SIDs from a real Supermicro capture: top bytes fixed, only
	// the low byte varies -> a <256 window.
	weak := `{"asset":{"type":"BMC","hw_vendor":"Super Micro","addresses":["192.0.2.72"]},` +
		`"services":[{"port":623,"transport":"udp","protocols":["ipmi"],"service_data":{` +
		`"ipmi.connVersions":"ipmi-2.0",` +
		`"ipmi.rakp.sessionIDs":"73181c00 b3171c00 d3171c00 53181c00 83171c00 93171c00 c3171c00 f3171c00 33181c00"}}]}`
	recs := convertToRecords(t, FormatRZSQL, writeLines(t, "weaksid.jsonl", weak))
	var sidRisk string
	var sidCheck string
	for _, f := range recs[0].Findings {
		if f.Check == "ipmi.sidEntropy" || f.Check == "ipmi.sidPredictable" {
			sidCheck, sidRisk = f.Check, f.Risk
		}
	}
	if sidCheck != "ipmi.sidPredictable" {
		t.Errorf("weak Supermicro session IDs did not produce ipmi.sidPredictable (got %q, all %v)", sidCheck, keys(findingChecks(recs[0].Findings)))
	}
	if sidRisk != "critical" {
		t.Errorf("Supermicro weak-SID risk = %q, want critical", sidRisk)
	}

	// Well-distributed 32-bit session IDs (an OpenBMC-style RNG) must not flag.
	strong := `{"asset":{"type":"BMC","hw_vendor":"OpenBMC","os_vendor":"OpenBMC","addresses":["192.0.2.73"]},` +
		`"services":[{"port":623,"transport":"udp","protocols":["ipmi"],"service_data":{` +
		`"ipmi.connVersions":"ipmi-2.0",` +
		`"ipmi.rakp.sessionIDs":"c6562d24 3ad4440a 90345216 961bc815 26828b32 c4acbc21 c34d381b 09ebb63f 3bbe8136"}}]}`
	recs = convertToRecords(t, FormatRZSQL, writeLines(t, "strongsid.jsonl", strong))
	got := findingChecks(recs[0].Findings)
	if got["ipmi.sidEntropy"] || got["ipmi.sidPredictable"] {
		t.Error("well-distributed session IDs were wrongly flagged as weak")
	}
}

// TestConvertILOFromDedicatedFields checks that the generation and firmware come
// off the dedicated ilo.* fields runZero parses from the RIMP document (an iLO5
// on port 443 with no HP-iLO Server header), and that an iLO5 mpSSH host is
// flagged for the SSH overflow but not the iLO4-only IPMI bypass.
func TestConvertILOFromDedicatedFields(t *testing.T) {
	line := `{"asset":{"type":"BMC","os":"HPE iLO 5","os_product":"iLO 5 Firmware","os_version":"3.08","hw_vendor":"HPE","hw_product":"Synergy 480 Gen10","addresses":["192.0.2.74"]},` +
		`"services":[` +
		`{"port":22,"transport":"tcp","protocols":["ssh"],"service_data":{"banner":"SSH-2.0-mpSSH_0.2.1"}},` +
		`{"port":443,"transport":"tcp","protocols":["http","tls"],"service_data":{"ilo.mp.pn":"Integrated Lights-Out 5 (iLO 5)","ilo.mp.fwri":"3.08"}}` +
		`]}`
	recs := convertToRecords(t, FormatRZSQL, writeLines(t, "ilofields.jsonl", line))
	got := findingChecks(recs[0].Findings)
	if !got["ssh.hpe.iloSSHOverflow"] {
		t.Errorf("iLO5 mpSSH (dedicated fields) did not produce the SSH overflow (got %v)", keys(got))
	}
	if got["ipmi.ilo.rakpNoneBypass"] {
		t.Error("iLO5 wrongly flagged the iLO2/3/4-only IPMI bypass")
	}
	// iLO5 at 3.08 is past every pre-2026 fix but below hpesbhf05170's 3.22.
	want := []string{"CVE-2026-65204", "CVE-2026-65205", "CVE-2026-65206", "CVE-2026-65207", "CVE-2026-65208", "CVE-2026-65209"}
	if cves := knownILOCVEs(recs[0].Findings); !slices.Equal(cves, want) {
		t.Errorf("iLO5/3.08 flagged %v, want %v", cves, want)
	}
}

// knownILOCVEs returns the sorted CVE ids of the http.ilo.knownCVEs findings.
func knownILOCVEs(fs []engine.Finding) []string {
	var out []string
	for _, f := range fs {
		if f.Check == "http.ilo.knownCVEs" {
			out = append(out, findingField(f, "cve"))
		}
	}
	slices.Sort(out)
	return out
}

// repeat returns a byte slice of n copies of b.
func repeat(b byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}
