package ipmi

import "bytes"

// Legacy deployment artifacts retained only so smc-uninstall can remove old
// installations.
const (
	SMCTailnetBinName        = "phase2d.conf"
	SMCTailnetConfName       = "oobtsnet.conf"
	SMCX9CarrierName         = "def_hostname"
	smcTailnetLauncherMarker = "# --- oobscan smtsnet: direct oobtsnet service ---"
	smcTailnetLegacyMarker   = "# --- oobscan smtsnet: phase-2 bootstrap service ---"
)

func StripSMCTailnetLauncher(current []byte) (out []byte, ok bool) {
	i := bytes.Index(current, []byte(smcTailnetLauncherMarker))
	legacy := bytes.Index(current, []byte(smcTailnetLegacyMarker))
	if i < 0 || (legacy >= 0 && legacy < i) {
		i = legacy
	}
	if i < 0 {
		return current, false
	}
	out = bytes.TrimRight(current[:i], "\n")
	return append(out, '\n'), true
}

func StripSMCDebugShellLauncher(current []byte) (out []byte, ok bool) {
	i := smcShellLauncherIndex(current)
	if i < 0 {
		return current, false
	}
	out = bytes.TrimRight(current[:i], "\n")
	return append(out, '\n'), true
}
