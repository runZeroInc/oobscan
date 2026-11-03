package redfish

import (
	"bytes"
	"encoding/json"
	"strings"
	"time"
)

// Intel Server Board BMC 2.94 is an AMI MegaRAC SPX "legacybmc" fork that ships
// identically on the M50CYP and D50TNP boards, and a firmware audit confirmed four
// post-auth Redfish/CGI session weaknesses in this image (see
// intelBMC294Advisories below).
//
// This file is fingerprint-only and non-destructive: FetchIntelBMC294 issues one
// GET to /redfish/v1/ and reads the advertised firmware version plus Intel OEM
// markers. It must not authenticate, POST, or exercise any of the weaknesses; it
// only version-gates an advisory for them.

const (
	// intelBMC294Version is the firmware version string advertised by the audited
	// 2.94 image. It is specific enough on its own to attribute the build.
	intelBMC294Version = "2.94.195893f7"
	// intelBMC294BuildTag is the distinctive build-tag fragment for the 2.94
	// Whitley/CAN5 QSBR release.
	intelBMC294BuildTag = "wht-can5"
)

// intelOEMActionMarkers are the lower-cased Intel OEM action names the 2.94
// service root advertises. Their presence corroborates an Intel MegaRAC image.
var intelOEMActionMarkers = []string{
	"intel.oem.updatebmc",
	"intel.oem.updatebios",
	"intel.oem.putfiletoimage",
}

// IntelBMC294Advisory describes one confirmed post-auth session weakness in the
// Intel BMC 2.94 image. These are advisory only: version-gated to the detected
// firmware and requiring an authenticated session to exploit. This package must
// not exercise them; it only reports that the detected build carries them.
type IntelBMC294Advisory struct {
	ID          string // stable short identifier
	Severity    string // "info" -- advisory; post-auth, low real-world severity
	Location    string // firmware source reference (Ghidra decompile file:line)
	Description string // one-line summary of the weakness
}

// intelBMC294Advisories enumerates the four confirmed post-auth weaknesses. They
// are emitted only when FetchIntelBMC294 positively identifies the 2.94 build.
var intelBMC294Advisories = []IntelBMC294Advisory{
	{
		ID:          "redfish-session-db-toctou",
		Severity:    "info",
		Location:    "libredfish.so.c:7333 (redfishSession_dbLoad/dbSave)",
		Description: "Redfish session DB (/tmp/session.db) is read/rewritten whole with no flock in both verifyAuthentication and the SessionService login handler; concurrent requests corrupt/lose/duplicate/resurrect session slots.",
	},
	{
		ID:          "redfish-stale-privilege-cache",
		Severity:    "info",
		Location:    "libredfish.so.c:7453 (login handler)",
		Description: "Username+privilege are copied into the session slot at login and never re-validated; demoting/disabling an account leaves its live sessions fully privileged until idle timeout.",
	},
	{
		ID:          "redfish-session-delete-prefix",
		Severity:    "info",
		Location:    "libredfish.so.c:33885 (FUN_00055954)",
		Description: "DELETE /redfish/v1/SessionService/Sessions/{id} authorizes a non-admin by strncmp of the target owner name bounded by the requester name length, so a user can delete the session of any user whose name is a prefix of theirs (e.g. admin2 -> admin).",
	},
	{
		ID:          "csrf-session-id-weak-rng-fallback",
		Severity:    "info",
		Location:    "libcgi.so.c:6063 (generateCSRFToekn)",
		Description: "generateCSRFToekn ignores the return value of mci_get_rnd_id and returns success unconditionally; if the intra-BMC MCI RNG pipe fails, the 32-byte CSRF token / session id is uninitialized/stale stack memory (predictable).",
	},
}

// IntelBMC294Info captures the unauthenticated Redfish service-root signals that
// identify an Intel Server Board BMC 2.94 unit.
type IntelBMC294Info struct {
	Status          int
	Reachable       bool   // service root answered (2xx, or auth-gated 401/403)
	ServerHeader    string // Server response header (lighttpd on this image)
	IsIntel         bool   // Intel OEM / vendor markers present in the service root
	HasIntelOEM     bool   // Intel.Oem.UpdateBMC/UpdateBIOS/PutFileToImage advertised
	FirmwareVersion string // advertised firmware version, when readable (e.g. 2.94.195893f7)
	BuildTag        string // advertised build tag, when readable (contains wht-can5)
	IsBMC294        bool   // firmware version and/or build tag confirm the audited 2.94 image
}

// Advisories returns the version-gated post-auth weakness advisories for this
// host, or nil when the target is not a confirmed Intel BMC 2.94 unit. The
// advisories are INFO/advisory only and are never exercised by this package.
func (i IntelBMC294Info) Advisories() []IntelBMC294Advisory {
	if !i.IsBMC294 {
		return nil
	}
	return intelBMC294Advisories
}

// FetchIntelBMC294 GETs /redfish/v1/ and reports the Intel BMC 2.94 fingerprint
// signals above. It sends only a GET; it does not authenticate, does not POST,
// and does not touch any of the four post-auth weaknesses.
func FetchIntelBMC294(host string, port int, timeout time.Duration) IntelBMC294Info {
	client := insecureClient(nil, timeout)
	url := baseURL(host, port) + "/redfish/v1/"
	st, body, hdr, err := httpGet(client, url, timeout)
	if err != nil {
		return IntelBMC294Info{}
	}
	info := IntelBMC294Info{Status: st}
	if hdr != nil {
		info.ServerHeader = hdr.Get("Server")
	}
	// A 2xx lets us read the identity fields; 401/403 still proves the service
	// root exists (some hardened builds gate it), which is Reachable but yields no
	// readable version signal.
	switch st {
	case 200, 401, 403:
		info.Reachable = true
	}
	if st != 200 || len(body) == 0 {
		return info
	}
	analyzeIntelBMC294(body, &info)
	return info
}

// analyzeIntelBMC294 reads the version/OEM signals out of a service-root body and
// fills the detection fields. Split out from FetchIntelBMC294 so the attribution
// logic is unit-testable without a live BMC.
func analyzeIntelBMC294(body []byte, info *IntelBMC294Info) {
	low := bytes.ToLower(body)

	// Intel attribution: the Oem extension key (parsed via the shared ServiceRoot
	// helper) is the most reliable signal; corroborate with the Intel OEM action
	// markers and the self-signed leaf's "Intel Corporation" org string that some
	// builds echo into the body.
	var sr ServiceRoot
	if json.Unmarshal(body, &sr) == nil {
		if v, _ := sr.OemVendor(); v == "intel" {
			info.IsIntel = true
		}
	}
	for _, m := range intelOEMActionMarkers {
		if bytes.Contains(low, []byte(m)) {
			info.HasIntelOEM = true
			info.IsIntel = true
			break
		}
	}
	if !info.IsIntel && (bytes.Contains(low, []byte("intel corporation")) || bytes.Contains(low, []byte("\"intel\""))) {
		info.IsIntel = true
	}

	// Recover the advertised firmware version + build tag when present. The 2.94
	// image reports FirmwareVersion in its Intel OEM block; the build tag carries
	// the wht-can5 fragment.
	if fw := extractJSONStringField(body, "FirmwareVersion"); fw != "" {
		info.FirmwareVersion = fw
	} else if bytes.Contains(low, []byte(intelBMC294Version)) {
		info.FirmwareVersion = intelBMC294Version
	}
	if bt := extractQuotedContaining(body, intelBMC294BuildTag); bt != "" {
		info.BuildTag = bt
	}

	// Confirm the audited 2.94 build. The full version string is specific enough
	// on its own; otherwise require the Intel attribution plus the build-tag
	// fragment so a generic AMI box is never mislabeled.
	switch {
	case strings.Contains(info.FirmwareVersion, intelBMC294Version):
		info.IsBMC294 = true
	case bytes.Contains(low, []byte(intelBMC294Version)):
		info.IsBMC294 = true
	case info.IsIntel && strings.Contains(strings.ToLower(info.BuildTag), intelBMC294BuildTag):
		info.IsBMC294 = true
	case info.IsIntel && bytes.Contains(low, []byte(intelBMC294BuildTag)):
		info.IsBMC294 = true
	}
}

// extractJSONStringField returns the string value of the first `"key":"value"`
// pair found in body, or "" when the key is absent or not a plain string. It is
// a tolerant scan (the field may be nested inside an Oem sub-block), not a full
// JSON walk.
func extractJSONStringField(body []byte, key string) string {
	needle := []byte("\"" + key + "\"")
	_, after, ok := bytes.Cut(body, needle)
	if !ok {
		return ""
	}
	rest := after
	// Skip whitespace and the colon.
	j := 0
	for j < len(rest) && (rest[j] == ' ' || rest[j] == '\t' || rest[j] == '\n' || rest[j] == '\r' || rest[j] == ':') {
		j++
	}
	if j >= len(rest) || rest[j] != '"' {
		return "" // not a string value
	}
	rest = rest[j+1:]
	before, _, ok := bytes.Cut(rest, []byte{'"'})
	if !ok {
		return ""
	}
	return string(before)
}

// extractQuotedContaining returns the full double-quoted JSON string token that
// contains substr (case-insensitive), or "" when substr is absent or not inside
// a quoted token. Used to recover the complete build-tag string from the wht-can5
// fragment.
func extractQuotedContaining(body []byte, substr string) string {
	low := bytes.ToLower(body)
	idx := bytes.Index(low, []byte(strings.ToLower(substr)))
	if idx < 0 {
		return ""
	}
	// Walk back to the opening quote.
	start := idx
	for start > 0 && body[start-1] != '"' {
		start--
	}
	if start == 0 || body[start-1] != '"' {
		return ""
	}
	// Walk forward to the closing quote.
	rest := body[idx:]
	off := bytes.IndexByte(rest, '"')
	if off < 0 {
		return ""
	}
	return string(body[start : idx+off])
}
