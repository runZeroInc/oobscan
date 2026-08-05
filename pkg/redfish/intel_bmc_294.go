package redfish

import (
	"bytes"
	"encoding/json"
	"strings"
	"time"
)

const (
	intelBMC294Version = "2.94.195893f7"

	intelBMC294BuildTag = "wht-can5"
)

var intelOEMActionMarkers = []string{
	"intel.oem.updatebmc",
	"intel.oem.updatebios",
	"intel.oem.putfiletoimage",
}

type IntelBMC294Advisory struct {
	ID          string
	Severity    string
	Location    string
	Description string
}

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

type IntelBMC294Info struct {
	Status          int
	Reachable       bool
	ServerHeader    string
	IsIntel         bool
	HasIntelOEM     bool
	FirmwareVersion string
	BuildTag        string
	IsBMC294        bool
}

func (i IntelBMC294Info) Advisories() []IntelBMC294Advisory {
	if !i.IsBMC294 {
		return nil
	}
	return intelBMC294Advisories
}

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

func analyzeIntelBMC294(body []byte, info *IntelBMC294Info) {
	low := bytes.ToLower(body)

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

	if fw := extractJSONStringField(body, "FirmwareVersion"); fw != "" {
		info.FirmwareVersion = fw
	} else if bytes.Contains(low, []byte(intelBMC294Version)) {
		info.FirmwareVersion = intelBMC294Version
	}
	if bt := extractQuotedContaining(body, intelBMC294BuildTag); bt != "" {
		info.BuildTag = bt
	}

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

func extractJSONStringField(body []byte, key string) string {
	needle := []byte("\"" + key + "\"")
	_, after, ok := bytes.Cut(body, needle)
	if !ok {
		return ""
	}
	rest := after

	j := 0
	for j < len(rest) && (rest[j] == ' ' || rest[j] == '\t' || rest[j] == '\n' || rest[j] == '\r' || rest[j] == ':') {
		j++
	}
	if j >= len(rest) || rest[j] != '"' {
		return ""
	}
	rest = rest[j+1:]
	before, _, ok := bytes.Cut(rest, []byte{'"'})
	if !ok {
		return ""
	}
	return string(before)
}

func extractQuotedContaining(body []byte, substr string) string {
	low := bytes.ToLower(body)
	idx := bytes.Index(low, []byte(strings.ToLower(substr)))
	if idx < 0 {
		return ""
	}

	start := idx
	for start > 0 && body[start-1] != '"' {
		start--
	}
	if start == 0 || body[start-1] != '"' {
		return ""
	}

	rest := body[idx:]
	off := bytes.IndexByte(rest, '"')
	if off < 0 {
		return ""
	}
	return string(body[start : idx+off])
}
