// Package ssh consumes sshamble scan output (JSONL) and emits OOB/BMC
// fingerprints. It is input-only: oobscan never re-implements SSH auth --
// sshamble already does it better. This module turns sshamble's per-host
// records into entries in the oobscan pipeline, keyed off the vendor slugs
// from pkg/oob.
package ssh

import (
	"bufio"
	"encoding/json"
	"io"
	"os"
	"strings"
)

// SshambleRecord is a subset of sshamble's JSON schema (only the fields we
// need). sshamble emits one record per host; we parse only what we consume.
type SshambleRecord struct {
	Host        string   `json:"host"`
	Port        int      `json:"port"`
	Banner      string   `json:"banner"`
	KeyTypes    []string `json:"key_types"`
	HostKeys    []string `json:"host_keys"`
	AuthMethods []string `json:"auth_methods"`
	ServerVer   string   `json:"server_version"`
	Checks      []struct {
		Name    string `json:"name"`
		Result  string `json:"result"`
		Message string `json:"message"`
	} `json:"checks"`
}

// BMCHit is an enriched record ready for oobscan's JSONL stream.
type BMCHit struct {
	Host        string
	Port        int
	Vendor      string
	Product     string
	Banner      string
	ServerVer   string
	AuthMethods []string
	HostKeys    []string
	Evidence    []string
	// Risk tags derived from the banner (e.g. "ipmi-sol", "legacy-cipher").
	Tags []string
}

// ImportFile reads a sshamble JSONL file and returns only records that look
// like BMCs / OOB appliances.
func ImportFile(path string) ([]BMCHit, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return ImportReader(f)
}

// ImportReader parses sshamble JSONL from any io.Reader.
func ImportReader(r io.Reader) ([]BMCHit, error) {
	var out []BMCHit
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || line[0] != '{' {
			continue
		}
		var rec SshambleRecord
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			continue
		}
		hit, ok := classify(rec)
		if ok {
			out = append(out, hit)
		}
	}
	return out, sc.Err()
}

// classify looks at banner / server version and assigns a vendor/product.
// The mapping table is deliberately conservative: only strong matches.
func classify(r SshambleRecord) (BMCHit, bool) {
	banner := strings.ToLower(r.Banner + " " + r.ServerVer)
	h := BMCHit{
		Host:        r.Host,
		Port:        r.Port,
		Banner:      r.Banner,
		ServerVer:   r.ServerVer,
		AuthMethods: r.AuthMethods,
		HostKeys:    r.HostKeys,
	}

	switch {
	case strings.Contains(banner, "hpilo") || strings.Contains(banner, "ilo "):
		h.Vendor, h.Product = "hpe", "iLO"
	case strings.Contains(banner, "drac") || strings.Contains(banner, "idrac"):
		h.Vendor, h.Product = "dell", "iDRAC"
	case strings.Contains(banner, "atenkvm") || strings.Contains(banner, "smcipmitool") || strings.Contains(banner, "supermicro"):
		h.Vendor, h.Product = "supermicro", "ATEN"
	case strings.Contains(banner, "megarac") || strings.Contains(banner, "smash-clp"):
		h.Vendor, h.Product = "ami", "MegaRAC"
	case strings.Contains(banner, "xclarity") || strings.Contains(banner, "lenovo"):
		h.Vendor, h.Product = "lenovo", "XCC"
	case strings.Contains(banner, "cimc") || strings.Contains(banner, "cisco"):
		h.Vendor, h.Product = "cisco", "CIMC"
	case strings.Contains(banner, "irmc") || strings.Contains(banner, "fujitsu"):
		h.Vendor, h.Product = "fujitsu", "iRMC"
	case strings.Contains(banner, "avocent") || strings.Contains(banner, "dsview"):
		h.Vendor, h.Product = "avocent", "Console"
	case strings.Contains(banner, "raritan") || strings.Contains(banner, "dominion"):
		h.Vendor, h.Product = "raritan", "Dominion"
	case strings.Contains(banner, "lantronix") || strings.Contains(banner, "slc-"):
		h.Vendor, h.Product = "lantronix", "SLC"
	case strings.Contains(banner, "moxa"):
		h.Vendor, h.Product = "moxa", "NPort"
	case strings.Contains(banner, "opengear"):
		h.Vendor, h.Product = "opengear", "Console"
	case strings.Contains(banner, "digi"):
		h.Vendor, h.Product = "digi", "PortServer"
	case strings.Contains(banner, "netbotz") || strings.Contains(banner, "apc"):
		h.Vendor, h.Product = "apc", "NMC"
	case strings.Contains(banner, "openbmc") || strings.Contains(banner, "phosphor"):
		h.Vendor, h.Product = "openbmc", "phosphor"
	case strings.Contains(banner, "ilom") || strings.Contains(banner, "sun-ilom"):
		h.Vendor, h.Product = "oracle", "ILOM"
	default:
		return h, false
	}

	// Heuristic risk tags.
	if strings.Contains(banner, "dropbear") && strings.Contains(banner, "0.") {
		h.Tags = append(h.Tags, "legacy-dropbear")
	}
	if strings.Contains(banner, "openssh_5.") || strings.Contains(banner, "openssh_4.") {
		h.Tags = append(h.Tags, "ancient-openssh")
	}
	for _, m := range r.AuthMethods {
		if m == "password" {
			h.Tags = append(h.Tags, "password-auth")
		}
		if m == "keyboard-interactive" {
			h.Tags = append(h.Tags, "ki-auth")
		}
	}
	h.Evidence = append(h.Evidence, "sshamble:"+r.Banner)
	return h, true
}
