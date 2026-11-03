package ilo

import (
	"context"
	"encoding/xml"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/runZeroInc/oobscan/pkg/httpx"
	"github.com/runZeroInc/oobscan/pkg/netaddr"
)

// XMLData is the shape returned by /xmldata?item=all on every iLO (1..6)
// without authentication.
//
// Every field carries an explicit lowerCamel json tag: this struct is
// serialized verbatim into the NDJSON record as `ilo`, and Go would otherwise
// emit Capitalized keys that downstream consumers cannot read. XMLName is
// json:"-" -- it is an xml decoding artifact, not device data.
type XMLData struct {
	XMLName xml.Name `xml:"RIMP" json:"-"`
	HSI     struct {
		SPN   string `xml:"SPN" json:"serverModel,omitempty"`     // "ProLiant DL360 Gen10"
		PN    string `xml:"PRODUCTID" json:"productId,omitempty"` // part number
		SBSN  string `xml:"SBSN" json:"chassisSerial,omitempty"`
		UUID  string `xml:"UUID" json:"uuid,omitempty"`
		CUUID string `xml:"cUUID" json:"chassisUuid,omitempty"`
		// NICS is emitted pre-auth on iLO2..6 and leaks each network port's
		// host/iLO MAC address and configured IP.
		NICS struct {
			NIC []NIC `xml:"NIC" json:"nic,omitempty"`
		} `xml:"NICS" json:"nics,omitzero"`
	} `xml:"HSI" json:"hsi,omitzero"`
	MP struct {
		// ST and PN are the two fields Generation() reads. They are serialized
		// so a generation fall-through ("iLO" with no digit) is diagnosable from
		// the scan output alone instead of requiring a re-scan.
		ST    string `xml:"ST" json:"family,omitempty"`            // mgmt processor family, "8" = iLO5
		PN    string `xml:"PN" json:"product,omitempty"`           // "Integrated Lights-Out 5"
		FWRI  string `xml:"FWRI" json:"firmwareVersion,omitempty"` // e.g. "2.82"
		HWRI  string `xml:"HWRI" json:"hardwareRevision,omitempty"`
		SN    string `xml:"SN" json:"serial,omitempty"` // iLO serial
		UUID  string `xml:"UUID" json:"uuid,omitempty"`
		SSO   string `xml:"SSO" json:"sso,omitempty"`
		LOCFG string `xml:"LOCFG" json:"locfgUrl,omitempty"` // "http://ilo.../perl/locfg.pl"
	} `xml:"MP" json:"mp,omitzero"`
	BladeSystem struct {
		BAY string `xml:"BAY" json:"bay,omitempty"`
		ENC struct {
			Rack string `xml:"RACK,attr" json:"rack,omitempty"`
			SN   string `xml:"SN" json:"serial,omitempty"`
		} `xml:"ENC" json:"enclosure,omitzero"`
	} `xml:"BLADESYSTEM" json:"bladeSystem,omitzero"`
}

// Fetch retrieves /xmldata?item=all from an iLO on the default web ports
// (https/443, then http/80). Callers that already discovered the target's web
// port must use FetchPorts instead: an iLO published only on 8443/4443/8083 is
// invisible to Fetch, and a non-iLO server occupying 443 (a NAT'd router web UI
// in front of a forwarded iLO) hides it too.
func Fetch(client *http.Client, host string) (*XMLData, error) {
	return FetchPorts(client, host, nil, nil)
}

// FetchPorts retrieves /xmldata?item=all, trying each HTTPS candidate port and
// then each plain-HTTP candidate port. Empty port lists reproduce Fetch's
// default of https://host then http://host.
//
// A 200 that parses but carries no iLO generation must not be accepted immediately:
// a generic web server answers /xmldata with 200 and an empty RIMP doc, which would
// mask a real iLO on a later candidate port. Such a doc is held back and returned
// only once every candidate has been tried.
func FetchPorts(client *http.Client, host string, httpsPorts, httpPorts []int) (*XMLData, error) {
	if client == nil {
		client = httpx.Client(10 * time.Second)
	}
	// Bound each request with a context derived from the client's whole-request
	// timeout so a stalled read is cancelled even if the transport is a caller's
	// unhardened one.
	reqTimeout := client.Timeout
	if reqTimeout <= 0 {
		reqTimeout = 10 * time.Second
	}

	type target struct {
		scheme   string
		hostport string
	}
	var targets []target
	for _, p := range httpsPorts {
		targets = append(targets, target{"https", netaddr.URLHostPort(host, p)})
	}
	for _, p := range httpPorts {
		targets = append(targets, target{"http", netaddr.URLHostPort(host, p)})
	}
	if len(targets) == 0 {
		targets = []target{{"https", host}, {"http", host}}
	}

	var fallback *XMLData
	for _, tg := range targets {
		url := tg.scheme + "://" + tg.hostport + "/xmldata?item=all"
		ctx, cancel := context.WithTimeout(context.Background(), reqTimeout)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			cancel()
			return nil, err
		}
		res, err := client.Do(req)
		if err != nil {
			cancel()
			continue
		}
		if res.StatusCode != http.StatusOK {
			res.Body.Close()
			cancel()
			continue
		}
		body, err := io.ReadAll(io.LimitReader(res.Body, 1<<20))
		res.Body.Close()
		cancel()
		if err != nil {
			continue
		}
		var x XMLData
		if err := xml.Unmarshal(body, &x); err != nil {
			continue
		}
		if x.Populated() {
			return &x, nil
		}
		if fallback == nil {
			fallback = &x
		}
	}
	if fallback != nil {
		return fallback, nil
	}
	return nil, errors.New("ilo xmldata: no iLO response")
}

// Populated reports whether the RIMP doc carries real iLO identity rather than
// being an empty <RIMP/> shell.
//
// Generation() is not usable as an emptiness test: it falls back to a bare
// "iLO" for any doc it cannot place, so it never returns "". Callers deciding
// whether a response actually proves an iLO must use this.
func (x *XMLData) Populated() bool {
	for _, v := range []string{x.MP.PN, x.MP.ST, x.MP.FWRI, x.MP.SN, x.HSI.SPN, x.HSI.SBSN} {
		if strings.TrimSpace(v) != "" {
			return true
		}
	}
	return false
}

// Generation returns a short iLO generation label ("iLO4", "iLO5", ...) based
// on the MP/PN string and the ST management-processor family code. It falls
// back to a bare "iLO" and never returns "" -- use Populated to test emptiness.
func (x *XMLData) Generation() string {
	pn := strings.ToLower(x.MP.PN)
	switch {
	case strings.Contains(pn, "lights-out 7"), strings.Contains(pn, "ilo7"):
		return "iLO7"
	case strings.Contains(pn, "lights-out 6"), strings.Contains(pn, "ilo6"):
		return "iLO6"
	case strings.Contains(pn, "lights-out 5"), strings.Contains(pn, "ilo5"):
		return "iLO5"
	case strings.Contains(pn, "lights-out 4"), strings.Contains(pn, "ilo4"):
		return "iLO4"
	case strings.Contains(pn, "lights-out 3"), strings.Contains(pn, "ilo3"):
		return "iLO3"
	case strings.Contains(pn, "lights-out 2"), strings.Contains(pn, "ilo2"):
		return "iLO2"
	}
	switch strings.TrimSpace(x.MP.ST) {
	case "9":
		return "iLO6"
	case "8":
		return "iLO5"
	case "7":
		return "iLO4"
	case "6":
		return "iLO3"
	case "5":
		return "iLO2"
	}
	return "iLO"
}

// GenerationFromString resolves a short iLO generation label ("iLO2".."iLO9") from a
// single free-form identity string: a product name, an HTTP Server header, or an SSH
// banner.
//
// Unlike Generation(), which reads a decoded /xmldata document and falls back to a
// bare "iLO", this returns "" when the string carries no recognizable generation
// token, so a data-only caller can distinguish a known generation from an iLO of
// unknown generation. The gates below depend on that distinction.
//
// Matching is narrow to avoid false positives: a compact "iloN" token, an
// "iLO"/"Lights-Out" token immediately followed by a lone digit, or the
// "lights-out N" phrase. It does not fire on "silo-4" or a bare "out 5".
func GenerationFromString(s string) string {
	toks := strings.FieldsFunc(strings.ToLower(s), func(r rune) bool {
		return !((r >= 'a' && r <= 'z') || (r >= '0' && r <= '9'))
	})
	for i, tok := range toks {
		// Compact "iloN" (iLO4, ilo5).
		if len(tok) == 4 && strings.HasPrefix(tok, "ilo") && tok[3] >= '1' && tok[3] <= '9' {
			return "iLO" + string(tok[3])
		}
		// "ilo" followed by a lone digit ("HP-iLO-4/2.55" -> ilo, 4; "iLO 4").
		if tok == "ilo" && i+1 < len(toks) && isGenDigit(toks[i+1]) {
			return "iLO" + toks[i+1]
		}
		// "lights-out N": the "out" token must be preceded by "lights" so a stray
		// "out 5" cannot masquerade as a generation.
		if tok == "out" && i > 0 && toks[i-1] == "lights" && i+1 < len(toks) && isGenDigit(toks[i+1]) {
			return "iLO" + toks[i+1]
		}
	}
	return ""
}

// isGenDigit reports whether tok is a single 1..9 generation digit.
func isGenDigit(tok string) bool {
	return len(tok) == 1 && tok[0] >= '1' && tok[0] <= '9'
}

// NIC is one port entry from the pre-auth /xmldata <HSI><NICS> block. iLO
// returns the host/iLO MAC and configured IP for each management/embedded NIC
// without authentication.
type NIC struct {
	Port        string `xml:"PORT" json:"port,omitempty"`
	Description string `xml:"DESCRIPTION" json:"description,omitempty"`
	Location    string `xml:"LOCATION" json:"location,omitempty"`
	MACAddr     string `xml:"MACADDR" json:"macAddress,omitempty"`
	IPAddr      string `xml:"IPADDR" json:"ipAddress,omitempty"`
	Status      string `xml:"STATUS" json:"status,omitempty"`
}

// MACIPs returns "MAC IP" strings from the pre-auth NICS block, skipping empty
// entries. This is the unauthenticated asset/topology inventory an attacker uses
// to correlate a BMC with its host on the production network.
func (x *XMLData) MACIPs() []string {
	var out []string
	for _, n := range x.HSI.NICS.NIC {
		mac := strings.TrimSpace(n.MACAddr)
		if mac == "" {
			continue
		}
		out = append(out, strings.TrimSpace(mac+" "+strings.TrimSpace(n.IPAddr)))
	}
	return out
}
