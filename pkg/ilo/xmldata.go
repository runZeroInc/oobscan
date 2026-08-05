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

type XMLData struct {
	XMLName xml.Name `xml:"RIMP" json:"-"`
	HSI     struct {
		SPN   string `xml:"SPN" json:"serverModel,omitempty"`
		PN    string `xml:"PRODUCTID" json:"productId,omitempty"`
		SBSN  string `xml:"SBSN" json:"chassisSerial,omitempty"`
		UUID  string `xml:"UUID" json:"uuid,omitempty"`
		CUUID string `xml:"cUUID" json:"chassisUuid,omitempty"`

		NICS struct {
			NIC []NIC `xml:"NIC" json:"nic,omitempty"`
		} `xml:"NICS" json:"nics,omitzero"`
	} `xml:"HSI" json:"hsi,omitzero"`
	MP struct {
		ST    string `xml:"ST" json:"family,omitempty"`
		PN    string `xml:"PN" json:"product,omitempty"`
		FWRI  string `xml:"FWRI" json:"firmwareVersion,omitempty"`
		HWRI  string `xml:"HWRI" json:"hardwareRevision,omitempty"`
		SN    string `xml:"SN" json:"serial,omitempty"`
		UUID  string `xml:"UUID" json:"uuid,omitempty"`
		SSO   string `xml:"SSO" json:"sso,omitempty"`
		LOCFG string `xml:"LOCFG" json:"locfgUrl,omitempty"`
	} `xml:"MP" json:"mp,omitzero"`
	BladeSystem struct {
		BAY string `xml:"BAY" json:"bay,omitempty"`
		ENC struct {
			Rack string `xml:"RACK,attr" json:"rack,omitempty"`
			SN   string `xml:"SN" json:"serial,omitempty"`
		} `xml:"ENC" json:"enclosure,omitzero"`
	} `xml:"BLADESYSTEM" json:"bladeSystem,omitzero"`
}

func Fetch(client *http.Client, host string) (*XMLData, error) {
	return FetchPorts(client, host, nil, nil)
}

func FetchPorts(client *http.Client, host string, httpsPorts, httpPorts []int) (*XMLData, error) {
	if client == nil {
		client = httpx.Client(10 * time.Second)
	}

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

func (x *XMLData) Populated() bool {
	for _, v := range []string{x.MP.PN, x.MP.ST, x.MP.FWRI, x.MP.SN, x.HSI.SPN, x.HSI.SBSN} {
		if strings.TrimSpace(v) != "" {
			return true
		}
	}
	return false
}

func (x *XMLData) Generation() string {
	pn := strings.ToLower(x.MP.PN)
	switch {
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

func GenerationFromString(s string) string {
	toks := strings.FieldsFunc(strings.ToLower(s), func(r rune) bool {
		return !((r >= 'a' && r <= 'z') || (r >= '0' && r <= '9'))
	})
	for i, tok := range toks {

		if len(tok) == 4 && strings.HasPrefix(tok, "ilo") && tok[3] >= '1' && tok[3] <= '9' {
			return "iLO" + string(tok[3])
		}

		if tok == "ilo" && i+1 < len(toks) && isGenDigit(toks[i+1]) {
			return "iLO" + toks[i+1]
		}

		if tok == "out" && i > 0 && toks[i-1] == "lights" && i+1 < len(toks) && isGenDigit(toks[i+1]) {
			return "iLO" + toks[i+1]
		}
	}
	return ""
}

func isGenDigit(tok string) bool {
	return len(tok) == 1 && tok[0] >= '1' && tok[0] <= '9'
}

type NIC struct {
	Port        string `xml:"PORT" json:"port,omitempty"`
	Description string `xml:"DESCRIPTION" json:"description,omitempty"`
	Location    string `xml:"LOCATION" json:"location,omitempty"`
	MACAddr     string `xml:"MACADDR" json:"macAddress,omitempty"`
	IPAddr      string `xml:"IPADDR" json:"ipAddress,omitempty"`
	Status      string `xml:"STATUS" json:"status,omitempty"`
}

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
