package redfish

import (
	"encoding/xml"
	"strings"
)

// ExtractLinksFromJSON is the exported counterpart of extractLinks. It is
// provided for fuzz testing (F1) and external callers.
func ExtractLinksFromJSON(body []byte, currentPath string) []string {
	return extractLinks(body, currentPath)
}

// ILORIMPFields is the subset of iLO RIMP XML fields that oobscan extracts.
// This covers the key fields from iLO4 through iLO6 observed in the wild.
type ILORIMPFields struct {
	// From <MP> block
	FWVersion string // <FWRI> firmware version string, e.g. "2.78"
	Product   string // <PN> product name, e.g. "iLO5"
	SerialTag string // <ST> service tag present flag

	// From <HSI> block
	SerialNumber string // <SBSN>
	Model        string // <SPN>
	UUID         string // <UUID>

	// Raw XML for further parsing
	Raw []byte
}

type rimpdoc struct {
	XMLName xml.Name `xml:"RIMP"`
	MP      rimpMP   `xml:"MP"`
	HSI     rimpHSI  `xml:"HSI"`
}

type rimpMP struct {
	FWRI string `xml:"FWRI"`
	PN   string `xml:"PN"`
	ST   string `xml:"ST"`
}

type rimpHSI struct {
	SBSN string `xml:"SBSN"`
	SPN  string `xml:"SPN"`
	UUID string `xml:"UUID"`
}

// ParseILORIMP parses the XML body returned by the HPE iLO /xmldata?item=all
// endpoint. It is exposed as an exported function for fuzz testing (F2) and
// can be called from ilo.Probe results.
//
// Returns a partial result on parse error so the caller can still use whatever
// fields were decoded before the error.
func ParseILORIMP(body []byte) *ILORIMPFields {
	out := &ILORIMPFields{Raw: body}
	if len(body) == 0 {
		return out
	}

	// Strip leading BOM / whitespace that some iLO versions emit.
	trimmed := strings.TrimSpace(string(body))
	if idx := strings.Index(trimmed, "<RIMP"); idx > 0 {
		trimmed = trimmed[idx:]
	}

	var doc rimpdoc
	if err := xml.Unmarshal([]byte(trimmed), &doc); err != nil {
		// Best-effort: return what we have.
		return out
	}

	out.FWVersion = strings.TrimSpace(doc.MP.FWRI)
	out.Product = strings.TrimSpace(doc.MP.PN)
	out.SerialTag = strings.TrimSpace(doc.MP.ST)
	out.SerialNumber = strings.TrimSpace(doc.HSI.SBSN)
	out.Model = strings.TrimSpace(doc.HSI.SPN)
	out.UUID = strings.TrimSpace(doc.HSI.UUID)
	return out
}
