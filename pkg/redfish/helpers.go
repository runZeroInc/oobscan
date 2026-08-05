package redfish

import (
	"encoding/xml"
	"strings"
)

func ExtractLinksFromJSON(body []byte, currentPath string) []string {
	return extractLinks(body, currentPath)
}

type ILORIMPFields struct {
	FWVersion string
	Product   string
	SerialTag string

	SerialNumber string
	Model        string
	UUID         string

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

func ParseILORIMP(body []byte) *ILORIMPFields {
	out := &ILORIMPFields{Raw: body}
	if len(body) == 0 {
		return out
	}

	trimmed := strings.TrimSpace(string(body))
	if idx := strings.Index(trimmed, "<RIMP"); idx > 0 {
		trimmed = trimmed[idx:]
	}

	var doc rimpdoc
	if err := xml.Unmarshal([]byte(trimmed), &doc); err != nil {

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
