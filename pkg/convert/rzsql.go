package convert

import (
	"encoding/json"
	"strings"
)

type sqlLine struct {
	Asset    sqlAsset     `json:"asset"`
	Services []sqlService `json:"services"`
}

type sqlAsset struct {
	ID             string            `json:"id"`
	Type           string            `json:"type"`
	Category       string            `json:"category"`
	DetectedBy     string            `json:"detected_by"`
	OS             string            `json:"os"`
	OSVendor       string            `json:"os_vendor"`
	OSProduct      string            `json:"os_product"`
	OSVersion      string            `json:"os_version"`
	HW             string            `json:"hw"`
	HWVendor       string            `json:"hw_vendor"`
	HWProduct      string            `json:"hw_product"`
	HWVersion      string            `json:"hw_version"`
	Addresses      []string          `json:"addresses"`
	AddressesExtra []string          `json:"addresses_extra"`
	MACs           []string          `json:"macs"`
	MACVendors     []string          `json:"mac_vendors"`
	Names          []string          `json:"names"`
	Attrs          map[string]string `json:"attributes"`
	Unindexed      map[string]string `json:"unindexed_attributes"`
}

type sqlService struct {
	Port      int               `json:"port"`
	Transport string            `json:"transport"`
	Address   string            `json:"address"`
	VHost     string            `json:"vhost"`
	Summary   string            `json:"summary"`
	Protocols []string          `json:"protocols"`
	Data      map[string]string `json:"service_data"`
}

func (l *sqlLine) host() *rzHost {
	h := &rzHost{asset: rzAsset{
		ID:             l.Asset.ID,
		Type:           l.Asset.Type,
		Category:       l.Asset.Category,
		DetectedBy:     l.Asset.DetectedBy,
		OS:             l.Asset.OS,
		OSVendor:       l.Asset.OSVendor,
		OSProduct:      l.Asset.OSProduct,
		OSVersion:      l.Asset.OSVersion,
		HW:             l.Asset.HW,
		HWVendor:       l.Asset.HWVendor,
		HWProduct:      l.Asset.HWProduct,
		HWVersion:      l.Asset.HWVersion,
		Addresses:      l.Asset.Addresses,
		AddressesExtra: l.Asset.AddressesExtra,
		MACs:           l.Asset.MACs,
		MACVendors:     l.Asset.MACVendors,
		Names:          l.Asset.Names,
		Attrs:          l.Asset.Attrs,
		Unindexed:      l.Asset.Unindexed,
	}}
	for i := range l.Services {
		s := &l.Services[i]
		h.services = append(h.services, rzService{
			Port:      s.Port,
			Transport: s.Transport,
			Address:   s.Address,
			VHost:     s.VHost,
			Summary:   s.Summary,
			Protocols: s.Protocols,
			Data:      s.Data,
		})
	}
	return h
}

func streamRZSQL(path string, fn func(*rzHost) error) (stats sourceStats, err error) {
	stats.Truncated, err = forEachLine(path, func(line []byte) error {
		var rec sqlLine
		if json.Unmarshal(line, &rec) != nil {
			if json.Unmarshal([]byte(unescapeCopyText(string(line))), &rec) != nil {
				stats.Skipped++
				return nil
			}
		}
		stats.Read++
		return fn(rec.host())
	})
	return stats, err
}

func unescapeCopyText(s string) string {
	if !strings.ContainsRune(s, '\\') {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c != '\\' || i+1 >= len(s) {
			b.WriteByte(c)
			continue
		}
		switch s[i+1] {
		case '\\':
			b.WriteByte('\\')
			i++
		case 't':
			b.WriteByte('\t')
			i++
		case 'n':
			b.WriteByte('\n')
			i++
		case 'r':
			b.WriteByte('\r')
			i++
		default:

			b.WriteByte(c)
		}
	}
	return b.String()
}
