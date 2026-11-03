package convert

import (
	"encoding/json"
	"maps"
)

// rzservices reads the runZero services export (models.ServiceWithJoin): one JSON
// object per line holding a single service with its whole asset denormalized
// alongside it, under `service_`-prefixed keys for the service and bare keys for
// the asset.
//
// Unlike the SQL export this format is neither grouped nor sorted by asset: rows
// for an already-seen asset reappear later in the file. Rows are therefore grouped
// in memory by asset id and emitted at the end in first-seen order, which makes
// peak memory proportional to the input.

// servicesLine is one line of the services export.
type servicesLine struct {
	// Service
	ServiceAssetID string            `json:"service_asset_id"`
	Port           int               `json:"service_port"`
	Transport      string            `json:"service_transport"`
	Address        string            `json:"service_address"`
	VHost          string            `json:"service_vhost"`
	Summary        string            `json:"service_summary"`
	Protocols      []string          `json:"service_protocol"`
	Data           map[string]string `json:"service_data"`

	// Asset (denormalized onto every one of its service rows)
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
	SiteName       string            `json:"site_name"`
	OrgName        string            `json:"org_name"`
}

// assetKey identifies the asset a row belongs to.
func (l *servicesLine) assetKey() string {
	if l.ServiceAssetID != "" {
		return l.ServiceAssetID
	}
	if l.ID != "" {
		return l.ID
	}
	// No id at all: fall back to the address so rows for one host still merge.
	return l.Address
}

// asset builds the asset view from a row. The export carries the site and
// organization names, which have no asset column of their own, so they are
// folded into the attribute bag rather than dropped.
func (l *servicesLine) asset() rzAsset {
	attrs := l.Attrs
	if l.SiteName != "" || l.OrgName != "" {
		merged := make(map[string]string, len(attrs)+2)
		maps.Copy(merged, attrs)
		if l.SiteName != "" {
			merged["site_name"] = l.SiteName
		}
		if l.OrgName != "" {
			merged["org_name"] = l.OrgName
		}
		attrs = merged
	}
	return rzAsset{
		ID:             l.ID,
		Type:           l.Type,
		Category:       l.Category,
		DetectedBy:     l.DetectedBy,
		OS:             l.OS,
		OSVendor:       l.OSVendor,
		OSProduct:      l.OSProduct,
		OSVersion:      l.OSVersion,
		HW:             l.HW,
		HWVendor:       l.HWVendor,
		HWProduct:      l.HWProduct,
		HWVersion:      l.HWVersion,
		Addresses:      l.Addresses,
		AddressesExtra: l.AddressesExtra,
		MACs:           l.MACs,
		MACVendors:     l.MACVendors,
		Names:          l.Names,
		Attrs:          attrs,
	}
}

func (l *servicesLine) service() rzService {
	return rzService{
		Port:      l.Port,
		Transport: l.Transport,
		Address:   l.Address,
		VHost:     l.VHost,
		Summary:   l.Summary,
		Protocols: l.Protocols,
		Data:      l.Data,
	}
}

// streamRZServices reads the services export at path, groups its rows by asset,
// and invokes fn once per asset in first-seen order.
func streamRZServices(path string, fn func(*rzHost) error) (stats sourceStats, err error) {
	byAsset := map[string]*rzHost{}
	var order []string

	stats.Truncated, err = forEachLine(path, func(line []byte) error {
		var row servicesLine
		if json.Unmarshal(line, &row) != nil {
			stats.Skipped++
			return nil
		}
		stats.Read++

		key := row.assetKey()
		h := byAsset[key]
		if h == nil {
			h = &rzHost{asset: row.asset()}
			byAsset[key] = h
			order = append(order, key)
		}
		h.services = append(h.services, row.service())
		return nil
	})
	if err != nil {
		return stats, err
	}

	stats.Grouped = len(order)
	for _, key := range order {
		if err := fn(byAsset[key]); err != nil {
			return stats, err
		}
	}
	return stats, nil
}
