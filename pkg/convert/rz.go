package convert

import (
	"fmt"
	"maps"
	"slices"
	"sort"
	"strings"

	"github.com/runZeroInc/oobscan/pkg/creds"
	"github.com/runZeroInc/oobscan/pkg/engine"
	"github.com/runZeroInc/oobscan/pkg/output"
	"github.com/runZeroInc/oobscan/pkg/scanfile"
)

// This file holds the source-independent runZero model and its projection onto the
// native schema. Both runZero inputs (SQL asset+services export, flattened services
// export) decode into rzHost; everything downstream is shared.
//
// The projection is lossless-first: every service_data key and asset attribute is
// carried through verbatim into the per-service and host attribute bags, and only
// then is the native view (identity, findings, RAKP rows) derived on top.

// rzService is one runZero service with its flattened service_data bag.
type rzService struct {
	Port      int
	Transport string
	Address   string
	VHost     string
	Summary   string
	Protocols []string
	Data      map[string]string
}

// get returns a service_data value, tolerating a nil map.
func (s *rzService) get(key string) string {
	if s.Data == nil {
		return ""
	}
	return s.Data[key]
}

// hasProto reports whether the service advertises the named protocol.
func (s *rzService) hasProto(name string) bool {
	return slices.Contains(s.Protocols, name)
}

// portKey renders the oobscan open-port key ("623/udp").
func (s *rzService) portKey() string {
	return fmt.Sprintf("%d/%s", s.Port, s.Transport)
}

// rzAsset is the asset-level view of a runZero export.
type rzAsset struct {
	ID             string
	Type           string
	Category       string
	DetectedBy     string
	OS             string
	OSVendor       string
	OSProduct      string
	OSVersion      string
	HW             string
	HWVendor       string
	HWProduct      string
	HWVersion      string
	Addresses      []string
	AddressesExtra []string
	MACs           []string
	MACVendors     []string
	Names          []string
	Attrs          map[string]string
	Unindexed      map[string]string
}

// rzHost is one runZero asset with all of its services.
type rzHost struct {
	asset    rzAsset
	services []rzService
}

// addr returns the host address for the record: the asset's first address,
// falling back to the first address any of its services was seen on.
func (h *rzHost) addr() string {
	for _, a := range h.asset.Addresses {
		if a = strings.TrimSpace(a); a != "" {
			return a
		}
	}
	for i := range h.services {
		if a := strings.TrimSpace(h.services[i].Address); a != "" {
			return a
		}
	}
	return ""
}

// record projects the runZero host onto an oobscan record.
func (h *rzHost) record() *scanfile.Record {
	rec := &scanfile.Record{
		Host:       h.addr(),
		Ports:      h.ports(),
		Services:   h.serviceRecords(),
		Attributes: h.attributes(),
		RAKP:       h.rakpRecords(),
	}
	rec.Identity = h.identity()
	rec.Findings = h.findings()

	// Reuse the scanner's own id.final derivation so a converted host carries the
	// same flags/topRisk projection a scanned one does, rather than a second
	// implementation that could drift from it.
	rec.Final = engine.Finalize(&engine.Target{
		Host:     rec.Host,
		Open:     rec.Ports,
		Identity: rec.Identity,
		Findings: rec.Findings,
	})
	return rec
}

// ports renders the services as the oobscan open-port map.
func (h *rzHost) ports() engine.OpenPorts {
	if len(h.services) == 0 {
		return nil
	}
	ports := make(engine.OpenPorts, len(h.services))
	for i := range h.services {
		s := &h.services[i]
		if s.Port == 0 && s.Transport == "" {
			continue
		}
		key := s.portKey()
		// A service seen on several addresses of the same asset repeats its port;
		// merge the protocol lists instead of letting the last row win.
		ports[key] = engine.SortedCSVString(joinCSV(ports[key], strings.Join(s.Protocols, ",")))
	}
	if len(ports) == 0 {
		return nil
	}
	return ports
}

// serviceRecords projects the runZero services onto oobscan service records,
// preserving the whole service_data bag.
func (h *rzHost) serviceRecords() []output.ServiceRecord {
	if len(h.services) == 0 {
		return nil
	}
	out := make([]output.ServiceRecord, 0, len(h.services))
	for i := range h.services {
		s := &h.services[i]
		out = append(out, output.ServiceRecord{
			Port:       s.Port,
			Transport:  s.Transport,
			Protocols:  sortedUnique(s.Protocols),
			Summary:    s.Summary,
			VHost:      s.VHost,
			Address:    s.Address,
			Attributes: boundedAttrs(s.Data),
		})
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Port != out[j].Port {
			return out[i].Port < out[j].Port
		}
		if out[i].Transport != out[j].Transport {
			return out[i].Transport < out[j].Transport
		}
		return out[i].Address < out[j].Address
	})
	return out
}

// attributes renders the asset-level bag: every raw runZero attribute, then the
// typed asset columns under their runZero names, then the oobscan-canonical
// class/vendor/product/version. Later writes win, so the canonical keys and the
// typed columns are authoritative over a same-named raw attribute.
func (h *rzHost) attributes() map[string]string {
	a := h.asset
	out := boundedAttrs(a.Unindexed)
	if out == nil {
		out = map[string]string{}
	}
	maps.Copy(out, boundedAttrs(a.Attrs))

	set := func(k, v string) {
		if strings.TrimSpace(v) != "" {
			out[k] = v
		}
	}
	setList := func(k string, v []string) {
		// Tab separation is runZero's own multi-value convention; keeping it means
		// a converted record reads the same way the source did.
		set(k, strings.Join(v, "\t"))
	}
	set("type", a.Type)
	set("category", a.Category)
	set("detected_by", a.DetectedBy)
	set("os", a.OS)
	set("os_vendor", a.OSVendor)
	set("os_product", a.OSProduct)
	set("os_version", a.OSVersion)
	set("hw", a.HW)
	set("hw_vendor", a.HWVendor)
	set("hw_product", a.HWProduct)
	set("hw_version", a.HWVersion)
	setList("addresses", append(append([]string{}, a.Addresses...), a.AddressesExtra...))
	setList("macs", a.MACs)
	setList("mac_vendors", a.MACVendors)
	setList("names", a.Names)

	id := h.identity()
	set("class", string(id.Class))
	set("vendor", id.Vendor)
	set("product", id.Product)
	set("version", h.version())

	if len(out) == 0 {
		return nil
	}
	return out
}

// identity resolves the oobscan identity from the runZero asset columns, with
// the observed services as the tiebreaker. Confidence is high when runZero
// itself typed the device as out-of-band gear and medium when the class was
// recovered from a port or protocol.
func (h *rzHost) identity() *engine.Identity {
	class, fromType := h.class()
	conf := engine.ConfMedium
	if fromType {
		conf = engine.ConfHigh
	}
	id := &engine.Identity{
		Class:      class,
		Vendor:     h.vendor(),
		Product:    firstNonEmpty(h.asset.HWProduct, h.asset.OSProduct, h.asset.HW, h.asset.OS),
		Confidence: conf,
	}
	if id.Vendor == "" && id.Product == "" && class == engine.ClassUnknown {
		id.Confidence = engine.ConfLow
	}
	if attrs := h.identityAttrs(); len(attrs) > 0 {
		id.Attributes = attrs
	}
	id.Signals = h.signals()
	return id
}

// identityAttrs carries the identity-shaped facts oobscan's own identify step
// would have recorded, so id.final can read a version off them.
func (h *rzHost) identityAttrs() map[string]string {
	attrs := map[string]string{}
	if v := h.version(); v != "" {
		attrs["firmwareVersion"] = v
	}
	for i := range h.services {
		s := &h.services[i]
		for _, k := range []string{"ipmi.system.guid", "ipmi.guid.vendor", "ipmi.oemName", "ipmi.oemID"} {
			if v := s.get(k); v != "" {
				attrs[engine.CanonicalFieldKey(k)] = v
			}
		}
	}
	if len(h.asset.MACs) > 0 {
		attrs["mac"] = h.asset.MACs[0]
	}
	if len(attrs) == 0 {
		return nil
	}
	return attrs
}

// signals records where the attribution came from, mirroring the Signal rows a
// live identify pass would have produced.
func (h *rzHost) signals() []engine.Signal {
	var sigs []engine.Signal
	if h.asset.Type != "" || h.asset.HWVendor != "" || h.asset.OSVendor != "" {
		sigs = append(sigs, engine.Signal{
			Source: "runzero.asset",
			Vendor: h.vendor(),
			Detail: strings.TrimSpace(strings.Join(nonEmpty(h.asset.Type, h.asset.HW, h.asset.OS), " / ")),
		})
	}
	for i := range h.services {
		if s := &h.services[i]; ipmiService(s) {
			sigs = append(sigs, engine.Signal{
				Source: "runzero.service",
				Vendor: creds.NormalizeVendor(s.get("ipmi.guid.vendor")),
				Detail: "ipmi on " + s.portKey(),
			})
			break
		}
	}
	return sigs
}

// version resolves a firmware/software version for the host.
func (h *rzHost) version() string {
	if v := firstNonEmpty(h.asset.OSVersion, h.asset.HWVersion); v != "" {
		return v
	}
	for i := range h.services {
		s := &h.services[i]
		for _, k := range []string{"ipmi.firmwareVersion", "ipmi.fw", "http.firmwareVersion", "snmp.firmwareVersion"} {
			if v := s.get(k); v != "" {
				return v
			}
		}
	}
	return ""
}

// vendor resolves the lowercase oobscan vendor slug. It prefers the hardware
// vendor (a BMC's own maker) over the OS vendor, and falls back to the IPMI
// GUID vendor, which is the one vendor signal a sessionless probe always gets.
func (h *rzHost) vendor() string {
	cands := []string{h.asset.HWVendor, h.asset.HWProduct, h.asset.OSVendor, h.asset.OSProduct, h.asset.HW, h.asset.OS}
	for i := range h.services {
		s := &h.services[i]
		cands = append(cands, s.get("ipmi.guid.vendor"), s.get("ipmi.oemName"), s.get("http.head.server"))
	}
	for _, c := range cands {
		if v := creds.NormalizeVendor(c); v != "" {
			return v
		}
	}
	return ""
}

// rzTypeClass maps a runZero asset type onto an oobscan device class. Matching
// is on a lowercased substring because the runZero type vocabulary is
// fingerprint-driven and not a closed set.
var rzTypeClass = []struct {
	match string
	class engine.DeviceClass
}{
	{"bmc", engine.ClassBMC},
	{"kvm", engine.ClassKVM},
	{"pdu", engine.ClassPDU},
	{"power distribution", engine.ClassPDU},
	{"power strip", engine.ClassPDU},
	{"ups", engine.ClassPDU},
	{"uninterruptible", engine.ClassPDU},
	{"serial", engine.ClassSerialConsole},
	{"terminal server", engine.ClassSerialConsole},
	{"console server", engine.ClassSerialConsole},
}

// class resolves the device class, reporting whether runZero's own asset type
// decided it rather than a service-shape inference.
//
// The service fallback accepts only a positive discriminator: the IPMI protocol or
// its attributes, or one of the two dedicated Intel AMT ports. It must not class
// off the KVM/virtual-media port list even though those ports do produce a
// kvm.exposure finding, because a host exposing a sequential serial-console range
// collides with that list by arithmetic accident. A wrong class propagates into
// every downstream count, so an unclassed host is the better failure.
func (h *rzHost) class() (engine.DeviceClass, bool) {
	t := strings.ToLower(strings.TrimSpace(h.asset.Type))
	for _, r := range rzTypeClass {
		if strings.Contains(t, r.match) {
			return r.class, true
		}
	}
	amt := false
	for i := range h.services {
		s := &h.services[i]
		switch {
		case ipmiService(s):
			return engine.ClassBMC, false
		case s.Transport == "tcp" && (s.Port == 16992 || s.Port == 16993):
			amt = true
		}
	}
	if amt {
		return engine.ClassAMT, false
	}
	return engine.ClassUnknown, false
}

// boundedAttrs copies an attribute bag, dropping empty keys and capping
// oversized values at the emitted-record ceiling. Returns nil when empty.
func boundedAttrs(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		if k == "" {
			continue
		}
		if len(v) > output.RawFieldMax {
			v = truncUTF8(v, output.RawFieldMax)
		}
		out[k] = v
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// truncUTF8 truncates s to at most max bytes without splitting a rune.
func truncUTF8(s string, max int) string {
	if len(s) <= max {
		return s
	}
	b := []byte(s)[:max]
	for len(b) > 0 && b[len(b)-1]&0xC0 == 0x80 {
		b = b[:len(b)-1]
	}
	if len(b) > 0 && b[len(b)-1] >= 0xC0 {
		b = b[:len(b)-1]
	}
	return string(b)
}

// tabValues splits a runZero multi-value attribute (tab separated).
func tabValues(v string) []string {
	if v == "" {
		return nil
	}
	parts := strings.Split(v, "\t")
	out := parts[:0]
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// containsFlag reports whether a tab-separated flag string contains flag.
func containsFlag(val, flag string) bool {
	return slices.Contains(tabValues(val), flag)
}

func sortedUnique(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, v := range in {
		if v = strings.TrimSpace(v); v == "" {
			continue
		}
		if _, dup := seen[v]; dup {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

func joinCSV(a, b string) string {
	switch {
	case a == "":
		return b
	case b == "":
		return a
	}
	return a + "," + b
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func nonEmpty(vals ...string) []string {
	out := make([]string, 0, len(vals))
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			out = append(out, v)
		}
	}
	return out
}
