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

type rzService struct {
	Port      int
	Transport string
	Address   string
	VHost     string
	Summary   string
	Protocols []string
	Data      map[string]string
}

func (s *rzService) get(key string) string {
	if s.Data == nil {
		return ""
	}
	return s.Data[key]
}

func (s *rzService) hasProto(name string) bool {
	return slices.Contains(s.Protocols, name)
}

func (s *rzService) portKey() string {
	return fmt.Sprintf("%d/%s", s.Port, s.Transport)
}

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

type rzHost struct {
	asset    rzAsset
	services []rzService
}

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

	rec.Final = engine.Finalize(&engine.Target{
		Host:     rec.Host,
		Open:     rec.Ports,
		Identity: rec.Identity,
		Findings: rec.Findings,
	})
	return rec
}

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

		ports[key] = engine.SortedCSVString(joinCSV(ports[key], strings.Join(s.Protocols, ",")))
	}
	if len(ports) == 0 {
		return nil
	}
	return ports
}

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
