package correlate

import (
	"sort"
	"strconv"
	"strings"
)

// Resolve is the cross-host stage. It pools every neighbour cache the scan collected
// and every MAC any scanned host claims as its own, then tries to give an address to
// the managed servers that were only described.
//
// Three joins, strongest first:
//
//   - A MAC the BMC published for its server appears in some BMC's neighbour cache.
//     MACs are globally unique, so this join is not scoped to a subnet, and it works
//     across prefixes -- which matters, because a quarter of located servers are not
//     in their BMC's own /24.
//   - A MAC the BMC published is claimed as its own by another scanned address.
//   - Nothing. The result stays Identity, and callers must not treat it as located.
//
// Every join is gated on the MAC being rare. A MAC that many endpoints claim is a
// duplicate factory address, not a machine: Tyan ships one such value on every unit,
// and before the gate existed it produced a large block of confident wrong matches.
// The gate counts only endpoints asserting a MAC as their OWN -- a BMC publishing its
// server's NIC list must not push that server's MAC over the threshold and gate away
// the very join it enabled.
const (
	// maxSelfClaims is how many endpoints may claim a MAC before it is treated as a
	// product identifier rather than a machine identity.
	maxSelfClaims = 2
	// maxNeighbourClaims bounds the same idea for neighbour caches, which legitimately
	// see one MAC from several vantage points on the same segment.
	maxNeighbourClaims = 8
)

// Index is the pooled cross-host view a Resolve pass needs.
type Index struct {
	// neighbourByMAC maps a MAC to the addresses some BMC has cached it at.
	neighbourByMAC map[string]map[string]struct{}
	// selfByMAC maps a MAC to the scanned addresses claiming it as their own.
	selfByMAC map[string]map[string]struct{}
	// isOOB marks scanned addresses that are themselves out-of-band devices, so a
	// pair of BMCs in a rack is never reported as a BMC and its server.
	isOOB map[string]bool
	// names maps a lowercased hostname to the scanned addresses answering to it.
	nameToAddr map[string]map[string]struct{}
}

// NewIndex builds the pooled view from every extracted record plus the set of
// scanned addresses and the MACs they claim.
func NewIndex() *Index {
	return &Index{
		neighbourByMAC: map[string]map[string]struct{}{},
		selfByMAC:      map[string]map[string]struct{}{},
		isOOB:          map[string]bool{},
		nameToAddr:     map[string]map[string]struct{}{},
	}
}

func put(m map[string]map[string]struct{}, k, v string) {
	if k == "" || v == "" {
		return
	}
	s, ok := m[k]
	if !ok {
		s = map[string]struct{}{}
		m[k] = s
	}
	s[v] = struct{}{}
}

// Observe folds one extracted record into the index.
func (ix *Index) Observe(m *ManagedHost) {
	if m == nil {
		return
	}
	if m.BMCClass != "" && m.BMCClass != "unknown" && m.BMCClass != "honeypot" {
		ix.isOOB[m.BMC] = true
	}
	for _, mac := range m.BMCMACs {
		put(ix.selfByMAC, mac, m.BMC)
	}
	for _, n := range m.Neighbours {
		put(ix.neighbourByMAC, n.MAC, n.IP)
	}
}

// ObserveHostMAC records that a scanned address claims a MAC as its own. This is the
// host side of the join and comes from whatever leaked it -- a NetBIOS node status,
// an SNMPv3 engine ID, a device-discovery reply.
func (ix *Index) ObserveHostMAC(addr, mac string) {
	if mac = normMAC(mac); mac != "" {
		put(ix.selfByMAC, mac, addr)
	}
}

// ObserveName records that a scanned address answers to a hostname.
func (ix *Index) ObserveName(addr, name string) {
	if n := usableName(name); n != "" {
		put(ix.nameToAddr, strings.ToLower(n), addr)
	}
}

// Resolve attempts to give the managed server an address. It mutates m and reports
// whether an address was added.
func (ix *Index) Resolve(m *ManagedHost) bool {
	if m == nil || len(m.Addresses) > 0 {
		return false // already stated; nothing to infer
	}
	added := false
	for _, mv := range m.MACs {
		mac := mv.Value
		// The self-claim gate: a MAC many endpoints call their own is a factory
		// duplicate. Count self-claims only, never the BMC's publication of it.
		if len(ix.selfByMAC[mac]) > maxSelfClaims {
			continue
		}
		for addr := range ix.neighbourByMAC[mac] {
			if addr == m.BMC || ix.isOOB[addr] {
				continue
			}
			if len(ix.neighbourByMAC[mac]) > maxNeighbourClaims {
				break
			}
			m.add(&m.Addresses, addr, Source{
				Producer: "correlate.neighbourJoin",
				Field:    "ipNetToMediaTable:" + mac,
				Auth:     defcred,
			})
			added = true
		}
		for addr := range ix.selfByMAC[mac] {
			if addr == m.BMC || ix.isOOB[addr] {
				continue
			}
			m.add(&m.Addresses, addr, Source{
				Producer: "correlate.hostMACJoin",
				Field:    "hostClaimedMAC:" + mac,
				Auth:     preauth,
			})
			added = true
		}
	}
	// A name the BMC gave for its server, answered by a scanned address, is the same
	// join one step removed. DNS would extend this further but a scan cannot assume
	// resolver access, so only in-scan names are used here.
	if !added {
		for _, nv := range m.Names {
			for addr := range ix.nameToAddr[strings.ToLower(nv.Value)] {
				if addr == m.BMC || ix.isOOB[addr] {
					continue
				}
				m.add(&m.Addresses, addr, Source{
					Producer: "correlate.nameJoin",
					Field:    "scannedHostName:" + nv.Value,
					Auth:     preauth,
				})
				added = true
			}
		}
	}
	if added {
		m.Confidence = Resolved
		sortAll(m)
	}
	return added
}

// AdjacencyHint describes where a server's NICs are likely to sit relative to the
// BMC's own MAC, for callers that want to search a neighbour table themselves.
//
// It is deliberately a hint and not a rule. Measured across 238 hosts with both a
// BMC MAC and a known server NIC list, only 42% share an OUI with any server NIC at
// all and only 39% have one within 16 slots, with +6/+7 the most common offsets. An
// earlier 16-host sample suggested -1/-2 and it was simply unrepresentative, in both
// rate and direction. Predicting a server MAC from a BMC MAC and looking it up on the
// internet produced zero confirmed mappings; the hint is only worth using against a
// neighbour table for the same segment.
type AdjacencyHint struct {
	BMCMAC  string   `json:"bmcMac"`
	OUI     string   `json:"oui"`
	Offsets []int    `json:"offsets"`
	Guesses []string `json:"guesses"`
}

// Adjacency returns candidate server MACs around a BMC MAC, most likely first.
func Adjacency(bmcMAC string) *AdjacencyHint {
	mac := normMAC(bmcMAC)
	if mac == "" {
		return nil
	}
	n, err := strconv.ParseUint(strings.ReplaceAll(mac, ":", ""), 16, 64)
	if err != nil {
		return nil
	}
	offsets := []int{6, 7, -1, -2, 1, 2, -6, -7, 3, -3, 4, -4}
	h := &AdjacencyHint{BMCMAC: mac, OUI: mac[:8], Offsets: offsets}
	for _, d := range offsets {
		v := int64(n) + int64(d)
		if v < 0 {
			continue
		}
		cand := formatMAC(uint64(v))
		if strings.HasPrefix(cand, h.OUI) { // stay inside the burned-in block
			h.Guesses = append(h.Guesses, cand)
		}
	}
	return h
}

func formatMAC(v uint64) string {
	b := make([]byte, 0, 17)
	for i := 5; i >= 0; i-- {
		if len(b) > 0 {
			b = append(b, ':')
		}
		x := byte(v >> (uint(i) * 8))
		const hexd = "0123456789abcdef"
		b = append(b, hexd[x>>4], hexd[x&0xf])
	}
	return string(b)
}

// Summarize counts a finished correlation set.
func Summarize(hosts []*ManagedHost, oobTotal int) Summary {
	s := Summary{OOBDevices: oobTotal}
	seenNbr := map[string]struct{}{}
	for _, m := range hosts {
		for _, n := range m.Neighbours {
			seenNbr[n.IP+"|"+n.MAC] = struct{}{}
		}
		if m.Empty() {
			continue
		}
		s.Described++
		switch m.Confidence {
		case Stated:
			s.Stated++
			s.Located++
		case Resolved:
			s.Resolved++
			s.Located++
		}
	}
	s.Neighbours = len(seenNbr)
	return s
}

// SortHosts orders results so the located ones come first and the output is stable.
func SortHosts(hosts []*ManagedHost) {
	rank := map[Confidence]int{Stated: 0, Resolved: 1, Identity: 2}
	sort.SliceStable(hosts, func(i, j int) bool {
		ri, rj := rank[hosts[i].Confidence], rank[hosts[j].Confidence]
		if ri != rj {
			return ri < rj
		}
		return hosts[i].BMC < hosts[j].BMC
	})
}
