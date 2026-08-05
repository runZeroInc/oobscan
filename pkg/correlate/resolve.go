package correlate

import (
	"sort"
	"strconv"
	"strings"
)

const (
	maxSelfClaims = 2

	maxNeighbourClaims = 8
)

type Index struct {
	neighbourByMAC map[string]map[string]struct{}

	selfByMAC map[string]map[string]struct{}

	isOOB map[string]bool

	nameToAddr map[string]map[string]struct{}
}

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

func (ix *Index) ObserveHostMAC(addr, mac string) {
	if mac = normMAC(mac); mac != "" {
		put(ix.selfByMAC, mac, addr)
	}
}

func (ix *Index) ObserveName(addr, name string) {
	if n := usableName(name); n != "" {
		put(ix.nameToAddr, strings.ToLower(n), addr)
	}
}

func (ix *Index) Resolve(m *ManagedHost) bool {
	if m == nil || len(m.Addresses) > 0 {
		return false
	}
	added := false
	for _, mv := range m.MACs {
		mac := mv.Value

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

type AdjacencyHint struct {
	BMCMAC  string   `json:"bmcMac"`
	OUI     string   `json:"oui"`
	Offsets []int    `json:"offsets"`
	Guesses []string `json:"guesses"`
}

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
		if strings.HasPrefix(cand, h.OUI) {
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
