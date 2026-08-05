package guid

import (
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"
)

type Result struct {
	Hex    string
	Family string
	Vendor string
	Fields map[string]string
}

func (r *Result) Keys() []string {
	out := make([]string, 0, len(r.Fields))
	for k := range r.Fields {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

var smcModelPrefixGen = map[string]string{
	"7001MS": "X10",
	"C001MS": "X10",
	"4101MS": "X11",
	"5201MS": "X12",
	"F201MS": "X12",
	"F401MS": "H13",
	"1401MS": "H13",
	"B201MS": "M12",
	"2401MS": "X13",
	"C301MS": "X13",
	"E401MS": "H13",
	"5601MS": "X14",
}

func SMCGenerationFromModelPrefix(prefix string) string {
	return smcModelPrefixGen[strings.ToUpper(strings.TrimSpace(prefix))]
}

func DecodeHex(s string) (*Result, error) {
	s = strings.ReplaceAll(s, "-", "")
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("hex: %w", err)
	}
	return Decode(b), nil
}

func Decode(b []byte) *Result {
	r := &Result{
		Hex:    hex.EncodeToString(b),
		Fields: map[string]string{},
	}
	if len(b) != 16 {
		r.Family = "short"
		return r
	}

	if allZero(b) {

		r.Family = "all-zero"
		return r
	}

	if string(b[:4]) == "DELL" {
		r.Family = "dell-service-tag"
		r.Vendor = "dell"
		tag := []byte{
			b[10] & 0x7f,
			b[4],
			b[7],
			b[9],
			b[13],
			b[14],
			b[15],
		}
		r.Fields["service_tag"] = string(tag)
		return r
	}

	if b[4] == 'M' && b[5] == 'S' && printableRatio(b[:4]) >= 0.9 {
		r.Family = "smc-board-serial"
		r.Vendor = "supermicro"
		r.Fields["model_prefix"] = string(b[:6])
		mac := b[6:12]
		r.Fields["mac"] = fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x",
			mac[0], mac[1], mac[2], mac[3], mac[4], mac[5])
		r.Fields["oui"] = fmt.Sprintf("%02x:%02x:%02x", mac[0], mac[1], mac[2])
		r.Fields["trailer"] = hex.EncodeToString(b[12:])
		return r
	}

	if printableRatio(b) >= 0.9 && isHPEPrintable(b) {
		r.Family = "hpe-printable"
		r.Vendor = "hpe"
		r.Fields["text"] = string(b)
		r.Fields["part_id"] = string(b[:6])
		r.Fields["country"] = string(b[6:9])
		r.Fields["serial"] = strings.TrimRight(string(b[9:]), "\x00")
		return r
	}

	if printableRatio(b) >= 0.9 && hasHPEModelPrefix(b) {
		r.Family = "hpe-printable"
		r.Vendor = "hpe"
		r.Fields["text"] = string(b)
		r.Fields["model_prefix"] = string(b[:6])
		return r
	}

	if printableRatio(b) >= 0.9 {
		r.Family = "printable-serial"
		r.Vendor = "unknown"
		r.Fields["text"] = string(b)
		return r
	}

	if printableRatio(b[:6]) >= 0.9 && printableRatio(b[6:]) < 0.5 {
		r.Family = "printable-prefix-binary"
		r.Vendor = "unknown"
		r.Fields["prefix"] = string(b[:6])
		r.Fields["binary"] = hex.EncodeToString(b[6:])
		return r
	}

	if b[6]&0xf0 == 0x10 {
		r.Family = "uuidv1"
		r.Vendor = "unknown"
		mac := b[10:16]
		r.Fields["node_mac"] = fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x",
			mac[0], mac[1], mac[2], mac[3], mac[4], mac[5])
		r.Fields["oui"] = fmt.Sprintf("%02x:%02x:%02x", mac[0], mac[1], mac[2])

		tsLow := le32(b[0:4])
		tsMid := le16(b[4:6])
		tsHi := le16(b[6:8]) & 0x0fff
		ts := (uint64(tsHi) << 48) | (uint64(tsMid) << 32) | uint64(tsLow)

		unix := int64(ts/10_000_000) - 12219292800
		if unix > 0 && unix < 1<<40 {
			r.Fields["unix"] = fmt.Sprintf("%d", unix)
			r.Fields["time"] = time.Unix(unix, 0).UTC().Format("2006-01-02T15:04:05Z")
		}
		return r
	}

	if b[0] == 0 && b[1] == 0 && b[2] == 0 && b[3] == 0 && b[4] != 0 {
		r.Family = "lenovo-imm-like"
		r.Vendor = "lenovo"
		r.Fields["body"] = hex.EncodeToString(b[4:])
		return r
	}

	switch {
	case hex.EncodeToString(b[:4]) == "ff200008":
		r.Family = "marker-ff200008"
	case hex.EncodeToString(b[:4]) == "00100000":
		r.Family = "marker-0010"
	case hex.EncodeToString(b[:3]) == "3868dd":
		r.Family = "marker-3868dd"
		r.Vendor = "h3c"
	}
	if r.Family != "" {
		r.Fields["prefix"] = hex.EncodeToString(b[:4])
		r.Fields["tail"] = hex.EncodeToString(b[4:])
		return r
	}

	r.Family = "unknown"
	r.Fields["prefix4"] = hex.EncodeToString(b[:4])
	r.Fields["raw"] = hex.EncodeToString(b)
	return r
}

func isHPEPrintable(b []byte) bool {
	if len(b) != 16 {
		return false
	}

	for i := range 9 {
		if !isUpperAlnum(b[i]) {
			return false
		}
	}

	serialLen := 0
	i := 9
	for ; i < 16; i++ {
		if isUpperAlnum(b[i]) {
			serialLen++
			continue
		}
		break
	}
	if serialLen < 6 {
		return false
	}
	for ; i < 16; i++ {
		if b[i] != 0 {
			return false
		}
	}
	return true
}

func hasHPEModelPrefix(b []byte) bool {
	if len(b) < 2 {
		return false
	}
	switch string(b[:2]) {
	case "DL", "ML", "BL", "SL", "XL":
		return true
	}
	return false
}

func isUpperAlnum(x byte) bool {
	return (x >= '0' && x <= '9') || (x >= 'A' && x <= 'Z')
}

func allZero(b []byte) bool {
	for _, x := range b {
		if x != 0 {
			return false
		}
	}
	return true
}

func printableRatio(b []byte) float64 {
	if len(b) == 0 {
		return 0
	}
	ok := 0
	for _, x := range b {
		if x >= 0x20 && x <= 0x7e {
			ok++
		}
	}
	return float64(ok) / float64(len(b))
}

func le16(b []byte) uint16 { return uint16(b[0]) | uint16(b[1])<<8 }
func le32(b []byte) uint32 {
	return uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24
}
