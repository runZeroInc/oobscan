// Package guid decodes BMC GUID fields.
//
// BMCs expose GUID-shaped identity tokens over IPMI. In oobscan the reliable
// pre-auth source is the 16-byte Get System GUID reply (session-zero, no auth);
// RAKP-2 also carries a 16-byte BMC GUID used by the cracking/export path.
//
// Both are 16 bytes but use mixed, vendor-specific conventions.
package guid

import (
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"
)

// Result describes a decoded GUID.
type Result struct {
	Hex    string
	Family string
	Vendor string
	Fields map[string]string
}

// Keys returns Fields keys in stable order.
func (r *Result) Keys() []string {
	out := make([]string, 0, len(r.Fields))
	for k := range r.Fields {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// smcModelPrefixGen maps a Supermicro GUID board-code prefix (the 6-char
// "model_prefix" embedded in the IPMI System GUID) to the board generation. The
// codes are board-family specific rather than a per-generation formula, so this is
// an extend-as-observed lookup: a known code pins the generation pre-auth, an
// unknown one contributes nothing and lets other signals decide. Callers apply a
// band floor for uncatalogued codes. Ground truth:
// kb/smc/notes/smc-guid-board-codes.md.
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

// SMCGenerationFromModelPrefix maps a Supermicro GUID board-code prefix (the
// model_prefix field of an smc-board-serial GUID) to a BMC generation, or "" when
// the code is not catalogued. Case/space-insensitive.
func SMCGenerationFromModelPrefix(prefix string) string {
	return smcModelPrefixGen[strings.ToUpper(strings.TrimSpace(prefix))]
}

// DecodeHex decodes a 32-hex-char GUID.
func DecodeHex(s string) (*Result, error) {
	s = strings.ReplaceAll(s, "-", "")
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("hex: %w", err)
	}
	return Decode(b), nil
}

// Decode a 16-byte raw GUID.
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
		// An all-zero GUID is an unset field: it carries no vendor bits, so no
		// vendor may be claimed. An ambiguous sentinel is unsafe here too:
		// creds.NormalizeVendor matches on substrings and would collapse a hedged
		// value like "supermicro-or-intel" to plain "supermicro". Leaving Vendor empty
		// costs nothing, since Family is still recorded and a host with a real vendor
		// gets it from a higher-confidence signal.
		r.Family = "all-zero"
		return r
	}

	// Dell: ASCII "DELL" (44454c4c) prefix + a 7-char service tag scattered
	// across non-contiguous byte positions. The tag lives at byte offsets 10, 4,
	// 7, 9, 13, 14, 15 (in that character order), and the high bit of byte 10 is a
	// marker that must be stripped. Byte 12 is a fixed 0x4f ('O') structural
	// constant, not part of the tag; bytes 5, 6, 8, and 11 are binary.
	if string(b[:4]) == "DELL" {
		r.Family = "dell-service-tag"
		r.Vendor = "dell"
		tag := []byte{
			b[10] & 0x7f, // marker high bit stripped; first tag char
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

	// Supermicro board-serial: an ASCII model prefix whose 5th and 6th bytes are
	// the marker "MS" (e.g. "7001MS", "C001MS", "6401MS"), followed by an embedded
	// NIC MAC (bytes 6:12) and zero padding. Check this before generic printable
	// GUID families; the MS marker is the primary key.
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

	// HPE iLO printable: fully-printable ASCII with the strict HPE layout of a
	// 6-char part-id, a 3-char plant/country code, and a 6-8 char serial
	// (e.g. "641016USE3256MN7", "719061CZ3447HTBR", "P53933CZJD17017L").
	// Only this strict shape is confidently attributed to HPE; other printable
	// GUIDs fall through to the conservative "printable-serial" family below.
	if printableRatio(b) >= 0.9 && isHPEPrintable(b) {
		r.Family = "hpe-printable"
		r.Vendor = "hpe"
		r.Fields["text"] = string(b)
		r.Fields["part_id"] = string(b[:6])
		r.Fields["country"] = string(b[6:9])
		r.Fields["serial"] = strings.TrimRight(string(b[9:]), "\x00")
		return r
	}

	// HPE ProLiant model-prefixed printable GUIDs that don't fit the strict
	// 6+3+6 layout (e.g. "DL380-CZ2043GW5C", "BL460c6CU8052DLB"). The model
	// prefix (DL/ML/BL/SL/XL ProLiant families) is a strong HPE signal.
	if printableRatio(b) >= 0.9 && hasHPEModelPrefix(b) {
		r.Family = "hpe-printable"
		r.Vendor = "hpe"
		r.Fields["text"] = string(b)
		r.Fields["model_prefix"] = string(b[:6])
		return r
	}

	// Generic printable serial we can't confidently attribute to a vendor.
	// Conservative: label it a printable serial rather than guessing HPE.
	if printableRatio(b) >= 0.9 {
		r.Family = "printable-serial"
		r.Vendor = "unknown"
		r.Fields["text"] = string(b)
		return r
	}

	// Leading printable ASCII then binary, but without the Supermicro "MS"
	// marker. Attribution is unknown (embedded serial/MAC blob); do not call
	// it HPE.
	if printableRatio(b[:6]) >= 0.9 && printableRatio(b[6:]) < 0.5 {
		r.Family = "printable-prefix-binary"
		r.Vendor = "unknown"
		r.Fields["prefix"] = string(b[:6])
		r.Fields["binary"] = hex.EncodeToString(b[6:])
		return r
	}

	// UUID v1: version nibble = 1 in the high nibble of byte 6 (big-endian
	// time fields per RFC 4122 - some BMCs emit little-endian-as-sent order,
	// matching the wire.
	if b[6]&0xf0 == 0x10 {
		r.Family = "uuidv1"
		r.Vendor = "unknown" // node MAC OUI is the clue
		mac := b[10:16]
		r.Fields["node_mac"] = fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x",
			mac[0], mac[1], mac[2], mac[3], mac[4], mac[5])
		r.Fields["oui"] = fmt.Sprintf("%02x:%02x:%02x", mac[0], mac[1], mac[2])

		tsLow := le32(b[0:4])
		tsMid := le16(b[4:6])
		tsHi := le16(b[6:8]) & 0x0fff
		ts := (uint64(tsHi) << 48) | (uint64(tsMid) << 32) | uint64(tsLow)
		// 100ns ticks since 1582-10-15 UTC -> unix
		unix := int64(ts/10_000_000) - 12219292800
		if unix > 0 && unix < 1<<40 {
			r.Fields["unix"] = fmt.Sprintf("%d", unix)
			r.Fields["time"] = time.Unix(unix, 0).UTC().Format("2006-01-02T15:04:05Z")
		}
		return r
	}

	// Lenovo IMM v1: zeroed prefix + signature blob.
	if b[0] == 0 && b[1] == 0 && b[2] == 0 && b[3] == 0 && b[4] != 0 {
		r.Family = "lenovo-imm-like"
		r.Vendor = "lenovo"
		r.Fields["body"] = hex.EncodeToString(b[4:])
		return r
	}

	// Known OEM firmware-family markers.
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

// isHPEPrintable reports whether b matches the strict HPE iLO GUID layout:
// a 6-char part-id, a 3-char plant/country code, and a 6-8 char serial, all
// uppercase-alphanumeric, optionally zero-padded at the tail. This is the
// same shape as the runZero platform decoder's hpRegex
// (^[A-Z0-9]{6}[A-Z0-9]{3}[A-Z0-9]{6,8}\x00*$) and is mutually exclusive with
// the Supermicro "MS"-marker layout.
func isHPEPrintable(b []byte) bool {
	if len(b) != 16 {
		return false
	}
	// The first 9 bytes (part-id + country) must be uppercase-alnum.
	for i := range 9 {
		if !isUpperAlnum(b[i]) {
			return false
		}
	}
	// The serial: 6-8 uppercase-alnum bytes, then zero padding only.
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

// hasHPEModelPrefix reports whether b starts with a known HPE ProLiant model
// family prefix (DL/ML/BL/SL/XL). Used as a secondary HPE signal for printable
// GUIDs that don't fit the strict part-id/country/serial layout.
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
