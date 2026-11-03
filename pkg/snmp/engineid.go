package snmp

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
)

// EngineIDInfo is a decoded SNMPv3 USM authoritative engine ID (RFC 3411,
// SNMP-FRAMEWORK-MIB SnmpEngineID TEXTUAL-CONVENTION).
//
// The standard layout is 5+ bytes: a 4-byte IANA enterprise number with its
// high bit set (so it never collides with the legacy pre-RFC3411 formats),
// followed by a 1-byte format indicator, followed by a variable-length
// enterprise-defined suffix:
//
//	byte 0-3: 0x80000000 | enterprise number (big-endian)
//	byte 4:   format (1=IPv4, 2=IPv6, 3=MAC, 4=administratively-assigned text,
//	          5=administratively-assigned octets, 128-255=enterprise-specific)
//	byte 5+:  the format-specific identifier
//
// Vendors frequently stuff a product code or serial number into the suffix
// (format 4/5), which is a useful pre-auth identification signal alongside
// the enterprise number itself.
type EngineIDInfo struct {
	Hex        string
	Enterprise uint32 // IANA enterprise number; 0 if not the standard RFC 3411 format
	Vendor     string // from VendorByEnterpriseID, "" if unmapped
	Format     byte   // RFC 3411 format octet; only meaningful when Enterprise != 0
	FormatName string
	Suffix     string // decoded suffix (ASCII text, dotted IPv4, colon-separated MAC), "" if undecodable
}

// DecodeEngineIDHex decodes a hex-encoded SNMPv3 engine ID, as stored in
// snmp.Result.EngineID.
func DecodeEngineIDHex(s string) (*EngineIDInfo, error) {
	b, err := hex.DecodeString(strings.TrimSpace(s))
	if err != nil {
		return nil, fmt.Errorf("hex: %w", err)
	}
	return DecodeEngineID(b), nil
}

// DecodeEngineID decodes a raw SNMPv3 engine ID. Returns a non-nil
// *EngineIDInfo even when the format is not recognised (Enterprise stays 0).
func DecodeEngineID(b []byte) *EngineIDInfo {
	r := &EngineIDInfo{Hex: hex.EncodeToString(b)}
	// The RFC 3411 enterprise format needs the enterprise word (4 bytes) with
	// its high bit set, plus a format octet.
	if len(b) < 5 || b[0]&0x80 == 0 {
		return r
	}
	r.Enterprise = binary.BigEndian.Uint32(b[0:4]) & 0x7fffffff
	r.Vendor = VendorByEnterpriseID[r.Enterprise]
	r.Format = b[4]
	suffix := b[5:]
	switch {
	case r.Format == 1 && len(suffix) == 4:
		r.FormatName = "ipv4"
		r.Suffix = fmt.Sprintf("%d.%d.%d.%d", suffix[0], suffix[1], suffix[2], suffix[3])
	case r.Format == 2 && len(suffix) == 16:
		r.FormatName = "ipv6"
		r.Suffix = hex.EncodeToString(suffix)
	case r.Format == 3 && len(suffix) == 6:
		r.FormatName = "mac"
		parts := make([]string, len(suffix))
		for i, c := range suffix {
			parts[i] = fmt.Sprintf("%02x", c)
		}
		r.Suffix = strings.Join(parts, ":")
	case r.Format == 4:
		r.FormatName = "text"
		r.Suffix = printableASCII(suffix)
	case r.Format == 5:
		r.FormatName = "octets"
		// Octets are not required to be text, but vendors commonly put a
		// human-readable serial/product code here anyway (e.g. HPE iLO); fall
		// back to hex when the bytes are not printable.
		if s := printableASCII(suffix); s != "" {
			r.Suffix = s
		} else {
			r.Suffix = hex.EncodeToString(suffix)
		}
	case r.Format >= 128:
		r.FormatName = "enterprise-specific"
		if s := printableASCII(suffix); s != "" {
			r.Suffix = s
		} else {
			r.Suffix = hex.EncodeToString(suffix)
		}
	default:
		r.FormatName = "reserved"
	}
	return r
}

// printableASCII returns b as a string when every byte is printable ASCII,
// else "".
func printableASCII(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	for _, c := range b {
		if c < 0x20 || c > 0x7e {
			return ""
		}
	}
	return string(b)
}
