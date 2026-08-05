package snmp

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
)

type EngineIDInfo struct {
	Hex        string
	Enterprise uint32
	Vendor     string
	Format     byte
	FormatName string
	Suffix     string
}

func DecodeEngineIDHex(s string) (*EngineIDInfo, error) {
	b, err := hex.DecodeString(strings.TrimSpace(s))
	if err != nil {
		return nil, fmt.Errorf("hex: %w", err)
	}
	return DecodeEngineID(b), nil
}

func DecodeEngineID(b []byte) *EngineIDInfo {
	r := &EngineIDInfo{Hex: hex.EncodeToString(b)}

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
