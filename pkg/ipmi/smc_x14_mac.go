package ipmi

import (
	"fmt"
	"strings"
)

const smcX14MacCapture = "M=$(cat /sys/class/net/eth0/address 2>/dev/null||cat /var/configuration/macaddr 2>/dev/null||fw_printenv ethaddr 2>/dev/null|cut -d= -f2);[ ${#M} -eq 17 ]||M="

func ValidateSMCX14MAC(s string) bool {
	if len(s) != 17 {
		return false
	}
	for i, c := range s {
		switch {
		case i%3 == 2:
			if c != ':' {
				return false
			}
		default:
			if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
				return false
			}
		}
	}
	return true
}

func ParseX14PSOOBBMAC(data []byte) (string, error) {
	s := string(data)
	const marker = `MacAddr value="`
	i := strings.Index(s, marker)
	if i < 0 {
		return "", fmt.Errorf("MacAddr value attribute not found")
	}
	start := i + len(marker)
	end := strings.Index(s[start:], `"`)
	if end < 0 {
		return "", fmt.Errorf("MacAddr value attribute not terminated")
	}
	mac := s[start : start+end]
	if !ValidateSMCX14MAC(mac) {
		return "", fmt.Errorf("MacAddr value %q is not a valid MAC", mac)
	}
	return mac, nil
}

func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'"'"'`) + "'"
}
