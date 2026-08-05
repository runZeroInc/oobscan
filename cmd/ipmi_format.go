package cmd

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/runZeroInc/oobscan/pkg/output"
)

func enabledDisabledWord(v bool) string {
	if v {
		return "enabled"
	}
	return "disabled"
}

func yesNoWord(v bool) string {
	if v {
		return "Yes"
	}
	return "No"
}

func channelAccessAvailable(callinEnabled bool) string {
	if callinEnabled {
		return "call-in / callback"
	}
	return "callback"
}

func channelPrivilegeLabel(priv byte) string {
	switch priv {
	case 0x01:
		return "Callback"
	case 0x02:
		return "User"
	case 0x03:
		return "Operator"
	case 0x04:
		return "ADMINISTRATOR"
	case 0x05:
		return "OEM"
	case 0x0f:
		return "NO ACCESS"
	case 0x00:
		return "Unknown (0x00)"
	default:
		return fmt.Sprintf("Unknown (0x%02x)", priv)
	}
}

func decodeChannelAccessSettings(b byte) ipmiChannelAccessSettings {
	return ipmiChannelAccessSettings{
		Alerting:       (b & 0x20) == 0,
		PerMessageAuth: (b & 0x10) == 0,
		UserLevelAuth:  (b & 0x08) == 0,
		AccessMode:     channelAccessModeLabel(b & 0x07),
	}
}

func channelAccessModeLabel(v byte) string {
	switch v {
	case 0:
		return "disabled"
	case 1:
		return "pre-boot only"
	case 2:
		return "always available"
	case 3:
		return "shared"
	default:
		return fmt.Sprintf("reserved (0x%x)", v)
	}
}

func channelMediumTypeLabel(v byte) string {
	switch v {
	case 0x01:
		return "IPMB (I2C)"
	case 0x04:
		return "802.3 LAN"
	case 0x05:
		return "Asynch Serial/Modem"
	case 0x0e:
		return "SMBus v1.0/1.1"
	case 0x0f:
		return "SMBus v2.0"
	case 0x11:
		return "System Interface"
	default:
		return fmt.Sprintf("0x%02x", v)
	}
}

func channelProtocolTypeLabel(v byte) string {
	switch v {
	case 0x01:
		return "IPMB-1.0"
	case 0x02:
		return "ICMB-1.0"
	case 0x04:
		return "IPMI-SMBus"
	case 0x05:
		return "KCS"
	case 0x06:
		return "SMIC"
	case 0x07:
		return "BT-10"
	case 0x08:
		return "TMode"
	default:
		return fmt.Sprintf("0x%02x", v)
	}
}

func channelSessionSupportLabel(v byte) string {
	switch (v >> 6) & 0x03 {
	case 0:
		return "session-less"
	case 1:
		return "single-session"
	case 2:
		return "multi-session"
	default:
		return "session-based"
	}
}

func boolWord(v bool) string {
	if v {
		return styleOK("yes")
	}
	return styleWarn("no")
}

func formatUserPrivilege(v string) string {
	v = strings.TrimSpace(strings.ToLower(v))
	switch v {
	case "admin", "administrator":
		return styleOK("admin")
	case "operator", "user", "callback", "oem":
		return v
	case "0x0f", "none", "off", "noaccess":
		return styleWarn("none")
	default:
		return sanitizeASCII(v)
	}
}

func writeKVFromJSON(w interface{ Write([]byte) (int, error) }, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	m := map[string]any{}
	if err := json.Unmarshal(b, &m); err != nil {
		return err
	}
	return writeKVMapAny(w, m)
}

func writeKVMapAny(w interface{ Write([]byte) (int, error) }, m map[string]any) error {
	if len(m) == 0 {
		_, err := fmt.Fprintln(w, "(no data)")
		return err
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	rows := make([][]string, 0, len(keys))
	for _, k := range keys {
		rows = append(rows, []string{prettyKey(k), formatAnyTypedValue(k, m[k])})
	}
	return writeASCIITable(w, []string{"Setting", "Value"}, rows)
}

func writeSliceGeneric(w interface{ Write([]byte) (int, error) }, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	items := []map[string]any{}
	if err := json.Unmarshal(b, &items); err != nil {
		_, err2 := fmt.Fprintln(w, string(b))
		return err2
	}
	if len(items) == 0 {
		_, err := fmt.Fprintln(w, "(no rows)")
		return err
	}
	keySet := map[string]struct{}{}
	for _, it := range items {
		for k := range it {
			keySet[k] = struct{}{}
		}
	}
	keys := make([]string, 0, len(keySet))
	for k := range keySet {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	headers := make([]string, 0, len(keys))
	for _, k := range keys {
		headers = append(headers, prettyKey(k))
	}
	rows := make([][]string, 0, len(items))
	for _, it := range items {
		row := make([]string, 0, len(keys))
		for _, k := range keys {
			row = append(row, formatAnyTypedValue(k, it[k]))
		}
		rows = append(rows, row)
	}
	return writeASCIITable(w, headers, rows)
}

func anyToString(v any) string {
	if v == nil {
		return ""
	}
	switch x := v.(type) {
	case string:
		return x
	case bool:
		if x {
			return "true"
		}
		return "false"
	case float64:
		if x == float64(int64(x)) {
			return strconv.FormatInt(int64(x), 10)
		}
		return strconv.FormatFloat(x, 'f', -1, 64)
	default:
		b, err := json.Marshal(x)
		if err != nil {
			return fmt.Sprintf("%v", x)
		}
		return string(b)
	}
}

func formatAnyTypedValue(key string, v any) string {
	if v == nil {
		return ""
	}
	switch x := v.(type) {
	case bool:
		return boolWord(x)
	case string:
		return formatTypedValue(key, x)
	default:
		return formatTypedValue(key, anyToString(v))
	}
}

func formatTypedValue(key, value string) string {
	k := strings.ToLower(strings.TrimSpace(key))
	v := strings.TrimSpace(value)
	if v == "" {
		return ""
	}

	if isBoolText(v) {
		return formatBoolText(v)
	}

	if strings.HasSuffix(k, "responsehex") || strings.HasSuffix(k, "responsebytes") {
		if strings.HasSuffix(k, "responsebytes") {
			if out, ok := normalizeHexArrayString(v); ok {
				return out
			}
		}
		return strings.ToUpper(sanitizeASCII(v))
	}

	if strings.Contains(k, "bitrate") || strings.Contains(k, "bit_rate") {
		if n, ok := parseLooseInt(v); ok {
			if name, ok := solBitrateLabel(byte(n)); ok {
				return fmt.Sprintf("%s (%d)", name, n)
			}
		}
	}

	if strings.Contains(k, "payloadport") || strings.Contains(k, "payload_port") {
		if after, ok := strings.CutPrefix(strings.ToLower(v), "0x"); ok {
			if b, err := hex.DecodeString(after); err == nil && len(b) >= 2 {
				p := binary.LittleEndian.Uint16(b[:2])
				return fmt.Sprintf("%d", p)
			}
		}
	}

	if strings.Contains(k, "completioncode") || strings.Contains(k, "completion_code") {
		if strings.EqualFold(v, "0x00") {
			return styleOK(v)
		}
		if strings.HasPrefix(strings.ToLower(v), "0x") {
			return styleWarn(v)
		}
	}

	if strings.HasPrefix(strings.ToLower(v), "0x") {
		return strings.ToLower(sanitizeASCII(v))
	}
	return sanitizeASCII(v)
}

func isBoolText(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "true", "false", "yes", "no", "on", "off", "enabled", "disabled":
		return true
	default:
		return false
	}
}

func formatBoolText(v string) string {
	s := strings.ToLower(strings.TrimSpace(v))
	switch s {
	case "true", "yes", "on", "enabled":
		return styleOK("yes")
	default:
		return styleWarn("no")
	}
}

func parseLooseInt(v string) (int, bool) {
	orig := strings.TrimSpace(strings.ToLower(v))
	v = orig
	base := 10
	if after, ok := strings.CutPrefix(v, "0x"); ok {
		v = after
		base = 16
	}
	if v == "" {
		return 0, false
	}
	n, err := strconv.ParseInt(v, base, 64)
	if err != nil {
		if orig != "" {
			n2, err2 := strconv.ParseInt(orig, 10, 64)
			if err2 == nil {
				return int(n2), true
			}
		}
		return 0, false
	}
	return int(n), true
}

func prettyKey(k string) string {
	k = strings.TrimSpace(strings.ReplaceAll(strings.ReplaceAll(k, "_", " "), "-", " "))
	if k == "" {
		return ""
	}
	l := strings.ToLower(k)
	special := map[string]string{
		"set in progress":            "Set in Progress",
		"enabled":                    "Enabled",
		"authentication":             "Authentication",
		"character accumulate level": "Character Accumulate Level (ms)",
		"character send threshold":   "Character Send Threshold",
		"retry count":                "Retry Count",
		"retry interval":             "Retry Interval (ms)",
		"volatile bit rate":          "Volatile Bit Rate (kbps)",
		"non volatile bit rate":      "Non-Volatile Bit Rate (kbps)",
		"payload channel":            "Payload Channel",
		"payload port":               "Payload Port",
		"completioncode":             "Completion Code",
		"responsehex":                "Response Hex",
		"responsebytes":              "Response Bytes",
		"ipmiauth":                   "IPMI Auth",
		"linkauth":                   "Link Auth",
	}
	if v, ok := special[l]; ok {
		return v
	}
	return formatTitleCase(k)
}

func formatTitleCase(v string) string {
	parts := strings.Fields(strings.TrimSpace(v))
	for i, p := range parts {
		u := strings.ToUpper(p)
		switch u {
		case "IPMI", "LAN", "LAN6", "FRU", "OEM", "ID", "I2C", "SPD", "SOL":
			parts[i] = u
		default:
			if len(p) == 1 {
				parts[i] = strings.ToUpper(p)
			} else {
				parts[i] = strings.ToUpper(p[:1]) + strings.ToLower(p[1:])
			}
		}
	}
	return strings.Join(parts, " ")
}

func isSOLInfoMap(v map[string]string) bool {
	if len(v) == 0 {
		return false
	}
	_, okA := v["set_in_progress"]
	_, okB := v["enabled"]
	_, okC := v["authentication"]
	return okA || okB || okC
}

func writeSOLInfoTable(w interface{ Write([]byte) (int, error) }, m map[string]string) error {
	ordered := []string{
		"set_in_progress",
		"enabled",
		"authentication",
		"character_accumulate_level",
		"character_send_threshold",
		"retry_count",
		"retry_interval",
		"volatile_bit_rate",
		"non_volatile_bit_rate",
		"payload_channel",
		"payload_port",
	}
	rows := make([][]string, 0, len(ordered))
	for _, k := range ordered {
		raw, ok := m[k]
		if !ok || strings.TrimSpace(raw) == "" {
			continue
		}
		rows = append(rows, []string{prettyKey(k), decodeSOLValue(k, raw)})
	}
	if len(rows) == 0 {
		return writeKVMapAny(w, map[string]any{"sol": "no data"})
	}
	return writeASCIITable(w, []string{"Setting", "Value"}, rows)
}

func decodeSOLValue(key, hexValue string) string {
	data, err := hex.DecodeString(strings.TrimSpace(hexValue))
	if err != nil || len(data) == 0 {
		return sanitizeASCII(hexValue)
	}
	b0 := data[0]
	switch key {
	case "set_in_progress":
		switch b0 & 0x03 {
		case 0:
			return styleOK("set-complete")
		case 1:
			return styleWarn("set-in-progress")
		case 2:
			return styleWarn("commit-write")
		default:
			return fmt.Sprintf("reserved (0x%02x)", b0)
		}
	case "enabled":
		if b0&0x01 == 0x01 {
			return styleOK("true")
		}
		return styleWarn("false")
	case "authentication":
		forceAuth := b0&0x01 != 0
		forceEnc := b0&0x02 != 0
		return fmt.Sprintf("force-auth=%s, force-encryption=%s", formatBoolText(strconv.FormatBool(forceAuth)), formatBoolText(strconv.FormatBool(forceEnc)))
	case "character_accumulate_level":
		return fmt.Sprintf("%d", int(b0))
	case "character_send_threshold":
		return fmt.Sprintf("%d", int(b0))
	case "retry_count":
		return fmt.Sprintf("%d", int(b0))
	case "retry_interval":
		return fmt.Sprintf("%d", int(b0))
	case "volatile_bit_rate", "non_volatile_bit_rate":
		if label, ok := solBitrateLabel(b0); ok {
			return label
		}
		return fmt.Sprintf("0x%02x", b0)
	case "payload_channel":
		ch := b0 & 0x0f
		return fmt.Sprintf("%d (0x%02x)", ch, ch)
	case "payload_port":
		if len(data) >= 2 {
			p := binary.LittleEndian.Uint16(data[:2])
			return fmt.Sprintf("%d", p)
		}
		return fmt.Sprintf("%d", int(b0))
	default:
		return strings.ToLower(strings.TrimSpace(hexValue))
	}
}

func solBitrateLabel(v byte) (string, bool) {
	switch v {
	case 0:
		return "serial", true
	case 6:
		return "9.6", true
	case 7:
		return "19.2", true
	case 8:
		return "38.4", true
	case 9:
		return "57.6", true
	case 10:
		return "115.2", true
	default:
		return "", false
	}
}

func normalizeHexArrayString(v string) (string, bool) {
	v = strings.TrimSpace(v)
	if !strings.HasPrefix(v, "[") {
		return "", false
	}
	var parts []string
	if err := json.Unmarshal([]byte(v), &parts); err != nil {
		return "", false
	}
	if len(parts) == 0 {
		return "", false
	}
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		s := strings.ToLower(strings.TrimSpace(p))
		s = strings.TrimPrefix(s, "0x")
		if len(s) == 1 {
			s = "0" + s
		}
		out = append(out, strings.ToUpper(s))
	}
	return strings.Join(out, " "), true
}

func writeASCIITable(w interface{ Write([]byte) (int, error) }, headers []string, rows [][]string) error {
	if len(headers) == 0 {
		_, err := fmt.Fprintln(w, "(no columns)")
		return err
	}
	widths := make([]int, len(headers))
	for i, h := range headers {
		widths[i] = visibleLen(sanitizeASCII(h))
	}
	for _, r := range rows {
		for i := 0; i < len(headers) && i < len(r); i++ {
			v := sanitizeASCIIPreserveANSI(r[i])
			if visibleLen(v) > widths[i] {
				widths[i] = visibleLen(v)
			}
		}
	}

	line := tableLine(widths)
	if _, err := fmt.Fprintln(w, line); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(w, tableRow(widths, headers)); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(w, line); err != nil {
		return err
	}
	for _, r := range rows {
		row := make([]string, len(headers))
		for i := range headers {
			if i < len(r) {
				row[i] = r[i]
			}
		}
		if _, err := fmt.Fprintln(w, tableRow(widths, row)); err != nil {
			return err
		}
	}
	_, err := fmt.Fprintln(w, line)
	return err
}

func tableLine(widths []int) string {
	var b strings.Builder
	b.WriteByte('+')
	for _, w := range widths {
		b.WriteString(strings.Repeat("-", w+2))
		b.WriteByte('+')
	}
	return b.String()
}

func tableRow(widths []int, cols []string) string {
	var b strings.Builder
	b.WriteByte('|')
	for i, w := range widths {
		val := ""
		if i < len(cols) {
			val = sanitizeASCIIPreserveANSI(cols[i])
		}
		if visibleLen(val) > w {
			val = truncateVisible(val, w)
		}
		pad := max(w-visibleLen(val), 0)
		b.WriteByte(' ')
		b.WriteString(val)
		b.WriteString(strings.Repeat(" ", pad+1))
		b.WriteByte('|')
	}
	return b.String()
}

func visibleLen(s string) int {
	return len(ansiSeqRE.ReplaceAllString(s, ""))
}

func truncateVisible(s string, max int) string {
	if max <= 0 {
		return ""
	}
	if visibleLen(s) <= max {
		return s
	}
	plain := ansiSeqRE.ReplaceAllString(s, "")
	if len(plain) <= max {
		return plain
	}
	return plain[:max]
}

func sanitizeASCIIPreserveANSI(s string) string {
	if s == "" {
		return ""
	}
	var b bytes.Buffer
	for i := 0; i < len(s); i++ {
		preservedANSI := false
		if s[i] == 0x1b {
			j := i + 1
			if j < len(s) && s[j] == '[' {
				j++
				for j < len(s) {
					ch := s[j]
					if (ch >= '0' && ch <= '9') || ch == ';' {
						j++
						continue
					}
					if ch == 'm' {
						j++
						b.WriteString(s[i:j])
						i = j - 1
						preservedANSI = true
						break
					}
					break
				}
			}
			if preservedANSI {
				continue
			}
			b.WriteByte('?')
			continue
		}
		c := s[i]
		if c >= 0x20 && c <= 0x7e {
			b.WriteByte(c)
		} else if c == '\n' || c == '\r' || c == '\t' {
			b.WriteByte(' ')
		} else {
			b.WriteByte('?')
		}
	}
	return b.String()
}

func useIPMIColor() bool {
	return !output.Default().NoColor()
}

func styleOK(v string) string {
	v = sanitizeASCII(v)
	if !useIPMIColor() {
		return v
	}
	return "\x1b[32m" + v + "\x1b[0m"
}

func styleWarn(v string) string {
	v = sanitizeASCII(v)
	if !useIPMIColor() {
		return v
	}
	return "\x1b[33m" + v + "\x1b[0m"
}

func sanitizeASCII(s string) string {
	if s == "" {
		return ""
	}
	var b bytes.Buffer
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 0x20 && c <= 0x7e {
			b.WriteByte(c)
		} else if c == '\n' || c == '\r' || c == '\t' {
			b.WriteByte(' ')
		} else {
			b.WriteByte('?')
		}
	}
	return b.String()
}
