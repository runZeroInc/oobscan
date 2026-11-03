// Package telnet provides RFC 854 IAC option parsing and lightweight negotiation for
// banner-reading probes on Perle IOLAN's diagnostic port, the Lantronix Setup service
// and other serial-console listeners that speak telnet-flavoured framing over raw
// TCP.
//
// The parser keeps negotiation separate from visible banner text: IAC commands become
// tokens interleaved with the visible bytes, so a finding's banner field still shows
// what was negotiated. Negotiation is answered by refusing every offer, the minimal
// legal response that stops the peer's loop and coaxes out its real banner.
package telnet

import (
	"slices"
	"strconv"
	"strings"
)

// RFC 854 command bytes.
const (
	IAC  byte = 0xFF
	DONT byte = 0xFE
	DO   byte = 0xFD
	WONT byte = 0xFC
	WILL byte = 0xFB
	SB   byte = 0xFA
	GA   byte = 0xF9
	EL   byte = 0xF8
	EC   byte = 0xF7
	AYT  byte = 0xF6
	AO   byte = 0xF5
	IP   byte = 0xF4
	BRK  byte = 0xF3
	DM   byte = 0xF2
	NOP  byte = 0xF1
	SE   byte = 0xF0
)

// optionNames maps RFC-registered telnet option numbers to a short label.
// Kept in sync with the platform's telnet protocol package.
var optionNames = map[byte]string{
	0:   "Binary",
	1:   "Echo",
	2:   "Reconnection",
	3:   "Suppress Go Ahead",
	4:   "Approx Message Size Negotiation",
	5:   "Status",
	6:   "Timing Mark",
	7:   "Remote Controlled Trans and Echo",
	8:   "Output Line Width",
	9:   "Output Page Size",
	10:  "Output CR Disposition",
	11:  "Output HT Stops",
	12:  "Output HT Disposition",
	13:  "Output FF Disposition",
	14:  "Output VT Stops",
	15:  "Output VT Disposition",
	16:  "Output LF Disposition",
	17:  "Extended ASCII",
	18:  "Logout",
	19:  "Byte Macro",
	20:  "Data Entry Terminal",
	21:  "SUPDUP",
	22:  "SUPDUP Output",
	23:  "Send Location",
	24:  "Terminal Type",
	25:  "End of Record",
	26:  "TACACS User Identification",
	27:  "Output Marking",
	28:  "Terminal Location Number",
	29:  "Telnet 3270 Regime",
	30:  "X.3 PAD",
	31:  "NAWS",
	32:  "Terminal Speed",
	33:  "Remote Flow Control",
	34:  "Linemode",
	35:  "X Display Location",
	36:  "Environment",
	37:  "Authentication",
	38:  "Encryption",
	39:  "New Environment",
	40:  "TN3270E",
	41:  "XAUTH",
	42:  "Charset",
	43:  "Telnet Remote Serial Port",
	44:  "Com Port Control",
	45:  "Telnet Suppress Local Echo",
	46:  "Start TLS",
	47:  "Kermit",
	48:  "Send URL",
	49:  "Forward X",
	255: "Extended-Options-List",
}

// OptionName returns a short human label for a telnet option number, falling
// back to the numeric form if the option isn't in the registry.
func OptionName(opt byte) string {
	if name, ok := optionNames[opt]; ok {
		return name
	}
	return "Opt-" + strconv.Itoa(int(opt))
}

// commandName returns the short label for the IAC command byte immediately
// following an IAC 0xFF marker.
func commandName(cmd byte) string {
	switch cmd {
	case WILL:
		return "WILL"
	case WONT:
		return "WONT"
	case DO:
		return "DO"
	case DONT:
		return "DONT"
	case SB:
		return "SB"
	case SE:
		return "SE"
	case GA:
		return "GA"
	case EL:
		return "EL"
	case EC:
		return "EC"
	case AYT:
		return "AYT"
	case AO:
		return "AO"
	case IP:
		return "IP"
	case BRK:
		return "BRK"
	case DM:
		return "DM"
	case NOP:
		return "NOP"
	default:
		return "CMD-" + strconv.Itoa(int(cmd))
	}
}

// IACResult is the output of ParseIAC.
type IACResult struct {
	// Visible is the non-IAC byte stream, i.e. whatever the peer's banner
	// would have been if we simply dropped IAC negotiation bytes. It is not
	// otherwise sanitised.
	Visible []byte
	// Annotated is the human-readable rendering with IAC commands interleaved
	// as tokens (e.g. "<DO Echo>", "<WILL Suppress Go Ahead>"). Printable
	// visible bytes are preserved inline; non-printable bytes are dropped.
	Annotated string
	// Responses is the minimal RFC 854 reject payload: WILL->DONT, DO->WONT.
	// Callers should write this back to the peer so the negotiation loop
	// terminates and the peer emits its real banner.
	Responses []byte
	// HasIAC records whether any IAC command byte was seen.
	HasIAC bool
	// Options tracks which options were offered under each verb, so callers
	// can surface the negotiated shape (WillEcho, DoNAWS, ...) if desired.
	Will []byte
	Wont []byte
	Do   []byte
	Dont []byte
}

// ParseIAC scans data and returns the visible byte stream, a human-readable
// annotated form (with `<VERB Option>` tokens for IAC commands), the
// minimal set of reject-response bytes that should be written back to the
// peer, and per-verb option lists. The parser is defensive: truncated IAC
// sequences at the tail of `data` are ignored (not treated as an error).
func ParseIAC(data []byte) IACResult {
	var (
		visible []byte
		ann     strings.Builder
		resp    []byte
		res     IACResult
	)
	for i := 0; i < len(data); i++ {
		b := data[i]
		if b != IAC {
			visible = append(visible, b)
			if b == '\r' || b == '\n' || b == '\t' || (b >= 0x20 && b < 0x7f) {
				ann.WriteByte(b)
			}
			continue
		}
		res.HasIAC = true
		if i+1 >= len(data) {
			break // truncated: bare IAC at tail
		}
		cmd := data[i+1]
		// IAC IAC = literal 0xff byte in the data stream.
		if cmd == IAC {
			visible = append(visible, IAC)
			i++
			continue
		}
		// Two-byte IAC commands (no option follows).
		if cmd < WILL || cmd > DONT {
			// GA/NOP/AYT/... are 2 bytes total.
			ann.WriteString("<")
			ann.WriteString(commandName(cmd))
			ann.WriteString(">")
			i++
			continue
		}
		// Three-byte option negotiation: IAC <cmd> <opt>.
		if i+2 >= len(data) {
			break // truncated option
		}
		opt := data[i+2]
		ann.WriteString("<")
		ann.WriteString(commandName(cmd))
		ann.WriteString(" ")
		ann.WriteString(OptionName(opt))
		ann.WriteString(">")
		switch cmd {
		case WILL:
			res.Will = appendUnique(res.Will, opt)
			resp = append(resp, IAC, DONT, opt)
		case WONT:
			res.Wont = appendUnique(res.Wont, opt)
		case DO:
			res.Do = appendUnique(res.Do, opt)
			resp = append(resp, IAC, WONT, opt)
		case DONT:
			res.Dont = appendUnique(res.Dont, opt)
		}
		i += 2
	}
	res.Visible = visible
	res.Annotated = ann.String()
	res.Responses = resp
	return res
}

func appendUnique(dst []byte, v byte) []byte {
	if slices.Contains(dst, v) {
		return dst
	}
	return append(dst, v)
}

// iacOptionSlug converts a telnet option name to a lowercase, hyphen-separated
// slug used in the telnet_iac CSV field (e.g. "Suppress Go Ahead" -> "suppress-go-ahead").
func iacOptionSlug(opt byte) string {
	name := OptionName(opt)
	return strings.ToLower(strings.ReplaceAll(name, " ", "-"))
}

// IACString returns a compact CSV summary of every IAC option the peer
// offered or refused during the exchange, ordered will/wont/do/dont by
// encounter order. Each token is "<verb>-<option-slug>", e.g.
// "will-echo,will-suppress-go-ahead". Returns "" when no IAC was observed.
func (r BannerResult) IACString() string {
	if !r.HasIAC {
		return ""
	}
	var parts []string
	for _, o := range r.Will {
		parts = append(parts, "will-"+iacOptionSlug(o))
	}
	for _, o := range r.Wont {
		parts = append(parts, "wont-"+iacOptionSlug(o))
	}
	for _, o := range r.Do {
		parts = append(parts, "do-"+iacOptionSlug(o))
	}
	for _, o := range r.Dont {
		parts = append(parts, "dont-"+iacOptionSlug(o))
	}
	return strings.Join(parts, ",")
}
