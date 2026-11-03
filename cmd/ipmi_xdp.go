package cmd

import (
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"

	"github.com/runZeroInc/oobscan/pkg/ipmi"
)

// RemoteXDP (Intel At-Scale-Debug) is toggled through H3C's OEM
// GetServiceConf/SetServiceConf handlers in libplatoemipmi.so. The outer OEM
// group dispatcher strips two control bytes before checking the 3-byte
// manufacturer id, so the raw handler payload is:
//
//	control[2] manufacturer[3] subcommand[1] service-id-le32[4] [set-fields...]
//
// The exact command id / control / subcommand tuple is not published, so this
// handler mirrors the validated lab probe (enable-remotexdp-ipmi.py): it
// discovers a GetServiceConf route that returns a plausible service config, then
// issues SetServiceConf on that route. Every field can be pinned via key=value
// overrides to skip discovery on a known target.
var (
	ipmiXDPNetFnCandidates     = []byte{0x36}
	ipmiXDPCmdCandidates       = []byte{0x01, 0x22, 0x2C, 0x50, 0x02, 0x03, 0x04, 0x05, 0x07, 0x09, 0x0A, 0x0B, 0x0D, 0x0E, 0x12, 0x14, 0x20, 0x21, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0xFC, 0xFD, 0xFE}
	ipmiXDPControlCandidates   = [][2]byte{{0x04, 0x01}, {0x00, 0x01}, {0x04, 0x00}, {0x00, 0x00}}
	ipmiXDPManufacturers       = [][3]byte{{0xA2, 0x63, 0x00}, {0x20, 0x14, 0x00}}
	ipmiXDPSubcommands         = []byte{0x01, 0x00, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F}
	ipmiXDPServiceIDCandidates = []uint32{0x00000400, 0x00001000, 0x00004000, 0x00000040, 0x00000080, 0x00000200, 0x00000800}
)

// ipmiXDPRoute identifies the OEM handler tuple used for Get/SetServiceConf.
type ipmiXDPRoute struct {
	NetFn        byte
	Cmd          byte
	Control      [2]byte
	Manufacturer [3]byte
	Subcommand   byte
	ServiceID    uint32
}

func (r ipmiXDPRoute) String() string {
	return fmt.Sprintf("netfn=0x%02x cmd=0x%02x control=%02x,%02x mfr=%02x,%02x,%02x subcmd=0x%02x sid=0x%08x",
		r.NetFn, r.Cmd, r.Control[0], r.Control[1], r.Manufacturer[0], r.Manufacturer[1], r.Manufacturer[2], r.Subcommand, r.ServiceID)
}

func (r ipmiXDPRoute) getPayload() []byte {
	p := []byte{r.Control[0], r.Control[1], r.Manufacturer[0], r.Manufacturer[1], r.Manufacturer[2], r.Subcommand}
	sid := make([]byte, 4)
	binary.LittleEndian.PutUint32(sid, r.ServiceID)
	return append(p, sid...)
}

// ipmiXDPSetConfig is the settable SetServiceConf field set. Fields left nil are
// sent as "unchanged" (0xFFFFFFFF for ports/timeout). The two editable-mask
// bytes control which fields the handler applies; the validated lab default is
// 0x80/0x80 (CurrentState + NonsecurePort). Bits beyond those defaults are
// unconfirmed, so raise them via editmask= only when you know the target layout.
type ipmiXDPSetConfig struct {
	enable         bool
	nonsecurePort  int
	securePort     *uint32
	sessionTimeout *uint32
	editState      byte
	editPort       byte
}

func (r ipmiXDPRoute) setPayload(cfg ipmiXDPSetConfig) []byte {
	p := r.getPayload()
	state := byte(0)
	if cfg.enable {
		state = 1
	}
	securePort := uint32(0xFFFFFFFF) // unchanged
	if cfg.securePort != nil {
		securePort = *cfg.securePort
	}
	timeout := uint32(0) // validated lab default keeps this zero unless overridden
	if cfg.sessionTimeout != nil {
		timeout = *cfg.sessionTimeout
	}
	sp := make([]byte, 4)
	binary.LittleEndian.PutUint32(sp, securePort)
	to := make([]byte, 4)
	binary.LittleEndian.PutUint32(to, timeout)
	p = append(p,
		state,                                                     // CurrentState
		byte(cfg.nonsecurePort), byte(cfg.nonsecurePort>>8), 0, 0, // NonsecurePort (LE32)
		sp[0], sp[1], sp[2], sp[3], // SecurePort (LE32; 0xFFFFFFFF = unchanged)
		to[0], to[1], to[2], to[3], // SessionTimeout (LE32)
		cfg.editState, // CurrentState/state editable mask
		cfg.editPort,  // Port/config editable mask
	)
	return p
}

// ipmiXDPPlausibleGet mirrors plausible_get_response from the lab probe.
func ipmiXDPPlausibleGet(data []byte) bool {
	if len(data) < 8 {
		return false
	}
	if data[0] != 0x00 && data[0] != 0xA2 && data[0] != 0x20 {
		return false
	}
	if len(data) >= 0x1F {
		return data[8] == 0 || data[8] == 1 || data[8] == 0x80 || data[8] == 0x81
	}
	return false
}

func ipmiXDPParseGet(data []byte) map[string]any {
	if len(data) < 0x1F {
		return map[string]any{"responseHex": bytesToHex(data)}
	}
	return map[string]any{
		"serviceID":      fmt.Sprintf("0x%08x", binary.LittleEndian.Uint32(data[4:8])),
		"currentState":   data[8] & 1,
		"nonsecurePort":  binary.LittleEndian.Uint32(data[9:13]),
		"securePort":     binary.LittleEndian.Uint32(data[13:17]),
		"sessionTimeout": binary.LittleEndian.Uint32(data[17:21]),
		"maxSession":     data[21] & 0x7F,
		"activeSession":  data[22] & 0x7F,
	}
}

// runIPMIXDP handles: xdp enable|disable|status [port] [key=value ...]
//
// Overrides (skip/pin discovery): netfn, cmd, control (aa,bb), mfr (aa,bb,cc),
// subcmd, sid, maxprobes, and the flag token "nodiscover".
func runIPMIXDP(sess *ipmi.CmdSess, args []string) (any, error) {
	if len(args) == 0 {
		return nil, fmt.Errorf("usage: xdp <enable|disable|status> [port] [key=value ...]")
	}
	action := strings.ToLower(args[0])
	switch action {
	case "enable", "disable", "status", "probe":
	default:
		return nil, fmt.Errorf("unsupported xdp action %q (want enable|disable|status)", args[0])
	}

	port := 6868
	maxProbes := 512
	noDiscover := false
	editState := byte(0x80)
	editPort := byte(0x80)
	var (
		ovNetFn, ovCmd, ovSubcmd *byte
		ovControl                *[2]byte
		ovMfr                    *[3]byte
		ovSID                    *uint32
		securePort               *uint32
		sessionTimeout           *uint32
	)

	for _, a := range args[1:] {
		if a == "nodiscover" {
			noDiscover = true
			continue
		}
		k, v, ok := strings.Cut(a, "=")
		if !ok {
			// bare positional: treat as port
			p, err := strconv.Atoi(a)
			if err != nil {
				return nil, fmt.Errorf("invalid port/argument %q", a)
			}
			port = p
			continue
		}
		switch strings.ToLower(k) {
		case "port":
			p, err := strconv.Atoi(v)
			if err != nil {
				return nil, fmt.Errorf("invalid port %q", v)
			}
			port = p
		case "maxprobes":
			p, err := strconv.Atoi(v)
			if err != nil {
				return nil, fmt.Errorf("invalid maxprobes %q", v)
			}
			maxProbes = p
		case "secureport", "tlsport":
			p, err := strconv.Atoi(v)
			if err != nil {
				return nil, fmt.Errorf("invalid secureport %q", v)
			}
			sp := uint32(p)
			securePort = &sp
		case "timeout", "sessiontimeout":
			p, err := strconv.Atoi(v)
			if err != nil {
				return nil, fmt.Errorf("invalid timeout %q", v)
			}
			st := uint32(p)
			sessionTimeout = &st
		case "editmask":
			parts := strings.Split(v, ",")
			if len(parts) != 2 {
				return nil, fmt.Errorf("editmask wants two bytes, e.g. editmask=80,80")
			}
			e0, err := parseByteArg(parts[0])
			if err != nil {
				return nil, fmt.Errorf("invalid editmask: %w", err)
			}
			e1, err := parseByteArg(parts[1])
			if err != nil {
				return nil, fmt.Errorf("invalid editmask: %w", err)
			}
			editState, editPort = e0, e1
		case "netfn":
			b, err := parseByteArg(v)
			if err != nil {
				return nil, fmt.Errorf("invalid netfn: %w", err)
			}
			ovNetFn = &b
		case "cmd":
			b, err := parseByteArg(v)
			if err != nil {
				return nil, fmt.Errorf("invalid cmd: %w", err)
			}
			ovCmd = &b
		case "subcmd":
			b, err := parseByteArg(v)
			if err != nil {
				return nil, fmt.Errorf("invalid subcmd: %w", err)
			}
			ovSubcmd = &b
		case "control":
			parts := strings.Split(v, ",")
			if len(parts) != 2 {
				return nil, fmt.Errorf("control wants two bytes, e.g. control=04,01")
			}
			c0, err := parseByteArg(parts[0])
			if err != nil {
				return nil, fmt.Errorf("invalid control: %w", err)
			}
			c1, err := parseByteArg(parts[1])
			if err != nil {
				return nil, fmt.Errorf("invalid control: %w", err)
			}
			ovControl = &[2]byte{c0, c1}
		case "mfr", "manufacturer":
			parts := strings.Split(v, ",")
			if len(parts) != 3 {
				return nil, fmt.Errorf("mfr wants three bytes, e.g. mfr=a2,63,00")
			}
			var m [3]byte
			for i := range 3 {
				b, err := parseByteArg(parts[i])
				if err != nil {
					return nil, fmt.Errorf("invalid mfr: %w", err)
				}
				m[i] = b
			}
			ovMfr = &m
		case "sid", "serviceid":
			n, err := strconv.ParseUint(strings.TrimPrefix(strings.ToLower(v), "0x"), 16, 32)
			if err != nil {
				// try decimal
				n, err = strconv.ParseUint(v, 10, 32)
				if err != nil {
					return nil, fmt.Errorf("invalid sid %q", v)
				}
			}
			s := uint32(n)
			ovSID = &s
		default:
			return nil, fmt.Errorf("unknown xdp option %q", k)
		}
	}

	// Build an explicit route when fully pinned (or nodiscover requested).
	cfg := ipmiXDPSetConfig{
		enable:         action == "enable",
		nonsecurePort:  port,
		securePort:     securePort,
		sessionTimeout: sessionTimeout,
		editState:      editState,
		editPort:       editPort,
	}
	if noDiscover || (ovCmd != nil && ovControl != nil && ovMfr != nil && ovSubcmd != nil) {
		route := ipmiXDPRoute{
			NetFn:        firstByte(ovNetFn, ipmiXDPNetFnCandidates[0]),
			Cmd:          firstByte(ovCmd, ipmiXDPCmdCandidates[0]),
			Control:      firstControl(ovControl),
			Manufacturer: firstMfr(ovMfr),
			Subcommand:   firstByte(ovSubcmd, ipmiXDPSubcommands[0]),
			ServiceID:    firstSID(ovSID),
		}
		return ipmiXDPApply(sess, route, action, cfg)
	}

	// Discover a GetServiceConf route.
	route, before, found := ipmiXDPDiscover(sess, ovNetFn, ovCmd, ovSubcmd, ovControl, ovMfr, ovSID, maxProbes)
	if !found {
		return nil, fmt.Errorf("no GetServiceConf route matched (try pinning cmd=/control=/mfr=/subcmd= and nodiscover, or raise maxprobes=)")
	}
	log().Infof("xdp: matched route %s", route.String())
	if action == "status" || action == "probe" {
		out := map[string]any{"route": route.String(), "config": ipmiXDPParseGet(before)}
		return out, nil
	}
	return ipmiXDPApply(sess, route, action, cfg)
}

func ipmiXDPApply(sess *ipmi.CmdSess, route ipmiXDPRoute, action string, cfg ipmiXDPSetConfig) (any, error) {
	if action == "status" || action == "probe" {
		cc, resp, err := sess.ExecRaw(route.NetFn, route.Cmd, route.getPayload())
		if err != nil {
			return nil, err
		}
		out := map[string]any{"route": route.String(), "completionCode": fmt.Sprintf("0x%02x", cc)}
		if cc == 0 {
			out["config"] = ipmiXDPParseGet(resp)
		} else {
			out["responseHex"] = bytesToHex(resp)
		}
		return out, nil
	}
	cc, resp, err := sess.ExecRaw(route.NetFn, route.Cmd, route.setPayload(cfg))
	if err != nil {
		return nil, err
	}
	out := map[string]any{
		"action":         "xdp " + action,
		"route":          route.String(),
		"port":           cfg.nonsecurePort,
		"completionCode": fmt.Sprintf("0x%02x", cc),
		"ok":             cc == 0,
		"responseHex":    bytesToHex(resp),
	}
	if cfg.securePort != nil {
		out["securePort"] = *cfg.securePort
	}
	if cfg.sessionTimeout != nil {
		out["sessionTimeout"] = *cfg.sessionTimeout
	}
	if cc != 0 {
		return out, fmt.Errorf("SetServiceConf rejected with completion code 0x%02x", cc)
	}
	// Read back.
	if rc, rresp, rerr := sess.ExecRaw(route.NetFn, route.Cmd, route.getPayload()); rerr == nil && rc == 0 {
		out["config"] = ipmiXDPParseGet(rresp)
	}
	return out, nil
}

func ipmiXDPDiscover(sess *ipmi.CmdSess, ovNetFn, ovCmd, ovSubcmd *byte, ovControl *[2]byte, ovMfr *[3]byte, ovSID *uint32, maxProbes int) (ipmiXDPRoute, []byte, bool) {
	netfns := ipmiXDPNetFnCandidates
	if ovNetFn != nil {
		netfns = []byte{*ovNetFn}
	}
	cmds := ipmiXDPCmdCandidates
	if ovCmd != nil {
		cmds = []byte{*ovCmd}
	}
	controls := ipmiXDPControlCandidates
	if ovControl != nil {
		controls = [][2]byte{*ovControl}
	}
	mfrs := ipmiXDPManufacturers
	if ovMfr != nil {
		mfrs = [][3]byte{*ovMfr}
	}
	subs := ipmiXDPSubcommands
	if ovSubcmd != nil {
		subs = []byte{*ovSubcmd}
	}
	sids := ipmiXDPServiceIDCandidates
	if ovSID != nil {
		sids = []uint32{*ovSID}
	}

	tried := 0
	for _, netfn := range netfns {
		for _, cmd := range cmds {
			for _, control := range controls {
				for _, mfr := range mfrs {
					for _, sub := range subs {
						for _, sid := range sids {
							if tried >= maxProbes {
								return ipmiXDPRoute{}, nil, false
							}
							tried++
							route := ipmiXDPRoute{NetFn: netfn, Cmd: cmd, Control: control, Manufacturer: mfr, Subcommand: sub, ServiceID: sid}
							cc, resp, err := sess.ExecRaw(netfn, cmd, route.getPayload())
							if err != nil || cc != 0 {
								continue
							}
							if ipmiXDPPlausibleGet(resp) {
								return route, resp, true
							}
						}
					}
				}
			}
		}
	}
	return ipmiXDPRoute{}, nil, false
}

func firstByte(p *byte, def byte) byte {
	if p != nil {
		return *p
	}
	return def
}

func firstControl(p *[2]byte) [2]byte {
	if p != nil {
		return *p
	}
	return ipmiXDPControlCandidates[0]
}

func firstMfr(p *[3]byte) [3]byte {
	if p != nil {
		return *p
	}
	return ipmiXDPManufacturers[0]
}

func firstSID(p *uint32) uint32 {
	if p != nil {
		return *p
	}
	return ipmiXDPServiceIDCandidates[0]
}
