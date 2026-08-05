package cmd

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/runZeroInc/oobscan/pkg/ipmi"
)

func runIPMIChannel(sess *ipmi.CmdSess, args []string) (any, error) {
	if len(args) == 0 {
		return nil, fmt.Errorf("usage: %s", ipmiChannelUsage)
	}
	sub := strings.ToLower(strings.TrimSpace(args[0]))
	if sub == "info" {
		ch := 0x0e
		if len(args) >= 2 {
			v, err := strconv.Atoi(args[1])
			if err != nil || v < 0 || v > 0x0f {
				return nil, fmt.Errorf("invalid channel %q", args[1])
			}
			ch = v
		}
		cc, data, err := sess.ExecRaw(ipmi.NetFnApp, ipmi.CmdGetChannelInfo, []byte{byte(ch & 0x0f)})
		if err != nil {
			return nil, err
		}
		if cc != 0x00 || len(data) < 7 {
			return nil, fmt.Errorf("channel info cc=0x%02x len=%d", cc, len(data))
		}
		ccVol, volData, err := sess.ExecRaw(ipmi.NetFnApp, ipmi.CmdGetChannelAccess, []byte{byte(ch & 0x0f), 0x80})
		if err != nil {
			return nil, err
		}
		if ccVol != 0x00 || len(volData) < 1 {
			return nil, fmt.Errorf("channel access (volatile) cc=0x%02x len=%d", ccVol, len(volData))
		}
		ccNV, nvData, err := sess.ExecRaw(ipmi.NetFnApp, ipmi.CmdGetChannelAccess, []byte{byte(ch & 0x0f), 0x40})
		if err != nil {
			return nil, err
		}
		if ccNV != 0x00 || len(nvData) < 1 {
			return nil, fmt.Errorf("channel access (non-volatile) cc=0x%02x len=%d", ccNV, len(nvData))
		}
		vendorID := uint32(data[4]) | uint32(data[5])<<8 | uint32(data[6])<<16
		return &ipmiChannelInfoResult{
			Channel:            int(data[0] & 0x0f),
			MediumType:         channelMediumTypeLabel(data[1]),
			ProtocolType:       channelProtocolTypeLabel(data[2]),
			SessionSupport:     channelSessionSupportLabel(data[3]),
			ActiveSessionCount: int(data[3] & 0x3f),
			ProtocolVendorID:   vendorID,
			Volatile:           decodeChannelAccessSettings(volData[0]),
			NonVolatile:        decodeChannelAccessSettings(nvData[0]),
		}, nil
	}
	if sub == "getaccess" {
		if len(args) < 2 {
			return nil, fmt.Errorf("usage: channel getaccess <channel> [id]")
		}
		channelID, err := strconv.Atoi(args[1])
		if err != nil || channelID < 0 || channelID > 0x0f {
			return nil, fmt.Errorf("invalid channel %q", args[1])
		}
		ch := byte(channelID & 0x0f)
		cc, d, err := sess.ExecRaw(ipmi.NetFnApp, ipmi.CmdGetUserAccess, []byte{ch, 0x01})
		if err != nil {
			return nil, err
		}
		if cc != 0x00 || len(d) < 3 {
			return nil, fmt.Errorf("getaccess bootstrap cc=0x%02x len=%d", cc, len(d))
		}
		maxUsers := int(d[0] & 0x3f)
		if maxUsers <= 0 {
			maxUsers = 16
		}
		if maxUsers > 63 {
			maxUsers = 63
		}
		enabledUsers := int(d[1] & 0x3f)
		fixedNameSlots := int(d[2] & 0x3f)
		startID := 1
		endID := maxUsers
		if len(args) >= 3 {
			oneID, err := strconv.Atoi(args[2])
			if err != nil || oneID < 1 || oneID > maxUsers {
				return nil, fmt.Errorf("invalid id %q", args[2])
			}
			startID = oneID
			endID = oneID
		}
		out := &ipmiChannelAccessResult{
			Channel:        channelID,
			MaxUserIDs:     maxUsers,
			EnabledUserIDs: enabledUsers,
			Users:          make([]ipmiChannelAccessUser, 0, endID-startID+1),
		}
		for uid := startID; uid <= endID; uid++ {
			ccA, dA, err := sess.ExecRaw(ipmi.NetFnApp, ipmi.CmdGetUserAccess, []byte{ch, byte(uid)})
			if err != nil || ccA != 0x00 || len(dA) < 4 {
				continue
			}
			ccN, dN, err := sess.ExecRaw(ipmi.NetFnApp, ipmi.CmdGetUserName, []byte{byte(uid)})
			name := ""
			if err == nil && ccN == 0x00 && len(dN) > 0 {
				name = sanitizeIPMIUserName(dN)
			}
			access := dA[3]
			priv := access & 0x0f
			callinEnabled := (access & 0x40) == 0
			linkAuth := (access & 0x20) != 0
			ipmiAuth := (access & 0x10) != 0
			enabled := uid <= enabledUsers
			if !enabled && (priv != 0 || linkAuth || ipmiAuth || !callinEnabled) {
				enabled = true
			}
			u := ipmiChannelAccessUser{
				ID:          uid,
				Name:        name,
				FixedName:   uid <= fixedNameSlots,
				Callin:      callinEnabled,
				LinkAuth:    linkAuth,
				IPMIAuth:    ipmiAuth,
				Privilege:   priv,
				EnableState: enabled,
			}
			if !u.EnableState && u.Privilege == 0 {
				u.Name = ""
			}
			out.Users = append(out.Users, u)
		}
		return out, nil
	}
	if sub != "setaccess" {
		return nil, fmt.Errorf("invalid CHANNEL command: %s\n\n%s", strings.Join(args, " "), ipmiChannelUsage)
	}
	if len(args) < 7 {
		return nil, fmt.Errorf("usage: channel setaccess <channel> <id> callin=<on|off> ipmi=<on|off> link=<on|off> privilege=<level>")
	}

	channelID, err := strconv.Atoi(args[1])
	if err != nil || channelID < 0 || channelID > 0x0f {
		return nil, fmt.Errorf("invalid channel %q", args[1])
	}
	userID, err := strconv.Atoi(args[2])
	if err != nil || userID < 1 || userID > 63 {
		return nil, fmt.Errorf("invalid id %q", args[2])
	}

	var (
		callinSet bool
		ipmiSet   bool
		linkSet   bool
		privSet   bool

		callinEnabled bool
		ipmiEnabled   bool
		linkEnabled   bool
		priv          byte
	)

	for _, tok := range args[3:] {
		k, v, ok := strings.Cut(tok, "=")
		if !ok {
			return nil, fmt.Errorf("invalid setaccess token %q (want key=value)", tok)
		}
		switch strings.ToLower(strings.TrimSpace(k)) {
		case "callin":
			bv, err := parseOnOff(v)
			if err != nil {
				return nil, fmt.Errorf("invalid callin value %q", v)
			}
			callinEnabled = bv
			callinSet = true
		case "ipmi":
			bv, err := parseOnOff(v)
			if err != nil {
				return nil, fmt.Errorf("invalid ipmi value %q", v)
			}
			ipmiEnabled = bv
			ipmiSet = true
		case "link":
			bv, err := parseOnOff(v)
			if err != nil {
				return nil, fmt.Errorf("invalid link value %q", v)
			}
			linkEnabled = bv
			linkSet = true
		case "privilege", "priv":
			pv, err := ipmi.ParsePrivilege(v)
			if err != nil {
				return nil, fmt.Errorf("invalid privilege %q", v)
			}
			priv = pv
			privSet = true
		default:
			return nil, fmt.Errorf("unsupported setaccess field %q", k)
		}
	}

	if !callinSet || !ipmiSet || !linkSet || !privSet {
		return nil, fmt.Errorf("usage: channel setaccess <channel> <id> callin=<on|off> ipmi=<on|off> link=<on|off> privilege=<level>")
	}

	ch := byte(channelID & 0x0f)
	uid := byte(userID)

	b1 := byte(0x80) | ch
	if !callinEnabled {
		b1 |= 0x40
	}
	if linkEnabled {
		b1 |= 0x20
	}
	if ipmiEnabled {
		b1 |= 0x10
	}
	privByte := priv & 0x0f

	reqVariants := [][]byte{
		{b1, uid, privByte, 0x00},
		{b1, uid, privByte},
	}
	var lastErr error
	for _, req := range reqVariants {
		cc, _, err := sess.ExecRaw(ipmi.NetFnApp, ipmi.CmdSetUserAccess, req)
		if err != nil {
			lastErr = err
			continue
		}
		if cc != 0x00 {
			lastErr = fmt.Errorf("set-user-access cc=0x%02x", cc)
			continue
		}
		ccA, dA, err := sess.ExecRaw(ipmi.NetFnApp, ipmi.CmdGetUserAccess, []byte{ch, uid})
		if err != nil {
			lastErr = err
			continue
		}
		if ccA != 0x00 || len(dA) < 4 {
			lastErr = fmt.Errorf("verify get-user-access cc=0x%02x len=%d", ccA, len(dA))
			continue
		}
		got := dA[3]
		gotCallinEnabled := (got & 0x40) == 0
		gotLinkEnabled := (got & 0x20) != 0
		gotIPMIEnabled := (got & 0x10) != 0
		gotPriv := got & 0x0f
		if gotCallinEnabled == callinEnabled && gotLinkEnabled == linkEnabled && gotIPMIEnabled == ipmiEnabled && gotPriv == (priv&0x0f) {
			return map[string]any{
				"ok":        true,
				"action":    "channel setaccess",
				"channel":   channelID,
				"id":        userID,
				"callin":    callinEnabled,
				"ipmi":      ipmiEnabled,
				"link":      linkEnabled,
				"privilege": gotPriv,
			}, nil
		}
		lastErr = fmt.Errorf("verify mismatch callin=%t ipmi=%t link=%t priv=%d", gotCallinEnabled, gotIPMIEnabled, gotLinkEnabled, gotPriv)
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("set-user-access failed")
	}
	return nil, lastErr
}
