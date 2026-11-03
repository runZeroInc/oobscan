package cmd

import (
	"context"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/runZeroInc/oobscan/pkg/ipmi"
)

const smcCDBUsage = "usage: smc-cdb enum [controller=<0..3>] [profile=<id>] | smc-cdb inquiry <controller> <target> [dir=<0..3>] [timeout=<ms>] [profile=<id>] | smc-cdb <controller> <target> <hex-cdb...> [dir=<0..3>] [timeout=<ms>] [profile=<id>] [apply]"

type smcCDBOpts struct {
	mode       string
	profileID  string
	controller int
	target     int
	direction  byte
	timeout    uint16
	apply      bool
	delay      time.Duration
	cdb        []byte
}

func parseIPMISMCCDBArgs(args []string) (*smcCDBOpts, error) {
	if len(args) == 0 {
		return nil, fmt.Errorf("%s", smcCDBUsage)
	}
	o := &smcCDBOpts{controller: -1, target: -1, direction: 1, timeout: 5000, delay: 20 * time.Millisecond}
	pos := make([]string, 0, len(args))
	for _, arg := range args {
		if strings.EqualFold(arg, "apply") {
			o.apply = true
			continue
		}
		key, value, ok := strings.Cut(arg, "=")
		if !ok {
			pos = append(pos, arg)
			continue
		}
		key, value = strings.ToLower(strings.TrimSpace(key)), strings.TrimSpace(value)
		var err error
		switch key {
		case "profile":
			o.profileID = value
		case "controller", "ctrl":
			o.controller, err = strconv.Atoi(value)
		case "target":
			o.target, err = strconv.Atoi(value)
		case "dir", "direction":
			var n int
			n, err = strconv.Atoi(value)
			o.direction = byte(n)
			if err == nil && (n < 0 || n > 3) {
				err = fmt.Errorf("direction must be 0..3")
			}
		case "timeout":
			var n uint64
			n, err = strconv.ParseUint(value, 0, 16)
			o.timeout = uint16(n)
		case "delay":
			o.delay, err = time.ParseDuration(value)
		default:
			return nil, fmt.Errorf("unknown smc-cdb option %q; %s", key, smcCDBUsage)
		}
		if err != nil {
			return nil, fmt.Errorf("invalid smc-cdb option %s=%q: %w", key, value, err)
		}
	}
	if len(pos) == 0 {
		return nil, fmt.Errorf("%s", smcCDBUsage)
	}
	switch strings.ToLower(pos[0]) {
	case "enum", "enumerate", "list":
		o.mode = "enum"
		if len(pos) != 1 {
			return nil, fmt.Errorf("enum takes controller= as an option; %s", smcCDBUsage)
		}
	case "inquiry":
		o.mode = "inquiry"
		if len(pos) != 3 {
			return nil, fmt.Errorf("%s", smcCDBUsage)
		}
		var err error
		if o.controller, err = parseSMCCDBInt(pos[1], 3); err != nil {
			return nil, fmt.Errorf("invalid controller: %w", err)
		}
		if o.target, err = parseSMCCDBInt(pos[2], 0x77); err != nil {
			return nil, fmt.Errorf("invalid target: %w", err)
		}
		o.cdb = []byte{0x12, 0x00, 0x00, 0x00, 0x60, 0x00}
	default:
		o.mode = "raw"
		if len(pos) < 3 {
			return nil, fmt.Errorf("%s", smcCDBUsage)
		}
		var err error
		if o.controller, err = parseSMCCDBInt(pos[0], 3); err != nil {
			return nil, fmt.Errorf("invalid controller: %w", err)
		}
		if o.target, err = parseSMCCDBInt(pos[1], 0x77); err != nil {
			return nil, fmt.Errorf("invalid target: %w", err)
		}
		o.cdb, err = parseMemWriteBytes(pos[2:])
		if err != nil {
			return nil, fmt.Errorf("invalid CDB: %w", err)
		}
		switch len(o.cdb) {
		case 6, 10, 12, 16:
		default:
			return nil, fmt.Errorf("invalid CDB length %d (use 6, 10, 12, or 16)", len(o.cdb))
		}
	}
	if o.controller < -1 || o.controller > 3 || o.target > 0x77 || o.delay < 0 {
		return nil, fmt.Errorf("invalid smc-cdb range; %s", smcCDBUsage)
	}
	return o, nil
}

func parseSMCCDBInt(value string, max int) (int, error) {
	n, err := strconv.ParseUint(value, 0, 8)
	if err != nil || int(n) > max {
		return 0, fmt.Errorf("%q is outside 0..%d", value, max)
	}
	return int(n), nil
}

func runIPMISMCCDB(ctx context.Context, sess *ipmi.CmdSess, args []string) (any, error) {
	opts, err := parseIPMISMCCDBArgs(args)
	if err != nil {
		return nil, err
	}
	profile, err := resolveSMCReadProfile(ctx, sess, opts.profileID)
	if err != nil {
		return nil, err
	}
	if opts.mode == "enum" {
		if !smcCDBProfileSupportsMode(profile, opts.mode) {
			return nil, fmt.Errorf("profile %s is not a Supermicro profile; no storage inventory request sent", profile.ID)
		}
		return runIPMISMCCDBEnum(ctx, sess, profile, opts)
	}
	if !profile.OEMHW1SCSI {
		return nil, fmt.Errorf("profile %s does not carry OEMHW1 SCSI passthrough; no storage request sent", profile.ID)
	}

	destructive := ipmi.SCSICDBIsDestructive(opts.cdb)
	requiresApply := smcCDBModeRequiresApply(opts.mode)
	if requiresApply && !opts.apply {
		note := "raw CDB not sent; add apply to execute it"
		if destructive {
			note = "destructive CDB not sent; add apply to execute it"
		}
		return map[string]any{
			"action": "smc-cdb", "profile": profile.ID, "mode": opts.mode,
			"controller": opts.controller, "target": opts.target,
			"direction": opts.direction, "timeout": opts.timeout,
			"cdb": hex.EncodeToString(opts.cdb), "cdbLen": len(opts.cdb),
			"destructive": destructive, "requiresApply": true, "applied": false,
			"note": note,
		}, nil
	}
	data, err := sess.HW1SCSICommand(byte(opts.controller), byte(opts.target), opts.direction, opts.timeout, opts.cdb)
	if err != nil {
		return nil, err
	}
	result := map[string]any{
		"action": "smc-cdb", "profile": profile.ID, "mode": opts.mode,
		"controller": opts.controller, "target": opts.target,
		"direction": opts.direction, "timeout": opts.timeout,
		"cdb": hex.EncodeToString(opts.cdb), "cdbLen": len(opts.cdb),
		"dataHex": hex.EncodeToString(data), "bytes": len(data),
		"destructive": destructive, "requiresApply": requiresApply, "applied": requiresApply && opts.apply,
	}
	if opts.mode == "inquiry" {
		inquiry, decodeErr := ipmi.DecodeSCSIInquiry(data)
		if decodeErr != nil {
			return nil, decodeErr
		}
		result["vendor"], result["product"], result["revision"] = inquiry.Vendor, inquiry.Product, inquiry.Revision
		result["note"] = fmt.Sprintf("INQUIRY: vendor=%s product=%s revision=%s", inquiry.Vendor, inquiry.Product, inquiry.Revision)
	}
	return result, nil
}

func smcCDBProfileSupportsMode(profile *ipmi.MemProfile, mode string) bool {
	if mode == "enum" {
		return profile != nil && profile.Vendor == "supermicro"
	}
	return profile != nil && profile.OEMHW1SCSI
}

func smcCDBModeRequiresApply(mode string) bool {
	return mode == "raw"
}

type smcCDBEnumRow struct {
	Profile    string `json:"profile"`
	Controller int    `json:"controller"`
	Target     any    `json:"target"`
	Present    string `json:"present"`
	Error      string `json:"error,omitempty"`
	Vendor     string `json:"vendor,omitempty"`
	Model      string `json:"model,omitempty"`
	Serial     string `json:"serial,omitempty"`
}

func runIPMISMCCDBEnum(ctx context.Context, sess *ipmi.CmdSess, profile *ipmi.MemProfile, opts *smcCDBOpts) (any, error) {
	controllers := []int{0, 1, 2, 3}
	if opts.controller >= 0 {
		controllers = []int{opts.controller}
	}
	rows := make([]smcCDBEnumRow, 0)
	for controllerIndex, controller := range controllers {
		if err := ctx.Err(); err != nil {
			return rows, err
		}
		targets, err := sess.SMCHDDTargets(byte(controller))
		if err != nil {
			return nil, err
		}
		if len(targets) == 0 {
			rows = append(rows, smcCDBEnumRow{Profile: profile.ID, Controller: controller, Target: "-", Present: "no"})
		}
		for targetIndex, target := range targets {
			row := smcCDBEnumRow{Profile: profile.ID, Controller: controller, Target: int(target.Target), Present: "yes"}
			if target.Error {
				row.Error = "yes"
			}
			if info, infoErr := sess.SMCHDDInfoRecord(byte(controller), target.Target); infoErr == nil {
				row.Vendor, row.Model, row.Serial = info.Vendor, info.Model, info.Serial
			}
			rows = append(rows, row)
			if opts.delay > 0 && targetIndex+1 < len(targets) {
				time.Sleep(opts.delay)
			}
		}
		if opts.delay > 0 && controllerIndex+1 < len(controllers) {
			time.Sleep(opts.delay)
		}
	}
	return rows, nil
}
