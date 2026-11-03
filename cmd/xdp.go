package cmd

import (
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/runZeroInc/oobscan/pkg/asd"
)

var (
	xdpPort    int
	xdpTLSMode string
	xdpUser    string
	xdpPass    string
	xdpTimeout time.Duration
	xdpTag     uint8
	xdpOrigin  uint8

	// reg subcommand
	xdpRegIR     uint64
	xdpRegIRBits int
	xdpRegDRBits int

	// mem subcommand parameters (target CPU debug-register model)
	xdpMemAddr       uint64
	xdpMemLen        int
	xdpMemData       string
	xdpMemIRWidth    int
	xdpMemAddrIR     uint64
	xdpMemDataIR     uint64
	xdpMemTriggerIR  uint64
	xdpMemWordBits   int
	xdpMemAddrBits   int
	xdpMemConfigured bool
)

var xdpCmd = &cobra.Command{
	Use:   "xdp <host>",
	Short: "Connect to an Intel ASD / H3C RemoteXDP JTAG service and print details.",
	Long: `xdp speaks the Intel At-Scale-Debug (ASD) wire protocol that H3C exposes as
"RemoteXDP" (tcp/6868). With no subcommand it connects and prints the negotiated
service details (downstream version, max data size, in-flight window, supported
JTAG chains) and reads the device IDCODE.

Use only on authorized targets in an approved maintenance window. JTAG scans
can alter CPU debug state even during reads. Register and memory operations
execute immediately and can interrupt the managed host; there is no apply gate.

Subcommands:
	reg        shift an instruction register and read a data register (JTAG)
	mem-read   read memory via a JTAG-composed CPU-debug scan sequence
	mem-write  write memory via a JTAG-composed CPU-debug scan sequence

The service is unauthenticated by default; H3C hardened builds wrap it in TLS +
a single-factor PAM login (--tls, --user/--pass).

Note on memory access: ASD exposes only raw JTAG/I2C scans (there is no DMA
message in this firmware). Memory reads/writes are therefore composed from
target-CPU run-control debug-register shifts, whose opcodes are CPU-model
specific and NOT derivable from the BMC firmware. The --mem-* flags parameterize
that model; on an emulated or powered-down target the scans return all-ones or
an ASD failure, which is reported as hardware-blocked rather than
fabricated data.`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return runXDPInfo(args[0])
	},
}

var xdpRegCmd = &cobra.Command{
	Use:   "reg <host>",
	Short: "Shift a JTAG instruction register and read the data register.",
	Long:  "Shift a JTAG instruction register and read the data register on an authorized target. Executes immediately and can alter CPU debug state; use an approved maintenance window.",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return runXDPReg(args[0])
	},
}

var xdpMemReadCmd = &cobra.Command{
	Use:   "mem-read <host>",
	Short: "Read memory via a JTAG-composed CPU-debug scan sequence.",
	Long:  "Read memory on an authorized target using CPU-debug register shifts. Executes immediately; reads can alter debug state or have hardware side effects. Use an approved maintenance window.",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return runXDPMemRead(args[0])
	},
}

var xdpMemWriteCmd = &cobra.Command{
	Use:   "mem-write <host>",
	Short: "Write memory via a JTAG-composed CPU-debug scan sequence.",
	Long:  "Write memory on an authorized target using CPU-debug register shifts. Executes immediately without an apply gate and can corrupt memory or interrupt the managed host. Use an approved maintenance window and recovery plan.",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return runXDPMemWrite(args[0])
	},
}

func dialXDP(host string) (*asd.Conn, error) {
	timeout := xdpTimeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	opts := asd.Options{
		Timeout: timeout,
		PAMUser: xdpUser,
		PAMPass: xdpPass,
		Tag:     xdpTag,
		Origin:  xdpOrigin,
	}
	switch strings.ToLower(xdpTLSMode) {
	case "true", "yes", "on", "tls":
		opts.TLS = true
		return asd.Dial(host, xdpPort, opts)
	case "false", "no", "off", "plain":
		opts.TLS = false
		return asd.Dial(host, xdpPort, opts)
	default: // auto
		opts.TLS = false
		c, err := asd.Dial(host, xdpPort, opts)
		if err == nil {
			// Confirm liveness; if the plain handshake yields nothing useful, retry TLS.
			if _, lberr := c.Loopback([]byte{0x01, 0x02, 0x03, 0x04}); lberr == nil {
				return c, nil
			}
			_ = c.Close()
		}
		opts.TLS = true
		return asd.Dial(host, xdpPort, opts)
	}
}

func runXDPInfo(host string) error {
	c, err := dialXDP(host)
	if err != nil {
		return err
	}
	defer func() { _ = c.Close() }()

	out := map[string]any{
		"host":      host,
		"port":      xdpPort,
		"transport": c.Transport,
	}
	if c.AuthPrompted {
		out["authPrompted"] = true
		out["authenticated"] = c.Authenticated
	}
	if v, err := c.Version(); err == nil {
		out["version"] = v
	} else {
		out["versionError"] = err.Error()
	}
	if n, err := c.MaxDataSizeReported(); err == nil {
		out["maxDataSize"] = n
	}
	if n, err := c.NumInFlight(); err == nil {
		out["numInFlight"] = n
	}
	if n, err := c.SupportedJTAGChains(); err == nil {
		out["supportedJTAGChains"] = n
	}
	if id, res, err := c.IDCODE(); err == nil {
		if res.Blocked {
			out["idcode"] = "hardware-blocked (no target on JTAG chain)"
			out["idcodeStatus"] = asd.FormatStatus(res.Status)
		} else {
			out["idcode"] = fmt.Sprintf("0x%08x", id)
		}
	}
	printJSON(out)
	return nil
}

func runXDPReg(host string) error {
	if xdpRegIRBits <= 0 {
		xdpRegIRBits = 8
	}
	if xdpRegDRBits <= 0 {
		xdpRegDRBits = 32
	}
	c, err := dialXDP(host)
	if err != nil {
		return err
	}
	defer func() { _ = c.Close() }()

	if r, err := c.ShiftIR(xdpRegIR, xdpRegIRBits); err != nil {
		return fmt.Errorf("shift IR: %w", err)
	} else if r.Blocked {
		printJSON(map[string]any{"host": host, "ir": fmt.Sprintf("0x%x", xdpRegIR), "blocked": true, "status": asd.FormatStatus(r.Status)})
		return nil
	}
	res, err := c.ReadDR(xdpRegDRBits)
	if err != nil {
		return fmt.Errorf("read DR: %w", err)
	}
	out := map[string]any{
		"host":   host,
		"ir":     fmt.Sprintf("0x%x", xdpRegIR),
		"irBits": xdpRegIRBits,
		"drBits": xdpRegDRBits,
		"status": asd.FormatStatus(res.Status),
	}
	if res.Blocked {
		out["blocked"] = true
		out["note"] = "all-ones or ASD failure: no target driving TDO on the JTAG chain"
	} else {
		out["tdoHex"] = hex.EncodeToString(res.TDO)
	}
	printJSON(out)
	return nil
}

func memParamsFromFlags() asd.MemParams {
	p := asd.DefaultMemParams()
	if xdpMemIRWidth > 0 {
		p.IRWidth = xdpMemIRWidth
	}
	if xdpMemAddrIR != 0 {
		p.AddrIR = xdpMemAddrIR
	}
	if xdpMemDataIR != 0 {
		p.DataIR = xdpMemDataIR
	}
	// TriggerIR may legitimately be 0 (no trigger); only override when set.
	if xdpMemTriggerIR != 0 {
		p.TriggerIR = xdpMemTriggerIR
	}
	if xdpMemWordBits > 0 {
		p.WordBits = xdpMemWordBits
	}
	if xdpMemAddrBits > 0 {
		p.AddrBits = xdpMemAddrBits
	}
	p.Configured = xdpMemConfigured
	return p
}

func runXDPMemRead(host string) error {
	if xdpMemLen <= 0 {
		return fmt.Errorf("--len must be > 0")
	}
	c, err := dialXDP(host)
	if err != nil {
		return err
	}
	defer func() { _ = c.Close() }()

	res, err := c.MemRead(xdpMemAddr, xdpMemLen, memParamsFromFlags())
	if err != nil {
		return err
	}
	out := map[string]any{
		"host":    host,
		"addr":    fmt.Sprintf("0x%x", xdpMemAddr),
		"length":  xdpMemLen,
		"blocked": res.Blocked,
	}
	if res.Note != "" {
		out["note"] = res.Note
	}
	if res.Blocked {
		out["result"] = "hardware-blocked (no live host CPU on JTAG chain)"
		out["bytesRead"] = len(res.Data)
	} else {
		out["dataHex"] = hex.EncodeToString(res.Data)
	}
	printJSON(out)
	return nil
}

func runXDPMemWrite(host string) error {
	data, err := hex.DecodeString(strings.TrimPrefix(xdpMemData, "0x"))
	if err != nil {
		return fmt.Errorf("invalid --data hex: %w", err)
	}
	if len(data) == 0 {
		return fmt.Errorf("--data is required (hex bytes)")
	}
	c, err := dialXDP(host)
	if err != nil {
		return err
	}
	defer func() { _ = c.Close() }()

	res, err := c.MemWrite(xdpMemAddr, data, memParamsFromFlags())
	if err != nil {
		return err
	}
	out := map[string]any{
		"host":    host,
		"addr":    fmt.Sprintf("0x%x", xdpMemAddr),
		"length":  len(data),
		"blocked": res.Blocked,
	}
	if res.Note != "" {
		out["note"] = res.Note
	}
	if res.Blocked {
		out["result"] = "hardware-blocked (no live host CPU on JTAG chain); write not confirmed"
	} else {
		out["result"] = "scan sequence accepted by ASD handler"
	}
	printJSON(out)
	return nil
}

func init() {
	pf := xdpCmd.PersistentFlags()
	pf.IntVar(&xdpPort, "port", asd.DefaultPort, "ASD/RemoteXDP TCP port")
	pf.StringVar(&xdpTLSMode, "tls", "auto", "TLS mode: auto|true|false")
	pf.StringVarP(&xdpUser, "user", "u", "", "PAM username (hardened builds)")
	pf.StringVarP(&xdpPass, "pass", "P", "", "PAM password (hardened builds)")
	pf.DurationVar(&xdpTimeout, "timeout", 10*time.Second, "connection/request timeout")
	pf.Uint8Var(&xdpTag, "tag", 1, "ASD message tag (0-7)")
	pf.Uint8Var(&xdpOrigin, "origin", 0, "ASD origin id (0-7)")

	rf := xdpRegCmd.Flags()
	rf.Uint64Var(&xdpRegIR, "ir", 0, "instruction-register value to shift")
	rf.IntVar(&xdpRegIRBits, "ir-bits", 8, "instruction-register width in bits")
	rf.IntVar(&xdpRegDRBits, "dr-bits", 32, "data-register width to read in bits")

	addMemFlags := func(c *cobra.Command, withData bool) {
		f := c.Flags()
		f.Uint64Var(&xdpMemAddr, "addr", 0, "physical address")
		if withData {
			f.StringVar(&xdpMemData, "data", "", "hex bytes to write, e.g. deadbeef")
		} else {
			f.IntVar(&xdpMemLen, "len", 0, "number of bytes to read")
		}
		f.IntVar(&xdpMemIRWidth, "mem-ir-width", 0, "debug IR width in bits (0=default)")
		f.Uint64Var(&xdpMemAddrIR, "mem-addr-ir", 0, "IR selecting the address debug register")
		f.Uint64Var(&xdpMemDataIR, "mem-data-ir", 0, "IR selecting the data debug register")
		f.Uint64Var(&xdpMemTriggerIR, "mem-trigger-ir", 0, "IR that triggers the bus access (0=none)")
		f.IntVar(&xdpMemWordBits, "mem-word-bits", 0, "data-register width per access in bits (0=default)")
		f.IntVar(&xdpMemAddrBits, "mem-addr-bits", 0, "address-register width in bits (0=default)")
		f.BoolVar(&xdpMemConfigured, "mem-configured", false, "assert the --mem-* model matches this target CPU")
	}
	addMemFlags(xdpMemReadCmd, false)
	addMemFlags(xdpMemWriteCmd, true)

	xdpCmd.AddCommand(xdpRegCmd, xdpMemReadCmd, xdpMemWriteCmd)
	rootCmd.AddCommand(xdpCmd)
}
