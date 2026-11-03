package cmd

import (
	"testing"
	"time"

	"github.com/runZeroInc/oobscan/pkg/ipmi"
)

func TestSMCCDBIsATopLevelCommand(t *testing.T) {
	c := findRootCommand("smc-cdb")
	if c == nil {
		t.Fatal("smc-cdb is not registered as a top-level command")
	}
	if err := c.Args(c, []string{"192.0.2.10"}); err == nil {
		t.Error("smc-cdb must require a subcommand as well as a target")
	}
	if err := c.Args(c, []string{"192.0.2.10", "enum"}); err != nil {
		t.Errorf("smc-cdb <host> enum should be accepted: %v", err)
	}
}

func TestParseIPMISMCCDBArgs(t *testing.T) {
	enum, err := parseIPMISMCCDBArgs([]string{"enum", "controller=2", "delay=25ms", "profile=smc-x13-0107"})
	if err != nil || enum.mode != "enum" || enum.controller != 2 || enum.delay != 25*time.Millisecond {
		t.Fatalf("enum = %+v, err=%v", enum, err)
	}
	inquiry, err := parseIPMISMCCDBArgs([]string{"inquiry", "0", "3"})
	if err != nil || inquiry.mode != "inquiry" || inquiry.controller != 0 || inquiry.target != 3 || len(inquiry.cdb) != 6 || inquiry.cdb[0] != 0x12 {
		t.Fatalf("inquiry = %+v, err=%v", inquiry, err)
	}
	raw, err := parseIPMISMCCDBArgs([]string{"1", "0x20", "2a000000000000000100", "dir=2", "timeout=1000", "apply"})
	if err != nil || raw.mode != "raw" || raw.target != 0x20 || raw.direction != 2 || raw.timeout != 1000 || !raw.apply || !ipmi.SCSICDBIsDestructive(raw.cdb) {
		t.Fatalf("raw = %+v, err=%v", raw, err)
	}
}

func TestParseIPMISMCCDBRejectsInvalid(t *testing.T) {
	for _, args := range [][]string{
		{"inquiry", "4", "0"},
		{"inquiry", "0", "0x78"},
		{"0", "0", "12345678"},
		{"enum", "dir=4"},
	} {
		if _, err := parseIPMISMCCDBArgs(args); err == nil {
			t.Errorf("accepted invalid args %v", args)
		}
	}
}

func TestSMCCDBProfileGatesInventorySeparately(t *testing.T) {
	x11, _ := ipmi.MemProfileByID("smc-x11")
	if !smcCDBProfileSupportsMode(&x11, "enum") {
		t.Fatal("Supermicro X11 inventory mode should be available")
	}
	if smcCDBProfileSupportsMode(&x11, "inquiry") {
		t.Fatal("Supermicro X11 should not advertise OEMHW1 CDB passthrough")
	}
	h13ssf, _ := ipmi.MemProfileByID("smc-h13ssf-0109")
	if !smcCDBProfileSupportsMode(&h13ssf, "inquiry") {
		t.Fatal("H13SSF should advertise OEMHW1 CDB passthrough")
	}
	generic, _ := ipmi.MemProfileByID("generic")
	if smcCDBProfileSupportsMode(&generic, "enum") {
		t.Fatal("generic profile should not send Supermicro inventory requests")
	}
}

func TestSMCCDBRawModeAlwaysRequiresApply(t *testing.T) {
	if !smcCDBModeRequiresApply("raw") {
		t.Fatal("arbitrary raw CDB should require apply")
	}
	if smcCDBModeRequiresApply("inquiry") || smcCDBModeRequiresApply("enum") {
		t.Fatal("named read-only modes should not require apply")
	}
}
