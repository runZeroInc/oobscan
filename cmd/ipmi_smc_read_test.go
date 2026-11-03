package cmd

import (
	"strings"
	"testing"

	"github.com/runZeroInc/oobscan/pkg/ipmi"
)

func TestSMCReadIsATopLevelCommand(t *testing.T) {
	c := findRootCommand("smc-read")
	if c == nil {
		t.Fatal("smc-read is not registered as a top-level command")
	}
	// <host> <remote-path> is the minimum; the path is not optional.
	if err := c.Args(c, []string{"192.0.2.10"}); err == nil {
		t.Error("smc-read must require a remote path as well as a target")
	}
	if err := c.Args(c, []string{"192.0.2.10", "/etc/shadow"}); err != nil {
		t.Errorf("smc-read <host> <path> should be accepted: %v", err)
	}
}

func TestParseIPMISMCReadArgs(t *testing.T) {
	o, err := parseIPMISMCReadArgs([]string{
		"/nv/config.tar.gz", "out=config.tgz", "offset=0x20", "len=2k",
		"chunk=128", "delay=25ms", "profile=smc-x13-0107", "psblock",
	})
	if err != nil {
		t.Fatal(err)
	}
	if o.remotePath != "/nv/config.tar.gz" || o.outFile != "config.tgz" || o.offset != 0x20 || o.length != 2048 {
		t.Fatalf("parsed path/output/range = %q %q 0x%x %d", o.remotePath, o.outFile, o.offset, o.length)
	}
	if o.chunk != 128 || o.delay.String() != "25ms" || o.profileID != "smc-x13-0107" || !o.decrypt {
		t.Fatalf("parsed options = %+v", o)
	}
}

func TestParseIPMISMCReadArgsSafety(t *testing.T) {
	if _, err := parseIPMISMCReadArgs(nil); err == nil || !strings.Contains(err.Error(), "usage:") {
		t.Fatalf("missing path error = %v", err)
	}
	if _, err := parseIPMISMCReadArgs([]string{"/etc/shadow", "chunk=256"}); err == nil {
		t.Fatal("oversized chunk accepted")
	}
	if _, err := parseIPMISMCReadArgs([]string{"/etc/shadow", "len=2m"}); err == nil {
		t.Fatal("multi-megabyte rendered output accepted without out=")
	}
	if p, _ := ipmi.MemProfileByID("smc-x13-0107"); !p.OEMHW1Files {
		t.Fatal("smc-x13-0107 lost the OEMHW1 file capability")
	}
	if p, _ := ipmi.MemProfileByID("smc-x11"); p.OEMHW1Files {
		t.Fatal("smc-x11 unexpectedly advertises OEMHW1 file operations")
	}
	implicit, err := parseIPMISMCReadArgs([]string{"/etc/hostname"})
	if err != nil || smcReadLimit(implicit) != smcReadRenderMax {
		t.Fatalf("implicit rendered limit = %d, err=%v", smcReadLimit(implicit), err)
	}
	toFile, err := parseIPMISMCReadArgs([]string{"/etc/hostname", "out=hostname"})
	if err != nil || smcReadLimit(toFile) != smcReadMaxBytes {
		t.Fatalf("implicit file limit = %d, err=%v", smcReadLimit(toFile), err)
	}
}

func TestIPMICommandValidationErrorIgnoresTargetMeaning(t *testing.T) {
	if isIPMICommandValidationError("OEMHW1 fd_open: OEMHW1 completion code 0xcc (sub-command absent, presence gate refused, or invalid data)") {
		t.Fatal("target completion error classified as command validation")
	}
	if !isIPMICommandValidationError("invalid smc-read chunk 256") {
		t.Fatal("argument validation error was not classified")
	}
}
