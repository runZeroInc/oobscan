package cmd

import (
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// findRootCommand returns a registered top-level command by name.
func findRootCommand(name string) *cobra.Command {
	for _, c := range rootCmd.Commands() {
		if c.Name() == name {
			return c
		}
	}
	return nil
}

// TestSMCCommandsUseHyphenNaming locks the naming convention: every Supermicro
// tool is "smc-<tool>", never a run-together "smc<tool>".
func TestSMCCommandsUseHyphenNaming(t *testing.T) {
	want := []string{
		"smc-alert-cmdinj", "smc-backup", "smc-cdb", "smc-kvm", "smc-priv-esc", "smc-rakp-bypass",
		"smc-read", "smc-restore-shell", "smc-shell", "smc-uninstall", "smc-x14-cmdinj",
	}
	got := smcCommandNames()
	slices.Sort(got)
	if !slices.Equal(got, want) {
		t.Errorf("smc command set = %v, want %v", got, want)
	}
	for _, name := range got {
		if !strings.HasPrefix(name, "smc-") {
			t.Errorf("%q must be spelled smc-<tool>", name)
		}
	}
}

// TestIPMIDoesNotOwnSMCCommands checks the SMC workflows really moved off the
// ipmi command: they are no longer target terminators, and none of their
// workflow-specific flags is left behind on ipmi.
func TestIPMIDoesNotOwnSMCCommands(t *testing.T) {
	for _, name := range ipmiKnownCommands {
		if strings.HasPrefix(name, "smc") {
			t.Errorf("%q is still an ipmi subcommand token", name)
		}
	}
	for _, old := range []string{"smcbackup", "smcread", "smccdb", "smcrestore-shell", "smcuninstall", "smc0014"} {
		if idx := findIPMICommandIndex([]string{"192.0.2.10", old}); idx >= 0 {
			t.Errorf("%q is still recognized by the ipmi target parser at %d", old, idx)
		}
	}
	// ipmi keeps only what "mem ... via=shell" needs to reach a deployed shell.
	for _, moved := range []string{
		"config-key", "config-cipher", "config-iv", "config-inner-pass", "chunk",
		"from", "out", "apply", "stage-only", "no-decrypt", "shell-delay",
		"raw-inner", "payload-host",
		"record0-keys", "activate-sol", "low-user", "admin-pass", "probe-only", "notes",
	} {
		if ipmiCmd.Flags().Lookup(moved) != nil {
			t.Errorf("--%s should have moved off ipmi onto its smc-* command", moved)
		}
	}
	for _, kept := range []string{"cert-path", "shell-port"} {
		if ipmiCmd.Flags().Lookup(kept) == nil {
			t.Errorf("--%s is still needed by \"mem ... via=shell\"", kept)
		}
	}
}

// TestSMCCommandsShareSessionFlags checks the central registration actually
// reaches every session-backed command, so none of them drifts out of step with
// ipmi on how a session is opened.
func TestSMCCommandsShareSessionFlags(t *testing.T) {
	session := []string{"port", "user", "password", "timeout", "max-retries", "cipher", "ipmi-version", "auth", "proto", "format"}
	for _, name := range []string{"smc-backup", "smc-restore-shell", "smc-uninstall", "smc-read", "smc-cdb", "smc-x14-cmdinj", "smc-alert-cmdinj"} {
		c := findRootCommand(name)
		if c == nil {
			t.Fatalf("%q is not registered", name)
		}
		for _, f := range session {
			if c.Flags().Lookup(f) == nil {
				t.Errorf("%s is missing the shared session flag --%s", name, f)
			}
		}
	}
	// Each config-archive command gets the crypto group; the read-only
	// inspection commands do not need it.
	for _, name := range []string{"smc-backup", "smc-restore-shell", "smc-uninstall"} {
		if findRootCommand(name).Flags().Lookup("config-key") == nil {
			t.Errorf("%s is missing --config-key", name)
		}
	}
	for _, name := range []string{"smc-read", "smc-cdb"} {
		if findRootCommand(name).Flags().Lookup("config-key") != nil {
			t.Errorf("%s should not carry the config-archive crypto flags", name)
		}
	}
	// The command-injection validators take the session group but not the
	// config-archive crypto group: neither touches the config container.
	for _, name := range []string{"smc-x14-cmdinj", "smc-alert-cmdinj"} {
		if findRootCommand(name).Flags().Lookup("config-key") != nil {
			t.Errorf("%s should not carry the config-archive crypto flags", name)
		}
		if findRootCommand(name).Flags().Lookup("callback-host") == nil {
			t.Errorf("%s is missing the shared --callback-host confirmation flag", name)
		}
	}
}

func TestNoTailnetDeploymentCommandsOrFlags(t *testing.T) {
	var walk func(*cobra.Command)
	walk = func(command *cobra.Command) {
		for _, name := range append([]string{command.Name()}, command.Aliases...) {
			if strings.Contains(name, "tailnet") || strings.Contains(name, "tsnet") {
				t.Errorf("removed deployment command remains registered: %s", name)
			}
		}
		for _, flags := range []*pflag.FlagSet{command.Flags(), command.PersistentFlags()} {
			flags.VisitAll(func(flag *pflag.Flag) {
				if strings.HasPrefix(flag.Name, "ts-") || flag.Name == "shell-only" {
					t.Errorf("%s retains removed deployment flag --%s", command.CommandPath(), flag.Name)
				}
			})
		}
		for _, child := range command.Commands() {
			walk(child)
		}
	}
	walk(rootCmd)
}

// TestIPMIShortUsageCoversKnownCommands keeps the usage block printed on an
// argument error in step with what the dispatcher actually accepts. A command
// that is dispatched but never listed is invisible to anyone reading the error.
func TestIPMIShortUsageCoversKnownCommands(t *testing.T) {
	for _, name := range ipmiKnownCommands {
		found := false
		for _, line := range ipmiShortUsageLines {
			if strings.HasPrefix(line, name+" ") || line == name {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("%q is dispatched but missing from the short usage block", name)
		}
	}
}

// helpFlagRE matches a long flag as written in help prose. A trailing "*"
// means the text is naming a family of flags (--mem-*), not one flag.
var helpFlagRE = regexp.MustCompile(`--[a-z][a-z0-9]*(?:-[a-z0-9]+)*(?:-?\*)?`)

// helpContextRE finds the command an example line is invoking, so a line like
// "oobscan convert --redact" is checked against convert rather than against the
// command whose help is quoting it.
var helpContextRE = regexp.MustCompile(`oobscan ((?:[a-z0-9-]+ ?)+)`)

// TestHelpTextOnlyNamesRealFlags is the guard against help drift: every --flag a
// command's help mentions must actually be registered on that command.
func TestHelpTextOnlyNamesRealFlags(t *testing.T) {
	var walk func(c *cobra.Command)
	walk = func(c *cobra.Command) {
		c.InitDefaultHelpFlag()
		for _, line := range strings.Split(c.Short+"\n"+c.Long, "\n") {
			owner := helpLineOwner(c, line)
			for _, name := range helpFlagRE.FindAllString(line, -1) {
				if strings.HasSuffix(name, "*") {
					continue
				}
				name = strings.TrimPrefix(name, "--")
				if lookupAnyFlag(owner, name) == nil {
					t.Errorf("%s help mentions --%s, which is not a flag on %s",
						c.CommandPath(), name, owner.CommandPath())
				}
			}
		}
		for _, sub := range c.Commands() {
			walk(sub)
		}
	}
	walk(rootCmd)
}

// lookupAnyFlag resolves a flag through the command's own local and persistent
// sets, the set it inherits, and the root's persistent set.
func lookupAnyFlag(c *cobra.Command, name string) any {
	c.InitDefaultHelpFlag()
	for _, set := range []*pflag.FlagSet{c.Flags(), c.PersistentFlags(), c.InheritedFlags(), rootCmd.PersistentFlags()} {
		if f := set.Lookup(name); f != nil {
			return f
		}
	}
	return nil
}

// helpLineOwner returns the command a help line's flags belong to: the command
// an example invokes, or c when the line invokes nothing.
func helpLineOwner(c *cobra.Command, line string) *cobra.Command {
	m := helpContextRE.FindStringSubmatch(line)
	if m == nil {
		return c
	}
	owner := rootCmd
	for _, word := range strings.Fields(m[1]) {
		next, _, err := owner.Find([]string{word})
		if err != nil || next == owner {
			break
		}
		owner = next
	}
	if owner == rootCmd {
		return c
	}
	return owner
}

// TestNoHelpTextNamesRetiredCommands checks no help still advertises the
// pre-rename spellings, which are now hard errors rather than aliases.
func TestNoHelpTextNamesRetiredCommands(t *testing.T) {
	retired := []string{"smcbackup", "smcread", "smccdb", "smcrestore-shell", "smcrestore-tailnet", "smc-restore-tailnet", "smcuninstall", "smc0014", "smc0015", "smckvm"}
	var walk func(c *cobra.Command)
	walk = func(c *cobra.Command) {
		text := c.Use + "\n" + c.Short + "\n" + c.Long
		// The cache filename and the Go package path are real on-disk names,
		// not command references.
		text = strings.ReplaceAll(text, "smcrestore-shell.pem", "")
		text = strings.ReplaceAll(text, "pkg/smckvm", "")
		for _, old := range retired {
			if strings.Contains(text, old) {
				t.Errorf("%s help still names the retired command %q", c.CommandPath(), old)
			}
		}
		for _, sub := range c.Commands() {
			walk(sub)
		}
	}
	walk(rootCmd)
}
