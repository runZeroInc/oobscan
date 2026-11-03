package check

import "testing"

// Guards the ssh.defaultCreds severity split: a credential that authenticates but is
// denied a usable session (restricted CLI / refused / no output) must not be graded
// as a compromise. Only a session that returned real command output is critical.
func TestSSHCredRiskSplit(t *testing.T) {
	cases := []struct {
		out    string
		access string
		risk   string
	}{
		{"uid=0(sysadmin) gid=0(sysadmin) groups=0(sysadmin)", "shell", "critical"},
		{"Linux bmc 5.10.0 #1 SMP", "shell", "critical"},
		{"No Access Privilege  ! Exiting...!", "restricted", "info"},
		{"COMMAND NOT SUPPORTED", "restricted", "info"},
		{"authenticated (session refused)", "restricted", "info"},
		{"authenticated (no command output)", "restricted", "info"},
		{"authenticated (session timed out)", "restricted", "info"},
		{"", "restricted", "info"},
	}
	for _, c := range cases {
		if got := sshAccessLevel(c.out); got != c.access {
			t.Errorf("sshAccessLevel(%q)=%q want %q", c.out, got, c.access)
		}
		if got := sshCredRisk(c.out); got != c.risk {
			t.Errorf("sshCredRisk(%q)=%q want %q", c.out, got, c.risk)
		}
	}
}
