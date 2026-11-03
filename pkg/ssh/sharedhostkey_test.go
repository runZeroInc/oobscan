package ssh

import (
	"strings"
	"testing"

	xssh "github.com/runZeroInc/excrypto/x/crypto/ssh"
)

// The CyberPower RMCARD ed25519 host key public point was extracted from the
// firmware image (openssh-key-v1 blob). Rebuilding an ssh-ed25519 public key
// from that 32-byte point and fingerprinting it must reproduce the catalogued
// SHA256 fingerprint -- proving HostKeyFingerprint matches `ssh-keygen -lf` and
// the DB value is correct.
func TestCyberPowerSharedHostKeyFingerprint(t *testing.T) {
	// public point f1b67367b6c6585b39f994e60c56830b2a1ae9b850a492fb62eb389924203158
	point := []byte{
		0xf1, 0xb6, 0x73, 0x67, 0xb6, 0xc6, 0x58, 0x5b, 0x39, 0xf9, 0x94, 0xe6, 0x0c, 0x56, 0x83, 0x0b,
		0x2a, 0x1a, 0xe9, 0xb8, 0x50, 0xa4, 0x92, 0xfb, 0x62, 0xeb, 0x38, 0x99, 0x24, 0x20, 0x31, 0x58,
	}
	// Marshal an ssh-ed25519 public key blob: string("ssh-ed25519") + string(A).
	blob := marshalString("ssh-ed25519")
	blob = append(blob, marshalString(string(point))...)
	pub, err := xssh.ParsePublicKey(blob)
	if err != nil {
		t.Fatalf("ParsePublicKey: %v", err)
	}
	got := HostKeyFingerprint(pub)
	const want = "SHA256:PG6ZKj40PRyaRboZNT+dkNq7Nc/MUDvvHvKsPpy0O/E"
	if got != want {
		t.Fatalf("HostKeyFingerprint = %q, want %q", got, want)
	}
	shk, ok := MatchSharedHostKey(got)
	if !ok {
		t.Fatalf("MatchSharedHostKey(%q) = not found; want cyberpower", got)
	}
	if shk.Vendor != "cyberpower" {
		t.Errorf("shared host key vendor = %q, want cyberpower", shk.Vendor)
	}
}

// HostKeyBadKey must reproduce the badkeys.xml bkhash we exported for the
// CyberPower RMCARD ed25519 host key and cross-reference it back to the badkeys
// table. Rebuilding the key from the same firmware-extracted point as above and
// hashing it must yield the catalogued pattern -- proving BadKeyHash matches
// sshamble/badkeys.PrefixFromPublicKey for ed25519 and that the exported value
// is correct. A typo in either the pattern or the algorithm would fail here.
func TestCyberPowerHostKeyBadKeyBkhash(t *testing.T) {
	point := []byte{
		0xf1, 0xb6, 0x73, 0x67, 0xb6, 0xc6, 0x58, 0x5b, 0x39, 0xf9, 0x94, 0xe6, 0x0c, 0x56, 0x83, 0x0b,
		0x2a, 0x1a, 0xe9, 0xb8, 0x50, 0xa4, 0x92, 0xfb, 0x62, 0xeb, 0x38, 0x99, 0x24, 0x20, 0x31, 0x58,
	}
	blob := marshalString("ssh-ed25519")
	blob = append(blob, marshalString(string(point))...)
	pub, err := xssh.ParsePublicKey(blob)
	if err != nil {
		t.Fatalf("ParsePublicKey: %v", err)
	}
	bkh, bk, ok := HostKeyBadKey(pub)
	if !ok {
		t.Fatalf("HostKeyBadKey(cyberpower ed25519) = not matched; bkhash=%q", bkh)
	}
	const wantBk = "y1LAl7GkQ4GTLsrjZs/L"
	if bkh != wantBk {
		t.Fatalf("bkhash = %q, want %q", bkh, wantBk)
	}
	if bk.Vendor != "cyberpower" {
		t.Errorf("badkey vendor = %q, want cyberpower", bk.Vendor)
	}
}

func TestMatchSharedHostKeyUnknown(t *testing.T) {
	if _, ok := MatchSharedHostKey("SHA256:definitelyNotAKnownKey"); ok {
		t.Error("unknown fingerprint should not match")
	}
	if _, ok := MatchSharedHostKey(""); ok {
		t.Error("empty fingerprint should not match")
	}
}

// The H3C HDM2/HDM3 firmware ships fixed SSH host keys (comment "sysadmin@HDM")
// with no first-boot regeneration. Parsing the exact public keys extracted from
// the firmware must reproduce the catalogued fingerprints and bkhashes and match
// both the shared-host-key and badkey tables -- proving the H3C entries are correct.
func TestH3CSharedHostKeys(t *testing.T) {
	cases := []struct {
		name, authLine, wantFP, wantBK string
	}{
		{
			"rsa",
			"ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDEuBeWw/lL6QvFLWi07MGDQ74YXrQr/YEdmAVA/CgA5uyOl9PVcMTUrpLPEdoRE0ZjHm1i+pspKNzbbdlNmG69gBAaofDSqOKmN3t50id3Wf+2AGJ6qzktsZIuGsZr0A0zv5LD39Ovrjp+hw0fhYSkokKRYTGoWJpTl/fFpnfm5p3g8cWbU48S6mclYLllCRwDD2IyGftvh28n+fY0A5LB5W3pUvaTqswDCPU4HGyzzr3/g2UF+Y5YxdeePapL9DrLCyZ5NxNgpi6L+UrQSxfIDS1yMLwvAXQM794tetZ6Dw3evW2529j4OdvrMG/zcQ4YZGpKB/+zc3Ajf+uUQDOAAvrNZwIzeA8uG1D6LMLuImqA1sOqtItqCvCvq3490J/3wY7k0/qWfrD7x0BvWHhtnqn9ifJiIl8tnbkS4xSjvWjHEf6ycOhzf3EV3BtsA6dfM2/5dhlAwE5CCnJkRczzZRfw4Ij0IzMKXmYiAvheZpOAxMTrQKPckaiqqk4VEdk= sysadmin@HDM",
			"SHA256:wC3o1vT7LNMZcDOT4YBR+PlTH1nzNeb+atUorjCjXTw",
			"wZB8T0k1CU/W7AbBiv1b",
		},
		{
			"ed25519",
			"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEx5ROwHuM8VsXu0gtY2VsFTxnVyxDvuvaDgaGks3VEw sysadmin@HDM",
			"SHA256:1v4RYLO9AAf3P3u1XwpMnXUUFrWB5eYsADAeVIp2yfs",
			"JDP7rsplKIC6pzE8DNTw",
		},
	}
	for _, c := range cases {
		pub, _, _, _, err := xssh.ParseAuthorizedKey([]byte(c.authLine))
		if err != nil {
			t.Fatalf("%s: ParseAuthorizedKey: %v", c.name, err)
		}
		if fp := HostKeyFingerprint(pub); fp != c.wantFP {
			t.Errorf("%s: fingerprint = %q, want %q", c.name, fp, c.wantFP)
		}
		shk, ok := MatchSharedHostKey(c.wantFP)
		if !ok || shk.Vendor != "h3c" {
			t.Errorf("%s: MatchSharedHostKey vendor = %q (ok=%v), want h3c", c.name, shk.Vendor, ok)
		}
		bkh, bk, ok := HostKeyBadKey(pub)
		if !ok || bkh != c.wantBK || bk.Vendor != "h3c" {
			t.Errorf("%s: HostKeyBadKey = (%q,%q,%v), want (%q,h3c,true)", c.name, bkh, bk.Vendor, ok, c.wantBK)
		}
	}
}

// Sierra Wireless AirLink ALEOS ships fixed Dropbear RSA + ECDSA host keys baked
// into the read-only SquashFS, byte-identical RV50/RV55. Parsing the
// public keys derived from the extracted dropbear_{rsa,ecdsa}_host_key files must
// reproduce the catalogued fingerprints and bkhashes and match both tables.
func TestSierraSharedHostKeys(t *testing.T) {
	cases := []struct {
		name, authLine, wantFP, wantBK string
	}{
		{
			"rsa",
			"ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEA1wwpSnyOXa7UXfMZy96XaybS+6sFnKDunNApwopit0RM1Ng+zYyZ++wHammCs05OiM7nSLU9h7RCL/ZVrboF9xksrO0POE0wY11FxJC2+/V4Kthg9DkE+dhntRlDndtFPcvpq7DGd7CSDD+I4CfAL9M+KUwWTt09zcl34McMTYcjQaGyvdsqMxfxVtJ6eJ5z/yep71e7i8B8AAWWrlr1eRqpN5cPIZPiTT/1jZ1BoZFbisGgDcNs2EAffzvq+SGQjsZBPChBkpkhIxz2WZXoFAm/bSislue0cL2g35hoYvrHnj4FQhj/5MPn9tdu48S6KtI3YXDpmjmai9bb4uPwFw== sierra",
			"SHA256:iuxeW3h71pKpYK+PwWG/7ztNAIUom1sdrEu9DbCXwec",
			"Hlj/L0gDKtOqkBNlXvhg",
		},
		{
			"ecdsa",
			"ecdsa-sha2-nistp521 AAAAE2VjZHNhLXNoYTItbmlzdHA1MjEAAAAIbmlzdHA1MjEAAACFBAE9rRsFDeTpRn3uUIAiCCznR8ThIeHVtN3yEfdDYFWTCYDStL1h5QNemGvi8hwHq0ZGB+jv/tqsseeFQ7XhPZP9BgFTqclCJC5GkM7XmnBzoszXahmOEaDZleW3WSSkkNGScE55G4znZx0Wn2hk6JpewrqA3B1UIa9SbkpImSE5vKZL5Q== sierra",
			"SHA256:c6bKq+FIyClFG5TdLztGDKMb5LzCkzl8JzfoDo90sKY",
			"8y1de1e89X4lv2thEgHp",
		},
	}
	for _, c := range cases {
		pub, _, _, _, err := xssh.ParseAuthorizedKey([]byte(c.authLine))
		if err != nil {
			t.Fatalf("%s: ParseAuthorizedKey: %v", c.name, err)
		}
		if fp := HostKeyFingerprint(pub); fp != c.wantFP {
			t.Errorf("%s: fingerprint = %q, want %q", c.name, fp, c.wantFP)
		}
		shk, ok := MatchSharedHostKey(c.wantFP)
		if !ok || shk.Vendor != "sierra" {
			t.Errorf("%s: MatchSharedHostKey vendor = %q (ok=%v), want sierra", c.name, shk.Vendor, ok)
		}
		bkh, bk, ok := HostKeyBadKey(pub)
		if !ok || bkh != c.wantBK || bk.Vendor != "sierra" {
			t.Errorf("%s: HostKeyBadKey = (%q,%q,%v), want (%q,sierra,true)", c.name, bkh, bk.Vendor, ok, c.wantBK)
		}
	}
}

// The catalogued fingerprints must be well-formed OpenSSH SHA-256 strings.
func TestKnownSharedHostKeysWellFormed(t *testing.T) {
	if len(knownSharedHostKeys) == 0 {
		t.Fatal("knownSharedHostKeys is empty")
	}
	for _, k := range knownSharedHostKeys {
		if k.Vendor == "" || k.Product == "" {
			t.Errorf("%+v: missing vendor/product", k)
		}
		if !strings.HasPrefix(k.Fingerprint, "SHA256:") {
			t.Errorf("%s: fingerprint %q must start with SHA256:", k.Vendor, k.Fingerprint)
		}
	}
}

// marshalString encodes a string as SSH wire format (uint32 length + bytes).
func marshalString(s string) []byte {
	n := len(s)
	out := []byte{byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)}
	return append(out, s...)
}
