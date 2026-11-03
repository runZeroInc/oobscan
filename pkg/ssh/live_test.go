package ssh

import (
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/runZeroInc/oobscan/pkg/bmcfp"
)

// TestBannerRequiresSSHPrefix confirms Banner only returns an SSH identification
// string ("SSH-...") and rejects non-SSH responders (HTTP proxies, binary
// services) that must not be reported as ssh.version or fed to fingerprinting.
func TestBannerRequiresSSHPrefix(t *testing.T) {
	cases := []struct {
		name     string
		reply    string
		wantOK   bool
		wantLine string
	}{
		{"openssh", "SSH-2.0-OpenSSH_9.9\r\n", true, "SSH-2.0-OpenSSH_9.9"},
		{"ssh-after-legal-banner", "Authorized users only\r\nSSH-2.0-dropbear\r\n", true, "SSH-2.0-dropbear"},
		{"http-407", "HTTP/1.1 407 Proxy Authentication Required\r\n\r\n", false, ""},
		{"http-400", "HTTP/1.1 400 Bad Request\r\n", false, ""},
		{"binary", "\x01\x02\x03\x00\xff", false, ""},
		{"overload", "Exceeded MaxStartups\r\n", false, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Skipf("listen: %v", err)
			}
			defer ln.Close()
			go func() {
				conn, e := ln.Accept()
				if e != nil {
					return
				}
				defer conn.Close()
				_, _ = conn.Write([]byte(c.reply))
				time.Sleep(30 * time.Millisecond)
			}()
			_, portStr, _ := net.SplitHostPort(ln.Addr().String())
			port, _ := strconv.Atoi(portStr)
			got, err := Banner("127.0.0.1", port, time.Second)
			if c.wantOK {
				if err != nil || got != c.wantLine {
					t.Fatalf("Banner()=%q,err=%v; want %q,nil", got, err, c.wantLine)
				}
			} else if err == nil {
				t.Fatalf("Banner() accepted non-SSH reply %q as %q; want error", c.reply, got)
			}
		})
	}
}

func TestFingerprintBanner(t *testing.T) {
	// Vendor attribution is asserted; banner-version-inferred CVEs are never
	// asserted (too noisy / backport-blind) - see TestFingerprintBannerNoCVEs.
	cases := []struct {
		banner     string
		wantVendor string
	}{
		{"SSH-2.0-mpSSH_0.0.1", "hpe"},
		{"SSH-2.0-mpSSH_0.2.1", "hpe"},
		{"SSH-2.0-dropbear_2014.66", ""},
		{"SSH-2.0-dropbear_2019.78", ""},
		{"SSH-2.0-OpenSSH_8.4", ""},
	}
	for _, c := range cases {
		_, vendor, cves := FingerprintBanner(c.banner)
		if vendor != c.wantVendor {
			t.Errorf("%s: vendor=%q want %q", c.banner, vendor, c.wantVendor)
		}
		if len(cves) != 0 {
			t.Errorf("%s: asserted CVEs %v, want none", c.banner, cves)
		}
	}
}

func TestWeakAlgos(t *testing.T) {
	ki := &KexInfo{
		KEX:      []string{"curve25519-sha256", "diffie-hellman-group14-sha1", "diffie-hellman-group1-sha1"},
		HostKeys: []string{"rsa-sha2-256", "ssh-rsa", "ssh-dss"},
		Ciphers:  []string{"aes256-gcm@openssh.com", "aes128-cbc", "3des-cbc"},
		MACs:     []string{"hmac-sha2-256", "hmac-sha1-96", "hmac-md5"},
	}
	w := ki.WeakAlgos()
	if len(w["kex"]) != 2 || len(w["cipher"]) != 2 || len(w["mac"]) != 2 || len(w["hostkey"]) != 2 {
		t.Errorf("WeakAlgos = %+v", w)
	}
}

// Banner-version-inferred SSH CVEs (OpenSSH regreSSHion, the Dropbear cluster)
// are intentionally not asserted - too noisy and backport-blind - so
// FingerprintBanner reports the product/build but no CVEs.
func TestFingerprintBannerNoCVEs(t *testing.T) {
	for _, banner := range []string{
		"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.14",
		"SSH-2.0-OpenSSH_8.5",
		"SSH-2.0-dropbear_2014.66",
		"SSH-2.0-dropbear_2019.78",
	} {
		if _, _, cves := FingerprintBanner(banner); len(cves) != 0 {
			t.Errorf("FingerprintBanner(%q) asserted CVEs %v, want none", banner, cves)
		}
	}
}

// TestSoftwareVersion covers the RFC 4253 §4.2 split: "SSH-protoversion-
// softwareversion[ comments]". The comment tail is retained because some
// fingerprints key off it (Oracle ILOM).
func TestSoftwareVersion(t *testing.T) {
	cases := []struct{ in, want string }{
		{"SSH-2.0-mpSSH_0.2.1", "mpSSH_0.2.1"},
		{"SSH-2.0-OpenSSH_7.4p1 +ILOM.1", "OpenSSH_7.4p1 +ILOM.1"},
		{"SSH-2.0-cryptlib", "cryptlib"},
		{"SSH-1.99-dropbear_2016.74", "dropbear_2016.74"},
		{"SSH-2.0-lancom-1.0-x", "lancom-1.0-x"}, // only the first '-' ends protoversion
		// Non-banners pass through untouched: detectHoneypot's "banner is an
		// HTTP response" heuristic reads the same value and needs the prefix.
		{"HTTP/1.1 400 Bad Request", "HTTP/1.1 400 Bad Request"},
		{"", ""},
		{"SSH-2.0", "SSH-2.0"}, // malformed: no softwareversion field
	}
	for _, c := range cases {
		if got := SoftwareVersion(c.in); got != c.want {
			t.Errorf("SoftwareVersion(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// TestFingerprintBannerVendorAgreesWithBMCFP guards against the two components
// disagreeing about the same banner: a silent contradiction between the label a
// finding prints and the vendor the identity resolves to is a defect in itself.
// cryptlib is the case that motivated it, and apc is the correct answer.
func TestFingerprintBannerVendorAgreesWithBMCFP(t *testing.T) {
	for _, wire := range []string{
		"SSH-2.0-mpSSH_0.2.1",
		"SSH-2.0-cryptlib",
		"SSH-2.0-CPS_SSH_ID",
		"SSH-2.0-ServerTech_SSH",
	} {
		_, vendor, _ := FingerprintBanner(wire)
		fpVendor, _, ok := bmcfp.Match(bmcfp.SSHBanner, SoftwareVersion(wire))
		if !ok {
			t.Errorf("%q: no bmcfp rule matched", wire)
			continue
		}
		if vendor != "" && vendor != fpVendor {
			t.Errorf("%q: FingerprintBanner says vendor %q, bmcfp says %q",
				wire, vendor, fpVendor)
		}
	}
}

// TestFingerprintBannerCryptlibNotILO pins the specific misattribution.
func TestFingerprintBannerCryptlibNotILO(t *testing.T) {
	product, vendor, _ := FingerprintBanner("SSH-2.0-cryptlib")
	if strings.Contains(strings.ToLower(product), "ilo") {
		t.Errorf("product = %q; cryptlib is predominantly APC AOS, not iLO", product)
	}
	if vendor != "apc" {
		t.Errorf("vendor = %q, want apc", vendor)
	}
}
