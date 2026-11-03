package asd

import (
	"bytes"
	"net"
	"reflect"
	"testing"
	"time"
)

// bannerServer starts a TCP listener that sends the given bytes on connect and
// holds the connection open briefly, then closes.
func bannerServer(t *testing.T, banner []byte) (host string, port int, closeFn func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			if len(banner) > 0 {
				_, _ = c.Write(banner)
			}
			_ = c.Close()
		}
	}()
	_, ps, _ := net.SplitHostPort(ln.Addr().String())
	p := 0
	for _, ch := range ps {
		p = p*10 + int(ch-'0')
	}
	return "127.0.0.1", p, func() { _ = ln.Close() }
}

// TestDialAuthPromptRequiresASDPrompt guards the false-positive fixed after the
// A generic connect banner (e.g. a lone newline) must not be
// treated as an ASD authpam prompt. Only a prompt beginning with the ASD
// status byte 0x30 marks the service as ASD.
func TestDialAuthPromptRequiresASDPrompt(t *testing.T) {
	// Non-ASD banner: must not set AuthPrompted.
	host, port, stop := bannerServer(t, []byte{0x0a})
	defer stop()
	c, err := Dial(host, port, Options{Timeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if c.AuthPrompted {
		t.Error("newline banner must not be treated as an ASD authpam prompt")
	}

	// ASD authpam prompt (0x30 first): must set AuthPrompted.
	host2, port2, stop2 := bannerServer(t, []byte{0x30, 'P', 'A', 'M'})
	defer stop2()
	c2, err := Dial(host2, port2, Options{Timeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer c2.Close()
	if !c2.AuthPrompted {
		t.Error("0x30-first prompt must be recognized as ASD authpam")
	}
}

// TestDialAuthPromptRejectsCompetingProtocols guards the field false positives:
// a bare 0x30 first byte also matches the ASN.1/BER SEQUENCE tag and ASCII '0',
// so LDAP/SNMP responses and bencode P2P handshakes were wrongly flagged as ASD
// authpam prompts. Both must now be rejected.
func TestDialAuthPromptRejectsCompetingProtocols(t *testing.T) {
	cases := []struct {
		name   string
		banner []byte
	}{
		// LDAP BindResponse (observed on 5123/tcp): SEQUENCE{messageID 1,
		// [APPLICATION 1] resultCode success}. 0x30 0x0c 0x02 ...
		{"ldap-bindresponse", []byte{0x30, 0x0c, 0x02, 0x01, 0x01, 0x61, 0x07, 0x0a, 0x01, 0x00, 0x04, 0x00, 0x04, 0x00}},
		// SNMP GetResponse-shaped BER: 0x30 <len> 0x02 0x01 0x00 (version).
		{"snmp-ber", []byte{0x30, 0x26, 0x02, 0x01, 0x00, 0x04, 0x06}},
		// BER with long-form length: 0x30 0x82 <2 len bytes> 0x02 ...
		{"ber-longform", []byte{0x30, 0x82, 0x01, 0x2c, 0x02, 0x01, 0x01}},
		// bencode P2P sync handshake (observed on 6868/tcp): "0097..." -> digits.
		{"bencode-handshake", []byte("00970795:d7:smethod6:shello")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			host, port, stop := bannerServer(t, tc.banner)
			defer stop()
			c, err := Dial(host, port, Options{Timeout: 2 * time.Second})
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			if c.AuthPrompted {
				t.Errorf("%s (0x30-led but not ASD) must not be treated as an authpam prompt", tc.name)
			}
		})
	}
}

func TestHeaderRoundTrip(t *testing.T) {
	cases := []Header{
		{Type: TypeJTAG, Size: 0, CmdStat: 0x00, Tag: 1, Origin: 0},
		{Type: TypeAgentControl, Size: 3000, CmdStat: 0x2A, Tag: 7, Origin: 5},
		{Type: TypeI2C, Size: 1234, CmdStat: 0xFF, Tag: 3, Origin: 2, Enc: 1},
	}
	for i, want := range cases {
		got := UnpackHeader(want.Pack())
		if got.Type != want.Type || got.Size != want.Size || got.CmdStat != want.CmdStat ||
			got.Tag != want.Tag || got.Origin != want.Origin || got.Enc != want.Enc {
			t.Fatalf("case %d: round trip mismatch: want %+v got %+v", i, want, got)
		}
	}
}

func TestOpcodeEncodings(t *testing.T) {
	// IR write, 8 bits value 0x22, end Run-Test-Idle.
	ir, err := BuildIRWrite(0x22, 8, TAPRunTestIdle)
	if err != nil {
		t.Fatal(err)
	}
	if want := []byte{0x2B, 0x48, 0x22, 0x21}; !bytes.Equal(ir, want) {
		t.Fatalf("IR write: want %x got %x", want, ir)
	}

	// DR read, 64 bits -> single chunk.
	dr64, out64, err := BuildDRRead(64, TAPRunTestIdle)
	if err != nil {
		t.Fatal(err)
	}
	if want := []byte{0x24, 0x80, 0x21}; !bytes.Equal(dr64, want) {
		t.Fatalf("DR64: want %x got %x", want, dr64)
	}
	if out64 != 8 {
		t.Fatalf("DR64 out len: want 8 got %d", out64)
	}

	// DR read, 96 bits -> 64+32 chunked, staying in Shift-DR between chunks.
	dr96, out96, err := BuildDRRead(96, TAPRunTestIdle)
	if err != nil {
		t.Fatal(err)
	}
	if want := []byte{0x24, 0x80, 0x24, 0xA0, 0x21}; !bytes.Equal(dr96, want) {
		t.Fatalf("DR96: want %x got %x", want, dr96)
	}
	if out96 != 12 {
		t.Fatalf("DR96 out len: want 12 got %d", out96)
	}
}

func TestStatusHelpers(t *testing.T) {
	if StatusName(StatusMsgNotSupported) != "ASD_MSG_NOT_SUPPORTED" {
		t.Fatalf("status name lookup failed")
	}
	if !HardwareBlocked(StatusXDPPresent) {
		t.Fatalf("XDP_PRESENT should be hardware-blocked")
	}
	if HardwareBlocked(StatusSuccess) {
		t.Fatalf("SUCCESS should not be hardware-blocked")
	}
}

func TestAgentQueriesAndIDCODE(t *testing.T) {
	const wantID = 0x12345678
	m, host, port, err := StartMockServer(wantID, "ASD_BMC_v1.4.4")
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()

	c, err := Dial(host, port, Options{Timeout: 3 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()

	if v, err := c.Version(); err != nil || v != "ASD_BMC_v1.4.4" {
		t.Fatalf("version: %q err=%v", v, err)
	}
	if n, err := c.MaxDataSizeReported(); err != nil || n != 3000 {
		t.Fatalf("max-data-size: %d err=%v", n, err)
	}
	if n, err := c.NumInFlight(); err != nil || n != 20 {
		t.Fatalf("num-in-flight: %d err=%v", n, err)
	}
	if n, err := c.SupportedJTAGChains(); err != nil || n != 1 {
		t.Fatalf("supported-jtag-chains: %d err=%v", n, err)
	}
	echo := []byte{0xDE, 0xAD, 0xBE, 0xEF}
	if got, err := c.Loopback(echo); err != nil || !bytes.Equal(got, echo) {
		t.Fatalf("loopback: %x err=%v", got, err)
	}
	id, res, err := c.IDCODE()
	if err != nil {
		t.Fatal(err)
	}
	if id != wantID {
		t.Fatalf("idcode: want %#x got %#x", uint32(wantID), id)
	}
	if res.Blocked {
		t.Fatalf("idcode should not be hardware-blocked with a live mock")
	}
}

func TestDMARejected(t *testing.T) {
	m, host, port, err := StartMockServer(0, "x")
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	c, err := Dial(host, port, Options{Timeout: 3 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	h, _, err := c.Exchange(TypeDMA, 0x00, []byte{0x01, 0x02})
	if err != nil {
		t.Fatal(err)
	}
	if h.CmdStat != StatusMsgNotSupported {
		t.Fatalf("DMA: want ASD_MSG_NOT_SUPPORTED got %s", StatusName(h.CmdStat))
	}
}

func TestIDCODEBuilder(t *testing.T) {
	ops, out := BuildIDCODE()
	want := []byte{0x14, 0x21, 0x24, 0xA0, 0x21}
	if !reflect.DeepEqual(ops, want) {
		t.Fatalf("IDCODE builder: want %x got %x", want, ops)
	}
	if out != 4 {
		t.Fatalf("IDCODE out len: want 4 got %d", out)
	}
}
