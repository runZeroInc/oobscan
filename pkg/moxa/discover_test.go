package moxa

import "testing"

func TestExtractFirmware(t *testing.T) {
	cases := []struct {
		name string
		data []byte
		want string
	}{
		{"strict version", []byte("NPort 5110 V1.15 Build_12345"), "V1.15"},
		{"three-part version", []byte("\x00\x00V3.4.2\x00"), "V3.4.2"},
		{"ver prefix", []byte("Moxa NPort Ver 1.15 Build 4"), "V1.15"},
		// The stray V in "NPort" must not be mistaken for a version.
		{"model only, no version", []byte("NPort 5150A"), ""},
		{"bare V with no digits", []byte("Very NPort device"), ""},
		{"empty", []byte(""), ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := extractFirmware(c.data); got != c.want {
				t.Errorf("extractFirmware(%q) = %q, want %q", c.data, got, c.want)
			}
		})
	}
}

func TestParseResponseRichFields(t *testing.T) {
	data := []byte{
		0x00, 0x01, 0x00, 0x00,
		0x10, 0x00, 0x90, 0xE8, 0x11, 0x22, 0x33,
		192, 168, 10, 44,
		'N', 'P', 'o', 'r', 't', ' ', '5', '1', '1', '0', 0x00,
		'S', 'N', '1', '2', '3', '4', '5', '6', 0x00,
		'V', '1', '.', '1', '5', 0x00,
	}
	b := make([]byte, 4+len(data))
	b[0] = 0x01
	b[1] = 0x81
	b[2] = byte(len(data) >> 8)
	b[3] = byte(len(data))
	copy(b[4:], data)

	r, ok := parse(b)
	if !ok {
		t.Fatal("expected valid moxa parse")
	}
	if r.MAC != "00:90:e8:11:22:33" {
		t.Fatalf("mac=%q", r.MAC)
	}
	if r.IP != "192.168.10.44" {
		t.Fatalf("ip=%q", r.IP)
	}
	if r.Ports != 16 {
		t.Fatalf("ports=%d", r.Ports)
	}
	if r.Model != "NPort 5110" {
		t.Fatalf("model=%q", r.Model)
	}
	if r.Serial != "SN123456" {
		t.Fatalf("serial=%q", r.Serial)
	}
	if r.Firmware != "V1.15" {
		t.Fatalf("firmware=%q", r.Firmware)
	}
}

func TestParseRejectsWrongOpcode(t *testing.T) {
	b := []byte{0x01, 0x82, 0x00, 0x00}
	if _, ok := parse(b); ok {
		t.Fatal("expected parse reject for non-0x81 opcode")
	}
}

func TestMagicQueryCanonical(t *testing.T) {
	want := []byte{0x01, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00}
	if len(MagicQuery) != len(want) {
		t.Fatalf("magic query len=%d want=%d", len(MagicQuery), len(want))
	}
	for i := range want {
		if MagicQuery[i] != want[i] {
			t.Fatalf("magic query byte[%d]=0x%02x want=0x%02x", i, MagicQuery[i], want[i])
		}
	}
}

func TestParseCanonicalReply(t *testing.T) {
	b := []byte{
		0x81, 0x00, 0x00, 0x18,
		0x00, 0x00, 0x00, 0x00,
		0x70, 0x17, // product line (LE)
		0x00, 0x80,
		0x1a, 0x14, // model id 5146 (LE)
		0x00, 0x90, 0xe8, 0x11, 0x22, 0x33,
		192, 168, 1, 50,
	}
	r, ok := parse(b)
	if !ok {
		t.Fatal("expected canonical parse")
	}
	if r.MAC != "00:90:e8:11:22:33" {
		t.Fatalf("mac=%q", r.MAC)
	}
	if r.IP != "192.168.1.50" {
		t.Fatalf("ip=%q", r.IP)
	}
	if r.Model != "NPort 5146" {
		t.Fatalf("model=%q", r.Model)
	}
}

func TestParseASCIIStatusFallback(t *testing.T) {
	b := []byte("Moxa Nport Device\nStatus: Authentication disabled\nName: NP5150A_2429\nMAC: 00:90:e8:71:de:0e\n")
	r, ok := parse(b)
	if !ok {
		t.Fatal("expected ASCII status parse")
	}
	if r.Model != "Moxa Nport Device" {
		t.Fatalf("model=%q", r.Model)
	}
	if r.Hostname != "NP5150A_2429" {
		t.Fatalf("hostname=%q", r.Hostname)
	}
	if r.MAC != "00:90:e8:71:de:0e" {
		t.Fatalf("mac=%q", r.MAC)
	}
	if r.Auth != "Authentication disabled" {
		t.Fatalf("auth=%q", r.Auth)
	}
}

func TestParseASCIIStatusFallbackHexMAC(t *testing.T) {
	b := []byte("Moxa Nport Device\nName: NP5110A_\u6771\u6cb3\nMAC: 0090E8819C2F\n")
	r, ok := parse(b)
	if !ok {
		t.Fatal("expected ASCII status parse")
	}
	if r.MAC != "00:90:e8:81:9c:2f" {
		t.Fatalf("mac=%q", r.MAC)
	}
}
