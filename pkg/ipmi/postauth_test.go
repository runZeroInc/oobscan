package ipmi

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

type postauthTestRunner struct {
	lanChannels   []byte
	bootstrapSeen bool
	userNameCalls int
}

type postauthSingleReplyRunner struct {
	netfn byte
	cmd   byte
	cc    byte
	data  []byte
}

func (r *postauthSingleReplyRunner) Exec(netfn, cmd byte, _ []byte) (byte, []byte, error) {
	if netfn == r.netfn && cmd == r.cmd {
		return r.cc, append([]byte(nil), r.data...), nil
	}
	return 0xcc, nil, nil
}

func (r *postauthSingleReplyRunner) Close() {}

func (r *postauthTestRunner) Exec(netfn, cmd byte, data []byte) (byte, []byte, error) {
	switch {
	case netfn == NetFnApp && cmd == CmdGetChannelInfo:
		if len(data) < 1 {
			return 0xc7, nil, nil
		}
		ch := data[0] & 0x0f
		if ch == 0x0e {
			// Current channel is not LAN in this fixture.
			return 0x00, []byte{0x0e, 0x0c}, nil
		}
		if ch == 0x01 {
			return 0x00, []byte{0x01, 0x04}, nil
		}
		return 0x00, []byte{ch, 0x05}, nil

	case netfn == NetFnApp && cmd == CmdGetUserAccess:
		if len(data) < 2 {
			return 0xc7, nil, nil
		}
		if data[0]&0x0f != 0x01 {
			return 0xcc, nil, nil
		}
		uid := data[1]
		if !r.bootstrapSeen && uid == 0x01 {
			r.bootstrapSeen = true
			// bootstrap (max users = 2)
			return 0x00, []byte{0x02}, nil
		}
		switch uid {
		case 0x01:
			// user 1 access
			return 0x00, []byte{0x02, 0x01, 0x14, 0x00}, nil
		case 0x02:
			// user 2 access
			return 0x00, []byte{0x02, 0x01, 0x00, 0x00}, nil
		default:
			return 0xcc, nil, nil
		}

	case netfn == NetFnApp && cmd == CmdGetUserName:
		r.userNameCalls++
		if len(data) < 1 {
			return 0xc7, nil, nil
		}
		switch data[0] {
		case 0x01:
			raw := append([]byte("root"), bytes.Repeat([]byte{0x00}, 11)...)
			raw = append(raw, 0xff)
			return 0x00, raw, nil
		case 0x02:
			return 0x00, []byte{'z', 0xff, 0x00}, nil
		default:
			return 0xcc, nil, nil
		}

	case netfn == NetFnTransport && cmd == CmdGetLANConfigParams:
		if len(data) < 2 {
			return 0xc7, nil, nil
		}
		ch := data[0] & 0x0f
		r.lanChannels = append(r.lanChannels, ch)
		if ch != 0x01 {
			return 0xcc, nil, nil
		}
		sel := data[1]
		switch sel {
		case 3:
			return 0x00, []byte{0x11, 10, 0, 2, 15}, nil
		case 4:
			return 0x00, []byte{0x11, 0x02}, nil
		case 12:
			return 0x00, []byte{0x11, 10, 0, 2, 2}, nil
		case 8:
			return 0x00, []byte{0x11, 0x6f, 0x02}, nil
		default:
			return 0xcc, nil, nil
		}
	}
	return 0xcc, nil, nil
}

func (r *postauthTestRunner) Close() {}

func TestSanitizeUserName(t *testing.T) {
	raw := append([]byte("root"), bytes.Repeat([]byte{0x00}, 11)...)
	raw = append(raw, 0xff)
	if got := sanitizeUserName(raw); got != "root" {
		t.Fatalf("sanitizeUserName = %q, want %q", got, "root")
	}
	if got := sanitizeUserName([]byte{'a', 0x1a}); got != "a" {
		t.Fatalf("sanitizeUserName prefix preservation = %q, want %q", got, "a")
	}
	if got := sanitizeUserName([]byte{0x1a, 0x00}); got != "" {
		t.Fatalf("sanitizeUserName control-only = %q, want empty", got)
	}
}

// Transport errors stay out of the device record (they surface as the finding's
// coverageError field), while Completed/IncompleteAt are serialized: section fields are
// omitempty, so without them an empty section is indistinguishable from one never attempted.
func TestPostAuthCollectionOmitsOperationalStatusFromJSON(t *testing.T) {
	b, err := json.Marshal(PostAuthCollection{
		Error:        "before users: context deadline exceeded",
		Completed:    []string{"mcInfo", "chassis"},
		IncompleteAt: "users",
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "context deadline exceeded") {
		t.Errorf("scan-side transport error leaked into the device record: %s", b)
	}
	for _, want := range []string{`"completed":["mcInfo","chassis"]`, `"incompleteAt":"users"`} {
		if !strings.Contains(string(b), want) {
			t.Errorf("coverage record missing %s from JSON: %s", want, b)
		}
	}
}

func TestPostAuthCollectionIncludesOpenBMCRelabelUser(t *testing.T) {
	b, err := json.Marshal(PostAuthCollection{
		Flow: AuthFlow{Version: "2.0", Mode: "openbmcRelabel", Username: "rzlow", RelabelUser: "root"},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"openbmcRelabel", "relabelUser", "root"} {
		if !strings.Contains(string(b), want) {
			t.Fatalf("expected %q in JSON: %s", want, b)
		}
	}
}

func TestPostAuthCollectionIncludesOpenBMCSetupFlow(t *testing.T) {
	b, err := json.Marshal(PostAuthCollection{
		Flow:              AuthFlow{Version: "2.0", Mode: "openbmcSetup", Username: "root"},
		CommandProtection: "setup-cleartext",
		SetPrivAttempts:   []SetPrivAttempt{{Requested: 0x04, Name: "admin", Success: true, CC: 0x00, Granted: 0x04}},
		OpenBMCSetup:      &OpenBMCSetupData{PrivilegeQueryCC: 0x00, PrivilegeQueryDataHex: "04", PayloadStatusCC: 0x00, PayloadStatusDataHex: "010000", ProviderBlocked: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"openbmcSetup", "setup-cleartext", "setPrivAttempts", "privilegeQueryDataHex", "payloadStatusDataHex", "010000"} {
		if !strings.Contains(string(b), want) {
			t.Fatalf("expected %q in JSON: %s", want, b)
		}
	}
}

func TestPostAuthContextFailureIdentifiesNextStep(t *testing.T) {
	inv, err := postAuthContextFailure(&PostAuthCollection{Completed: []string{"mcInfo"}}, "chassis", context.DeadlineExceeded)
	if err == nil || inv.IncompleteAt != "chassis" || inv.Error != "before chassis: context deadline exceeded" {
		t.Fatalf("failure = inv %+v err %v", inv, err)
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("wrapped failure lost context deadline identity: %v", err)
	}
}

func TestCollectUsersSanitizesAndFiltersGarbage(t *testing.T) {
	r := &postauthTestRunner{}
	users, err := collectUsers(context.Background(), r)
	if err != nil {
		t.Fatalf("collectUsers error: %v", err)
	}
	if len(users) != 2 {
		t.Fatalf("collectUsers count = %d, want 2", len(users))
	}
	if users[0].Name != "root" {
		t.Fatalf("user1 name = %q, want root", users[0].Name)
	}
	if users[1].Name != "" {
		t.Fatalf("user2 name = %q, want empty", users[1].Name)
	}
	if r.userNameCalls != 2 {
		t.Fatalf("GetUserName calls = %d, want 2", r.userNameCalls)
	}
}

func TestCollectLANUsesLANChannelAndDecodesIPv4(t *testing.T) {
	r := &postauthTestRunner{}
	lan, _, err := collectLAN(context.Background(), r)
	if err != nil {
		t.Fatalf("collectLAN error: %v", err)
	}
	if got := lan["ip_addr"]; got != "10.0.2.15" {
		t.Fatalf("ip_addr = %q, want 10.0.2.15", got)
	}
	if got := lan["default_gw_ip"]; got != "10.0.2.2" {
		t.Fatalf("default_gw_ip = %q, want 10.0.2.2", got)
	}
	if got := lan["rmcp_udp_port"]; got != "623" {
		t.Fatalf("rmcp_udp_port = %q, want 623", got)
	}
	for _, ch := range r.lanChannels {
		if ch != 0x01 {
			t.Fatalf("LAN parameter requested on unexpected channel 0x%02x", ch)
		}
	}
}

// TestCollectLANAllParamsDeniedReturnsError locks that a BMC answering every Get LAN
// Configuration Parameters read with cc=0xd4 (insufficient privilege) surfaces an error,
// not a zero-field "success" that the pipeline would record as a completed section.
func TestCollectLANAllParamsDeniedReturnsError(t *testing.T) {
	r := &postauthSingleReplyRunner{
		netfn: NetFnTransport, cmd: CmdGetLANConfigParams,
		cc: 0xd4, data: nil,
	}
	lan, lan6, err := collectLAN(context.Background(), r)
	if err == nil {
		t.Fatal("expected an error when every LAN config param is denied")
	}
	if len(lan) != 0 || len(lan6) != 0 {
		t.Fatalf("lan=%v lan6=%v, want both empty", lan, lan6)
	}
}

func TestCollectMCInfoMasksDeviceRevision(t *testing.T) {
	r := &postauthSingleReplyRunner{
		netfn: NetFnApp,
		cmd:   CmdGetDeviceID,
		cc:    0x00,
		data:  []byte{0x00, 0x80, 0x03, 0x00, 0x02, 0x8d, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
	}
	mi, err := collectMCInfo(context.Background(), r)
	if err != nil {
		t.Fatalf("collectMCInfo error: %v", err)
	}
	if mi.DeviceRevision != 0 {
		t.Fatalf("device_revision = %d, want 0", mi.DeviceRevision)
	}
	if mi.FirmwareRevision != "3.00" {
		t.Fatalf("firmware_revision = %q, want 3.00", mi.FirmwareRevision)
	}
}

func TestCollectChassisStatusParsesDriveCoolingBits(t *testing.T) {
	r := &postauthSingleReplyRunner{
		netfn: NetFnChassis,
		cmd:   CmdGetChassisStatus,
		cc:    0x00,
		data:  []byte{0x00, 0x00, 0x70, 0x30, 0x33},
	}
	cs, err := collectChassisStatus(context.Background(), r)
	if err != nil {
		t.Fatalf("collectChassisStatus error: %v", err)
	}
	if !cs.IdentifyOn {
		t.Fatalf("identify_on = false, want true")
	}
	if cs.DriveFault {
		t.Fatalf("drive_fault = true, want false")
	}
	if cs.CoolingFault {
		t.Fatalf("cooling_fault = true, want false")
	}
}

func TestSanitizeOpaqueString(t *testing.T) {
	cases := []struct {
		name      string
		in        []byte
		want      string
		wantDirty bool
	}{
		{"empty", []byte{}, "", false},
		{"pure_ascii", []byte("public"), "public", false},
		{"ascii_with_nul_pad", append([]byte("public"), 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0), "public", true},
		{"ascii_with_nul_pad_then_ff", append(append([]byte("public"), 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0), 0xff), "public", true},
		{"ascii_with_nul_pad_then_caret", append(append([]byte("public"), 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0), '^'), "public", true},
		{"single_ff_only", []byte{0xff}, "", true},
		{"single_bang", []byte{'!'}, "!", false},
		{"all_nuls", []byte{0, 0, 0, 0}, "", true},
		{"interior_nul", []byte{'a', 0, 'b'}, "a", true},
		{"utf8_valid_no_control", []byte("Supermicro"), "Supermicro", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, dirty := sanitizeOpaqueString(c.in)
			if got != c.want {
				t.Fatalf("got %q, want %q", got, c.want)
			}
			if dirty != c.wantDirty {
				t.Fatalf("dirty=%v, want %v", dirty, c.wantDirty)
			}
		})
	}
}

func TestSelectPostAuthFlowSMCRAKPFixedKey(t *testing.T) {
	auth := &AuthReport{
		Suite: &CipherAlgos{Suite: 17, Auth: RAKPHMACSHA256, Integrity: IntegrityHMACSHA256128, Conf: ConfAESCBC},
		Cracked: []CrackResult{{
			Username:       "ADMIN",
			PasswordType:   "smcrakp-fixed-key",
			Verified:       true,
			CommandCapable: true, // H3 bypass confirmed exploitable -> collect inventory
		}},
	}
	flow, ok := SelectPostAuthFlow(auth, nil)
	if !ok {
		t.Fatal("expected flow to be selected")
	}
	if flow.Mode != "smcrakpFixedKey" {
		t.Fatalf("flow.Mode=%q, want smcrakpFixedKey", flow.Mode)
	}
	if flow.Username != "ADMIN" {
		t.Fatalf("flow.Username=%q, want ADMIN", flow.Username)
	}
	if flow.Source != "ipmi.auth.smcrakpBypass" {
		t.Fatalf("flow.Source=%q, want ipmi.auth.smcrakpBypass", flow.Source)
	}
}

// A SMCRAKP fixed-key that forges a session without being command-capable (X14/OpenBMC
// enforces per-session integrity) is not selected for forged-session inventory: the session
// opens but no command executes, so there is nothing to enumerate.
func TestSelectPostAuthFlowSMCRAKPNotCommandCapable(t *testing.T) {
	auth := &AuthReport{
		Suite: &CipherAlgos{Suite: 17, Auth: RAKPHMACSHA256, Integrity: IntegrityHMACSHA256128, Conf: ConfAESCBC},
		Cracked: []CrackResult{{
			Username:       "ADMIN",
			PasswordType:   "smcrakp-fixed-key",
			Verified:       true,
			CommandCapable: false,
		}},
	}
	if _, ok := SelectPostAuthFlow(auth, nil); ok {
		t.Fatal("expected no post-auth flow for a non-command-capable SMCRAKP session")
	}
}

func TestDecodeLANParamCommunityString(t *testing.T) {
	// Community string with NUL padding and a non-ASCII trailing byte.
	raw := append(append([]byte("public"), bytes.Repeat([]byte{0x00}, 12)...), 0xff)
	got := decodeLANParam(16, raw)
	if got != "public" {
		t.Fatalf("community_string = %q, want %q", got, "public")
	}
}

func TestDecodeFRUFieldASCII(t *testing.T) {
	// FRU field payload commonly comes NUL/space padded.
	raw := append([]byte("Supermicro"), 0x00, 0x00, ' ')
	got := decodeFRUField(0x3, raw)
	if got != "Supermicro" {
		t.Fatalf("fru field = %q, want %q", got, "Supermicro")
	}
}

func TestDecodeFRUFieldSixBitAndBCD(t *testing.T) {
	// 6-bit packed ASCII (enc 0x2): "IPMI" packs LSB-first into 3 bytes.
	if got := decodeFRUField(0x2, []byte{0x29, 0xdc, 0xa6}); got != "IPMI" {
		t.Errorf("6-bit decode = %q, want %q", got, "IPMI")
	}
	// BCD plus (enc 0x1): two nibbles per byte, high nibble first.
	if got := decodeFRUField(0x1, []byte{0x12, 0x34}); got != "1234" {
		t.Errorf("BCD decode = %q, want %q", got, "1234")
	}
	if got := decodeFRUField(0x1, []byte{0x9b, 0xc0}); got != "9-.0" {
		t.Errorf("BCD special-char decode = %q, want %q", got, "9-.0")
	}
	// enc 0x0 (raw binary) still falls back to hex.
	if got := decodeFRUField(0x0, []byte{0xde, 0xad}); got != "dead" {
		t.Errorf("binary decode = %q, want %q", got, "dead")
	}
}

// TestParseFRUFieldsBlankFieldIndex locks that a present-but-blank field (all spaces) still
// advances the positional index, so later fields keep the correct Name -- otherwise the
// Serial is emitted under the Version index.
func TestParseFRUFieldsBlankFieldIndex(t *testing.T) {
	// Build a FRU image: 8-byte common header + one Product area at offset 8.
	// Product area TLV (starts at area[3]): Mfg, Name, Part, <all-spaces>, Serial.
	tl := func(s string) []byte { return append([]byte{0xc0 | byte(len(s))}, []byte(s)...) }
	area := []byte{0x01, 0x00, 0x00} // version, length(placeholder), language
	area = append(area, tl("ACME")...)
	area = append(area, tl("WIDGET")...)
	area = append(area, tl("PN-1")...)
	area = append(area, tl("   ")...) // present but decodes to "" (idx must still advance)
	area = append(area, tl("SN-9")...)
	area = append(area, 0xc1) // end marker
	for len(area)%8 != 0 {
		area = append(area, 0x00)
	}
	area[1] = byte(len(area) / 8)
	raw := []byte{0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00} // product offset = 1 (*8 = 8)
	raw = append(raw, area...)

	fields := parseFRUFields(raw, 16, 0)
	var serial *FRUField
	for i := range fields {
		if fields[i].Value == "SN-9" {
			serial = &fields[i]
		}
	}
	if serial == nil {
		t.Fatal("Serial field SN-9 not parsed")
	}
	// idx 4 = Product Serial (0 Mfg, 1 Name, 2 Part, 3 blank Version, 4 Serial).
	if serial.Index != 4 {
		t.Errorf("SN-9 at index %d (name %q); want index 4 -- blank field failed to advance idx",
			serial.Index, serial.Name)
	}
}

type fruAliasRunner struct {
	raw []byte
}

func (r *fruAliasRunner) Exec(netfn, cmd byte, data []byte) (byte, []byte, error) {
	if netfn != NetFnStorage {
		return 0xcc, nil, nil
	}
	if len(data) == 0 {
		return 0xc7, nil, nil
	}
	dev := data[0]
	switch cmd {
	case CmdGetFRUInventoryInfo:
		if dev > 1 {
			return 0xc1, nil, nil
		}
		info := make([]byte, 3)
		binary.LittleEndian.PutUint16(info[:2], uint16(len(r.raw)))
		info[2] = 0x00
		return 0x00, info, nil
	case CmdReadFRUData:
		if dev > 1 {
			return 0xc1, nil, nil
		}
		if len(data) < 4 {
			return 0xc7, nil, nil
		}
		off := int(data[1]) | int(data[2])<<8
		cnt := int(data[3])
		if off >= len(r.raw) {
			return 0x00, []byte{0x00}, nil
		}
		end := min(off+cnt, len(r.raw))
		chunk := r.raw[off:end]
		resp := make([]byte, 1+len(chunk))
		resp[0] = byte(len(chunk))
		copy(resp[1:], chunk)
		return 0x00, resp, nil
	default:
		return 0xcc, nil, nil
	}
}

func (r *fruAliasRunner) Close() {}

func TestCollectFRUKeepsAliasedDevices(t *testing.T) {
	raw := make([]byte, 32)
	raw[0] = 0x01 // common header format
	raw[3] = 0x01 // board area offset at 8 bytes
	board := 8
	raw[board+0] = 0x01 // board area format
	raw[board+1] = 0x03 // area length = 24 bytes
	raw[board+2] = 0x00 // language code
	raw[board+6] = 0xca // type=ASCII(0x3), length=10
	copy(raw[board+7:], []byte("Supermicro"))
	raw[board+17] = 0xc1 // end-of-fields marker

	r := &fruAliasRunner{raw: raw}
	got, err := collectFRU(context.Background(), r, 16)
	if err != nil {
		t.Fatalf("collectFRU() error: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("collectFRU() fields=%d, want 2 (%v)", len(got), got)
	}
	if got[0].DeviceID != 0 {
		t.Fatalf("collectFRU() device=%d, want 0", got[0].DeviceID)
	}
	if got[1].DeviceID != 1 {
		t.Fatalf("collectFRU() device=%d, want 1", got[1].DeviceID)
	}
	if got[0].Area != "board" || got[0].Index != 0 || got[0].Value != "Supermicro" {
		t.Fatalf("collectFRU() unexpected field: %+v", got[0])
	}
	if got[1].Area != "board" || got[1].Index != 0 || got[1].Value != "Supermicro" {
		t.Fatalf("collectFRU() unexpected field: %+v", got[1])
	}
}

func TestParseFRUFieldsContinuesPastZeroLength(t *testing.T) {
	raw := make([]byte, 80)
	raw[0] = 0x01
	raw[4] = 0x01 // product area starts at byte 8

	prod := 8
	raw[prod+0] = 0x01 // area format
	raw[prod+1] = 0x06 // 48 bytes
	raw[prod+2] = 0x00 // language
	raw[prod+3] = 0x00 // empty field (must not terminate parsing)
	raw[prod+4] = 0xc3 // ASCII len=3
	copy(raw[prod+5:], []byte("X14"))
	raw[prod+8] = 0xc1 // end marker

	got := parseFRUFields(raw, 16, 0)
	if len(got) != 1 {
		t.Fatalf("parseFRUFields() fields=%d, want 1 (%v)", len(got), got)
	}
	if got[0].Area != "product" || got[0].Index != 1 || got[0].Value != "X14" {
		t.Fatalf("parseFRUFields() unexpected field: %+v", got[0])
	}
}
