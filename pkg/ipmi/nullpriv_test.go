package ipmi

import "testing"

func TestPrivilegeName(t *testing.T) {
	for _, tc := range []struct {
		level byte
		want  string
	}{
		{PrivUnspecified, "unspecified"},
		{PrivCallback, "callback"},
		{PrivUser, "user"},
		{PrivOperator, "operator"},
		{PrivAdministrator, "administrator"},
		{PrivOEM, "oem"},
		{PrivNoAccess, "noAccess"},
		// The reply byte carries the level in the low nibble; reserved high bits
		// must not change the name.
		{0xf4, "administrator"},
		{0x07, "unknown(0x07)"},
	} {
		if got := PrivilegeName(tc.level); got != tc.want {
			t.Errorf("PrivilegeName(0x%02x)=%q, want %q", tc.level, got, tc.want)
		}
	}
}

func TestNullUserProbeUsableAccessThreshold(t *testing.T) {
	// USER (2) is the threshold: below it the account reaches only a handful of
	// session/GUID commands, so it must not read as usable access.
	for _, tc := range []struct {
		name  string
		probe *NullUserPrivProbe
		want  bool
	}{
		{"nil", nil, false},
		{"not activated", &NullUserPrivProbe{}, false},
		{"activated but unmeasured", &NullUserPrivProbe{Activated: true}, false},
		{"privilege 0", &NullUserPrivProbe{Activated: true, PrivilegeOK: true, Privilege: PrivUnspecified}, false},
		{"callback", &NullUserPrivProbe{Activated: true, PrivilegeOK: true, Privilege: PrivCallback}, false},
		{"user", &NullUserPrivProbe{Activated: true, PrivilegeOK: true, Privilege: PrivUser}, true},
		{"operator", &NullUserPrivProbe{Activated: true, PrivilegeOK: true, Privilege: PrivOperator}, true},
		{"administrator", &NullUserPrivProbe{Activated: true, PrivilegeOK: true, Privilege: PrivAdministrator}, true},
		// 0x0f is numerically above USER but means no access.
		{"no-access", &NullUserPrivProbe{Activated: true, PrivilegeOK: true, Privilege: PrivNoAccess}, false},
	} {
		if got := tc.probe.UsableAccess(); got != tc.want {
			t.Errorf("%s: UsableAccess()=%t, want %t", tc.name, got, tc.want)
		}
	}
}

func TestNullUserProbeStatus(t *testing.T) {
	for _, tc := range []struct {
		name  string
		probe *NullUserPrivProbe
		want  string
	}{
		{"nil", nil, "notProbed"},
		{"session failed", &NullUserPrivProbe{Error: "rakp4 status=0x08"}, "sessionFailed"},
		{"privilege query denied", &NullUserPrivProbe{Activated: true, PrivilegeCC: 0xd4}, "privilegeUnmeasured"},
		{"measured", &NullUserPrivProbe{Activated: true, PrivilegeOK: true}, "measured"},
	} {
		if got := tc.probe.Status(); got != tc.want {
			t.Errorf("%s: Status()=%q, want %q", tc.name, got, tc.want)
		}
	}
}

func TestSOLConfigReadableAndSummary(t *testing.T) {
	if (*SOLConfig)(nil).Readable() {
		t.Error("nil SOLConfig must not report readable")
	}
	if (&SOLConfig{Params: map[byte]string{}}).Readable() {
		t.Error("SOLConfig with no answered parameters must not report readable")
	}
	if got := (*SOLConfig)(nil).Summary(); got != "" {
		t.Errorf("nil Summary()=%q, want empty", got)
	}

	// A representative SOL readout at privilege 0: SOL on, activation gated at
	// OPERATOR, payload on channel 1 port 623.
	sol := &SOLConfig{
		ParamRevision:       0x11,
		Enabled:             true,
		EnabledOK:           true,
		RequiredPrivilege:   PrivOperator,
		RequiredPrivilegeOK: true,
		PayloadChannel:      1,
		PayloadChannelOK:    true,
		PayloadPort:         623,
		PayloadPortOK:       true,
		Params:              map[byte]string{SOLParamEnable: "1101"},
	}
	if !sol.Readable() {
		t.Fatal("SOLConfig with an answered parameter must report readable")
	}
	want := "solEnabled=true requiredPrivilege=operator payloadChannel=1 payloadPort=623"
	if got := sol.Summary(); got != want {
		t.Errorf("Summary()=%q, want %q", got, want)
	}

	// A partial readout must render only what answered, not zero values.
	partial := &SOLConfig{Enabled: true, EnabledOK: true, Params: map[byte]string{SOLParamEnable: "1101"}}
	if got := partial.Summary(); got != "solEnabled=true" {
		t.Errorf("partial Summary()=%q, want solEnabled=true", got)
	}
}

func TestNullUserProbeSuitesPrefersFullCryptoAndBounds(t *testing.T) {
	// No advertised list falls back to the modern defaults.
	got := nullUserProbeSuites(nil)
	if len(got) != 2 {
		t.Fatalf("nullUserProbeSuites(nil) returned %d suites, want 2", len(got))
	}
	if got[0].Suite != 17 || got[1].Suite != 3 {
		t.Errorf("default suites = %d,%d; want 17,3", got[0].Suite, got[1].Suite)
	}

	// An advertised list that leads with cipher 0 and weak suites must still yield
	// full-crypto suites, and must never yield an unauthenticated triple -- a
	// cipher-zero session would measure the cipher-zero bypass, not the account.
	got = nullUserProbeSuites([]int{0, 1, 2, 3, 8})
	if len(got) != 2 {
		t.Fatalf("returned %d suites, want 2", len(got))
	}
	for _, ca := range got {
		if ca.Auth == RAKPNone {
			t.Errorf("suite %d has no authentication algorithm", ca.Suite)
		}
		if ca.Integrity == IntegrityNone || ca.Conf == ConfNone {
			t.Errorf("suite %d is not full-crypto (integrity=0x%02x conf=0x%02x)", ca.Suite, ca.Integrity, ca.Conf)
		}
	}
}

func TestOpenSession20NullUserRejectsCipherZero(t *testing.T) {
	// Guard for direct callers: cipher-zero authenticates nothing, so a "null
	// user" result over it would be meaningless. This must fail before any packet
	// leaves, so the unroutable host below is never dialed.
	_, _, err := OpenSession20NullUser("192.0.2.1", 623, "", CipherAlgos{Suite: 0, Auth: RAKPNone}, 0)
	if err == nil {
		t.Fatal("OpenSession20NullUser accepted a cipher-zero suite, want error")
	}
}

func TestParseOpenSessionRespFullReturnsMaxPrivilege(t *testing.T) {
	// Open Session Response: tag, status 0, maxPriv, rsvd, consoleSID, bmcSID.
	// The maxPriv byte is the channel ceiling -- ADMINISTRATOR here -- and the
	// caller records it precisely because it does not track the account.
	payload := []byte{
		0x00, 0x00, 0x04, 0x00,
		0xa1, 0xa2, 0xa3, 0xa4,
		0x11, 0x22, 0x33, 0x44,
	}
	pkt := buildRMCPPlus(PayloadOpenSessionRes, 0, 0, payload)
	bmcSID, maxPriv, err := parseOpenSessionRespFull(pkt)
	if err != nil {
		t.Fatalf("parseOpenSessionRespFull: %v", err)
	}
	if bmcSID != 0x44332211 {
		t.Errorf("bmcSID=0x%08x, want 0x44332211", bmcSID)
	}
	if maxPriv != PrivAdministrator {
		t.Errorf("maxPriv=0x%02x, want 0x%02x", maxPriv, PrivAdministrator)
	}
	// The narrow parser must stay wire-compatible with the full one.
	sid2, err := parseOpenSessionResp(pkt)
	if err != nil || sid2 != bmcSID {
		t.Errorf("parseOpenSessionResp=0x%08x (err=%v), want 0x%08x", sid2, err, bmcSID)
	}
}
