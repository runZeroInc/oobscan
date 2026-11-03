package ipmi

import (
	"strings"
	"testing"
)

// openSessionRespPkt frames an Open Session Response payload the way a BMC does:
// RMCP header, IPMI 2.0 session header with payload type 0x11, then the payload.
func openSessionRespPkt(payload []byte) []byte {
	pkt := []byte{0x06, 0x00, 0xff, 0x07, 0x06, 0x11, 0, 0, 0, 0, 0, 0, 0, 0}
	pkt = append(pkt, byte(len(payload)), byte(len(payload)>>8))
	return append(pkt, payload...)
}

// A rejection may stop after the remote-console session ID, so it is 8 bytes and
// never reaches the 12 a success carries. Reading the length before the status
// reported every rejection as "short open-session payload" and hid the reason -
// which is how an iLO 4 refusing SHA-256 looked like a credential failure.
func TestParseOpenSessionRespReportsShortRejection(t *testing.T) {
	// tag=0, status=0x05 (invalid integrity algorithm), maxPriv, rsvd, console SID
	pkt := openSessionRespPkt([]byte{0x00, 0x05, 0x00, 0x00, 0x21, 0x16, 0x9c, 0xd6})

	_, _, err := parseOpenSessionRespFull(pkt)
	if err == nil {
		t.Fatal("expected an error for a rejected open session")
	}
	msg := err.Error()
	if strings.Contains(msg, "short open-session payload") {
		t.Errorf("rejection reported as a short payload, hiding the status: %v", err)
	}
	if !strings.Contains(msg, "status=0x05") {
		t.Errorf("error does not carry the status byte: %v", err)
	}
	if !strings.Contains(msg, "invalid integrity algorithm") {
		t.Errorf("error does not decode the status: %v", err)
	}
}

// A payload too short to hold even a status byte is still a short payload.
func TestParseOpenSessionRespTrulyShort(t *testing.T) {
	if _, _, err := parseOpenSessionRespFull(openSessionRespPkt([]byte{0x00})); err == nil ||
		!strings.Contains(err.Error(), "short open-session payload") {
		t.Errorf("want short-payload error, got %v", err)
	}
}

func TestParseOpenSessionRespSuccessUnchanged(t *testing.T) {
	pkt := openSessionRespPkt([]byte{
		0x00, 0x00, 0x04, 0x00,
		0x21, 0x16, 0x9c, 0xd6, // remote console SID
		0xef, 0xbe, 0xad, 0xde, // managed system SID
	})
	sid, priv, err := parseOpenSessionRespFull(pkt)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if sid != 0xdeadbeef {
		t.Errorf("managed system SID = 0x%08x, want 0xdeadbeef", sid)
	}
	if priv != 0x04 {
		t.Errorf("maxPriv = 0x%02x, want 0x04", priv)
	}
}

// Only an algorithm rejection should trigger the blind cipher-suite fallback; a
// credential or transport failure must not cause a renegotiation loop.
func TestOpenSessionAlgoRejected(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		want bool
	}{
		{"invalid auth algo", errString("open-session rejected: status=0x04 (invalid authentication algorithm)"), true},
		{"invalid integrity algo", errString("open-session rejected: status=0x05 (invalid integrity algorithm)"), true},
		{"invalid confidentiality algo", errString("open-session rejected: status=0x10 (invalid confidentiality algorithm)"), true},
		{"no cipher suite match", errString("open-session rejected: status=0x11 (no cipher suite match with proposed security algorithms)"), true},
		{"insufficient resources", errString("open-session rejected: status=0x01 (insufficient resources for session)"), false},
		{"unauthorized name", errString("open-session rejected: status=0x0d (unauthorized name)"), false},
		{"rakp3 timeout", errString("rakp3: i/o timeout"), false},
		{"nil", nil, false},
	} {
		if got := openSessionAlgoRejected(tc.err); got != tc.want {
			t.Errorf("%s: openSessionAlgoRejected = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// The fallback ladder must not be empty and must not lead with the suite that
// chooseCipherSuite already guessed, or the retry is a no-op.
func TestBlindCipherFallbackIsUsable(t *testing.T) {
	if len(blindCipherFallback) == 0 {
		t.Fatal("blindCipherFallback is empty; a rejected guess has nowhere to fall back to")
	}
	for _, sid := range blindCipherFallback {
		if sid == 17 {
			t.Errorf("suite 17 is the blind default; retrying it wastes a round trip")
		}
		if _, ok := CipherAlgosFor(sid); !ok {
			t.Errorf("fallback suite %d has no algorithm mapping", sid)
		}
	}
}
