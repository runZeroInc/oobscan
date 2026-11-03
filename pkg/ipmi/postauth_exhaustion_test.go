package ipmi

import (
	"fmt"
	"testing"
)

// The predicate reads the status byte off the same string the handshake produces, so it is
// built here the way rakp.go builds it. A literal in the test would let the two drift.
func openSessionRejection(status byte) error {
	return fmt.Errorf("open-session rejected: status=0x%02x (%s)", status, rakpStatusText(status))
}

// Status 0x01 means the session table is full. Escalating past it costs another slot and
// makes the host less measurable, so it has to be distinguishable from an algorithm,
// credential or role rejection, all of which are worth another flow.
func TestSessionResourceExhaustedStatusCodes(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status byte
		want   bool
	}{
		{"insufficient resources", 0x01, true},
		{"invalid session id", 0x02, false},
		{"invalid auth algo", 0x04, false},
		{"invalid integrity algo", 0x05, false},
		{"unauthorized role", 0x0a, false},
		// 0x0b decodes to a phrase containing "insufficient resources" but refuses the
		// requested role, not a session slot: another flow may still land.
		{"insufficient resources for role", 0x0b, false},
		{"unauthorized name", 0x0d, false},
		{"no cipher suite match", 0x11, false},
	} {
		err := openSessionRejection(tc.status)
		if got := SessionResourceExhausted(nil, err); got != tc.want {
			t.Errorf("%s: SessionResourceExhausted(%v) = %v, want %v", tc.name, err, got, tc.want)
		}
	}
}

// The rejection reaches the caller three ways depending on where it happened, and each has
// to stop the walk. A cipher-suite walk in particular records the rejection per suite and
// returns whatever the last suite failed with.
func TestSessionResourceExhaustedInspectsCollection(t *testing.T) {
	rejection := openSessionRejection(0x01).Error()

	if !SessionResourceExhausted(&PostAuthCollection{Error: "sessionOpen: " + rejection}, nil) {
		t.Error("a rejection recorded on the collection was missed")
	}
	inv := &PostAuthCollection{
		CipherMatrix: []CipherAttempt{
			{Suite: 3, Error: rejection},
			{Suite: 17, Error: "rakp3: i/o timeout"},
		},
		Error: "no cipher suite candidates worked",
	}
	if !SessionResourceExhausted(inv, errString("rakp3: i/o timeout")) {
		t.Error("a rejection recorded on a cipher-suite attempt was missed")
	}
	if !SessionResourceExhausted(nil, errString("rakp4 status=0x01 (insufficient resources for session)")) {
		t.Error("a RAKP4 resource rejection was missed")
	}
}

func TestSessionResourceExhaustedIgnoresUnrelatedFailures(t *testing.T) {
	for _, tc := range []struct {
		name string
		inv  *PostAuthCollection
		err  error
	}{
		{"nothing", nil, nil},
		{"timeout", nil, errString("before mcInfo: context deadline exceeded")},
		{"empty collection", &PostAuthCollection{}, nil},
		{"unrelated status byte", nil, errString("mc info: cc=0x01 len=0")},
		{"partial success", &PostAuthCollection{Completed: []string{"mcInfo"}}, nil},
	} {
		if SessionResourceExhausted(tc.inv, tc.err) {
			t.Errorf("%s: reported session exhaustion", tc.name)
		}
	}
}
