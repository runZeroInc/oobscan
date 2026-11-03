package check

import (
	"context"
	"net/http/httptest"
	"testing"

	"github.com/runZeroInc/oobscan/pkg/engine"
	"github.com/runZeroInc/oobscan/pkg/ipmi"
	"github.com/runZeroInc/oobscan/pkg/redfish"
)

// TestSuppliedCredsOrdersCLIThenRecovered pins the candidate order: the operator's
// own pairs are tried first, then the accounts this scan recovered with the
// admin-looking ones ahead of the rest. It also pins what never becomes a web
// credential (unverified cracks, the SMCRAKP forged-HMAC marker, empty pairs).
func TestSuppliedCredsOrdersCLIThenRecovered(t *testing.T) {
	tg := &engine.Target{
		Host:  "192.0.2.21",
		Cred:  engine.Cred{User: "operator", Pass: "opsecret"},
		Creds: []engine.Cred{{User: "second", Pass: "twopass"}},
	}
	tg.SetEvidence("ipmi.auth", &ipmi.AuthReport{Cracked: []ipmi.CrackResult{
		{Username: "guest", Password: "guestpw", Verified: true},
		{Username: "ADMIN", Password: "adminpw", Verified: true},
		{Username: "notlogged", Password: "nope", Verified: false},
		{Username: "ADMIN", Password: "forged", Verified: true, PasswordType: "smcrakp-fixed-key"},
		{Username: "", Password: "anon", Verified: true},
		{Username: "blankpw", Password: "", Verified: true},
	}})

	got := suppliedCreds(tg)
	want := []engine.Cred{
		{User: "operator", Pass: "opsecret"},
		{User: "second", Pass: "twopass"},
		{User: "ADMIN", Pass: "adminpw"},
		{User: "guest", Pass: "guestpw"},
	}
	if len(got) != len(want) {
		t.Fatalf("creds = %+v, want %+v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("cred %d = %+v, want %+v (full list %+v)", i, got[i], want[i], got)
		}
	}
}

// TestRedfishPostAuthEnumUsesRecoveredCredential exercises the credential reuse
// itself: with no operator credential, a password the scan cracked over IPMI has
// to authenticate to Redfish and the record has to name that provenance rather
// than claiming the operator supplied it.
func TestRedfishPostAuthEnumUsesRecoveredCredential(t *testing.T) {
	bmc := &redfishBMC{user: "ADMIN", pass: "s3cret"}
	srv := httptest.NewTLSServer(bmc.handler())
	defer srv.Close()

	tg := mkRedfishTarget(t, srv.URL, "supermicro", true)
	tg.SetEvidence("ipmi.auth", &ipmi.AuthReport{Cracked: []ipmi.CrackResult{
		{Username: "ADMIN", Password: "s3cret", Verified: true, PasswordType: "common"},
	}})

	got := runRedfishPostAuthEnum(context.Background(), tg)
	f := hasFinding(got, "http.redfish.postAuthEnum")
	if f == nil {
		t.Fatalf("recovered credential did not produce a postAuthEnum finding, got %+v", got)
	}
	if u := explainField(*f, "username"); u != "ADMIN" {
		t.Errorf("username = %q, want ADMIN", u)
	}
	if s := explainField(*f, "source"); s != "ipmi.rakpCracked" {
		t.Errorf("source = %q, want ipmi.rakpCracked", s)
	}

	v, ok := tg.Evidenced("redfish.postAuth")
	if !ok {
		t.Fatal("expected redfish.postAuth evidence")
	}
	post, _ := v.(*redfish.PostAuthSnapshot)
	if post == nil {
		t.Fatalf("unexpected redfish.postAuth type: %T", v)
	}
	if post.Source != "ipmi.rakpCracked" || post.User != "ADMIN" {
		t.Errorf("snapshot source/user = %q/%q, want ipmi.rakpCracked/ADMIN", post.Source, post.User)
	}
	if post.Info.FirmwareVersion == "" {
		t.Errorf("snapshot missing inventory: %+v", post.Info)
	}
}

// TestRedfishPostAuthEnumLabelsCLICredential keeps the operator's own credential
// labelled as such once provenance is tracked.
func TestRedfishPostAuthEnumLabelsCLICredential(t *testing.T) {
	bmc := &redfishBMC{user: "root", pass: "0penBmc"}
	srv := httptest.NewTLSServer(bmc.handler())
	defer srv.Close()

	tg := mkRedfishTarget(t, srv.URL, "openbmc", true)
	tg.Cred = engine.Cred{User: "root", Pass: "0penBmc"}

	f := hasFinding(runRedfishPostAuthEnum(context.Background(), tg), "http.redfish.postAuthEnum")
	if f == nil {
		t.Fatal("expected postAuthEnum finding")
	}
	if s := explainField(*f, "source"); s != "cli" {
		t.Errorf("source = %q, want cli", s)
	}
}
