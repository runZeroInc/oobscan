package check

import (
	"context"
	"testing"
	"time"

	"github.com/runZeroInc/oobscan/pkg/engine"
	"github.com/runZeroInc/oobscan/pkg/idrac"
	"github.com/runZeroInc/oobscan/pkg/tlscert"
)

func TestRunIDRACDefaultCreds_Outcomes(t *testing.T) {
	base := func() *engine.Target {
		return &engine.Target{
			Host:    "192.0.2.20",
			Timeout: 2 * time.Second,
			Identity: &engine.Identity{
				Class:  engine.ClassBMC,
				Vendor: "dell",
			},
		}
	}

	t.Run("default creds still in place", func(t *testing.T) {
		tgt := base()
		tgt.SetEvidence("idrac", &idrac.Info{DefaultCredKnown: true, DefaultCredInPlace: true})
		got := runIDRACDefaultCreds(context.Background(), tgt)
		if len(got) != 1 {
			t.Fatalf("len(got)=%d, want 1", len(got))
		}
		// The passive /data flag is a Dell self-report, not a confirmed login, so it
		// is rated high (critical is reserved for the active-login path).
		if got[0].Check != "http.idrac.defaultCreds" || got[0].Risk != "high" {
			t.Fatalf("finding=%+v, want high http.idrac.defaultCreds", got[0])
		}
		if user := explainField(got[0], "user"); user != "root" {
			t.Fatalf("user=%q, want root", user)
		}
		if pass := explainField(got[0], "pass"); pass != "calvin" {
			t.Fatalf("pass=%q, want calvin", pass)
		}
	})

	// A non-Dell host must not trigger an on-demand iDRAC probe or login.
	t.Run("non-dell host is not sprayed", func(t *testing.T) {
		tgt := base()
		tgt.Identity.Vendor = "hpe"
		got := runIDRACDefaultCreds(context.Background(), tgt)
		if len(got) != 0 {
			t.Fatalf("len(got)=%d, want 0 (root:calvin must not be attempted on a non-Dell host)", len(got))
		}
	})

	t.Run("default creds known rotated", func(t *testing.T) {
		tgt := base()
		tgt.SetEvidence("idrac", &idrac.Info{DefaultCredKnown: true, DefaultCredInPlace: false})
		got := runIDRACDefaultCreds(context.Background(), tgt)
		if len(got) != 1 {
			t.Fatalf("len(got)=%d, want 1", len(got))
		}
		if got[0].Check != "http.idrac.defaultCreds" || got[0].Risk != "none" {
			t.Fatalf("finding=%+v, want none-risk http.idrac.defaultCreds", got[0])
		}
	})

	t.Run("probe inconclusive no finding", func(t *testing.T) {
		tgt := base()
		tgt.DisableLogins = true
		tgt.SetEvidence("idrac", &idrac.Info{DefaultCredKnown: false, DefaultCredInPlace: false})
		got := runIDRACDefaultCreds(context.Background(), tgt)
		if len(got) != 0 {
			t.Fatalf("len(got)=%d, want 0 for inconclusive default-cred probe", len(got))
		}
	})
}

func TestIDRACLoginPorts(t *testing.T) {
	t.Run("defaults when no identity", func(t *testing.T) {
		tgt := &engine.Target{}
		got := idracLoginPorts(tgt)
		want := []int{443, 8443, 4443}
		if len(got) != len(want) {
			t.Fatalf("len(got)=%d want %d (got=%v)", len(got), len(want), got)
		}
		for i := range want {
			if got[i] != want[i] {
				t.Fatalf("got=%v want=%v", got, want)
			}
		}
	})

	t.Run("adds https web.port", func(t *testing.T) {
		tgt := &engine.Target{Identity: &engine.Identity{Attributes: map[string]string{"web.scheme": "https", "web.port": "9443"}}}
		got := idracLoginPorts(tgt)
		if got[len(got)-1] != 9443 {
			t.Fatalf("expected 9443 in %v", got)
		}
	})

	t.Run("ignores http web.port", func(t *testing.T) {
		tgt := &engine.Target{Identity: &engine.Identity{Attributes: map[string]string{"web.scheme": "http", "web.port": "80"}}}
		got := idracLoginPorts(tgt)
		for _, p := range got {
			if p == 80 {
				t.Fatalf("did not expect port 80 in %v", got)
			}
		}
	})
}

func TestRunTLSSharedKeyReportsGenericClientCertRequest(t *testing.T) {
	tgt := &engine.Target{Host: "192.0.2.44"}
	tgt.SetEvidence("tls", &tlscert.CertInfo{SubjectCN: "example", ClientCertRequested: true})

	got := runTLSSharedKey(context.Background(), tgt)
	if len(got) != 1 {
		t.Fatalf("len(got)=%d, want 1", len(got))
	}
	if got[0].Check != "tls.clientCertRequested" || got[0].Risk != "info" {
		t.Fatalf("finding=%+v, want info tls.clientCertRequested", got[0])
	}
	if got[0].Port != 443 || got[0].Transport != "tcp" || got[0].Protocol != "https" {
		t.Fatalf("finding location=%d/%s/%s, want 443/tcp/https", got[0].Port, got[0].Transport, got[0].Protocol)
	}
}
