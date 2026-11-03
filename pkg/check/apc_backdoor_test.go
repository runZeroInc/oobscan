package check

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/runZeroInc/oobscan/pkg/engine"
)

// nmcDemoServer emulates the APC NMC web tier for the demo-backdoor check:
// /home.htm 303-redirects to /NMC/<tok>/logon.htm; a login POST with the demo
// creds (apc/jmm627) 303-redirects to the bare authed base, a wrong one to
// /Password. /macontrol.htm answers with the supplied status so both the exempt
// and gated PCNS-endpoint paths can be exercised.
func nmcDemoServer(t *testing.T, demoAccepted bool, macontrolStatus int) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/home.htm", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/NMC/TOK123/logon.htm", http.StatusSeeOther)
	})
	mux.HandleFunc("/NMC/TOK123/Forms/login1", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if demoAccepted && r.FormValue("login_username") == "apc" && r.FormValue("login_password") == "jmm627" {
			http.Redirect(w, r, "/NMC/NEWTOK9/", http.StatusSeeOther)
			return
		}
		http.Redirect(w, r, "/NMC/TOK123/Password", http.StatusSeeOther)
	})
	mux.HandleFunc("/NMC/NEWTOK9/home.htm", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("<html><title>APC</title>Model: AP9631 PF:v6.8.2</html>"))
	})
	mux.HandleFunc("/NMC/NEWTOK9/logout.htm", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/testdrive522.ini", func(w http.ResponseWriter, r *http.Request) {
		if !demoAccepted {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("[testdrive]\nmarker=enabled\n"))
	})
	mux.HandleFunc("/macontrol.htm", func(w http.ResponseWriter, r *http.Request) {
		if macontrolStatus == http.StatusSeeOther {
			http.Redirect(w, r, "/NMC/TOK123/logon.htm", http.StatusSeeOther) // gated (not exempt)
			return
		}
		w.WriteHeader(macontrolStatus)
		if macontrolStatus >= 200 && macontrolStatus < 300 {
			_, _ = w.Write([]byte("<html><head><title>MACONTROL</title></head><body>MV=v1.7.0\nPC=192.0.2.10\nDT=07/11/2026\nTM=23:57:39\nSR=49\nSU=61FC032F\nRD=36AF\nCI=0\nCS=71be7a6e4566f9c426f190393b41321b\nMD=5072ffa89bc1b122f271be5c44c66f8b</body></html>"))
		}
	})
	mux.HandleFunc("/Forms/macontrol1", func(w http.ResponseWriter, r *http.Request) {
		if macontrolStatus == http.StatusSeeOther {
			http.Redirect(w, r, "/NMC/TOK123/logon.htm", http.StatusSeeOther)
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte("invalid token"))
	})
	return httptest.NewServer(mux)
}

// apcTarget builds a Target pointed at an httptest server with the web.port/
// web.scheme attributes set (HTTP-only, like a real NMC with HTTPS disabled).
func apcTarget(t *testing.T, srvURL, vendor string, credsOnline bool) *engine.Target {
	t.Helper()
	host, portStr, err := net.SplitHostPort(strings.TrimPrefix(srvURL, "http://"))
	if err != nil {
		t.Fatalf("split %q: %v", srvURL, err)
	}
	return &engine.Target{
		Host:          host,
		Timeout:       2 * time.Second,
		DisableLogins: !credsOnline,
		Identity: &engine.Identity{
			Vendor:     vendor,
			Class:      engine.ClassPDU,
			Attributes: map[string]string{"web.port": portStr, "web.scheme": "http"},
		},
	}
}

func TestAPCDemoBackdoor_DisableLoginsAccepted(t *testing.T) {
	// !DisableLogins + demo creds accepted (demo/Test-Drive unit or planted
	// testdrive522.ini) + PCNS endpoint exempt (200) -> critical + info.
	srv := nmcDemoServer(t, true, http.StatusOK)
	defer srv.Close()

	got := runAPCDemoBackdoor(context.Background(), apcTarget(t, srv.URL, "apc", true))
	f := hasFinding(got, "http.apc.demoBackdoor")
	if f == nil {
		t.Fatal("expected apc.demo_backdoor when the jmm627 demo login authenticates")
	}
	if f.Risk != "critical" {
		t.Errorf("risk = %s, want critical", f.Risk)
	}
	p := hasFinding(got, "http.apc.pcnsControl")
	if p == nil || p.Risk != "low" {
		t.Errorf("expected apc.pcns_control low finding, got %+v", p)
	} else {
		want := map[string]string{
			"MV": "v1.7.0", "PC": "192.0.2.10", "DT": "07/11/2026", "TM": "23:57:39",
			"SR": "49", "SU": "61FC032F", "RD": "36AF", "CI": "0",
			"CS": "71be7a6e4566f9c426f190393b41321b", "MD": "5072ffa89bc1b122f271be5c44c66f8b",
		}
		for key, value := range want {
			if got := explainField(*p, key); got != value {
				t.Errorf("MACONTROL field %s = %q, want %q", key, got, value)
			}
		}
	}
}

func TestAPCDemoBackdoor_DisableLoginsRejected(t *testing.T) {
	// !DisableLogins but the gate rejects jmm627 (hardened production unit): no
	// demo_backdoor finding. PCNS endpoint gated (redirect to logon) -> no PCNS
	// finding either.
	srv := nmcDemoServer(t, false, http.StatusSeeOther)
	defer srv.Close()

	got := runAPCDemoBackdoor(context.Background(), apcTarget(t, srv.URL, "apc", true))
	if f := hasFinding(got, "http.apc.demoBackdoor"); f != nil {
		t.Errorf("production unit (gate rejects jmm627) must not report demo_backdoor, got %+v", f)
	}
	if p := hasFinding(got, "http.apc.pcnsControl"); p != nil {
		t.Errorf("gated /macontrol.htm (login redirect) must not report pcns_control, got %+v", p)
	}
}

func TestAPCDemoBackdoor_DetectionOnly(t *testing.T) {
	// DisableLogins: report the jmm627 candidacy as info (never attempted),
	// matching ipkvm.defaultCreds. PCNS endpoint still noted (safe GET).
	srv := nmcDemoServer(t, true, http.StatusOK)
	defer srv.Close()

	got := runAPCDemoBackdoor(context.Background(), apcTarget(t, srv.URL, "schneiderpm", false))
	f := hasFinding(got, "http.apc.demoBackdoor")
	if f == nil {
		t.Fatal("expected an info candidacy finding when DisableLogins is on")
	}
	if f.Risk != "info" {
		t.Errorf("detection-only risk = %s, want info", f.Risk)
	}
	// The candidacy must carry the credential but must not have been attempted:
	// with DisableLogins on we never POST, so this is detection-only regardless of
	// whether the server would have accepted it.
	if userField(f) != "apc" {
		t.Errorf("candidacy user = %q, want apc", userField(f))
	}
}

func TestAPCDemoBackdoor_PreauthEvidenceOverridesWeakVendor(t *testing.T) {
	// The check should not be gated only on identify's vendor: a weak/mistaken
	// identity must not suppress a self-confirmed APC/NMC web flow.
	srv := nmcDemoServer(t, true, http.StatusOK)
	defer srv.Close()
	tgt := apcTarget(t, srv.URL, "cyberpower", true)
	got := runAPCDemoBackdoor(context.Background(), tgt)
	if f := hasFinding(got, "http.apc.demoBackdoor"); f == nil || f.Risk != "critical" {
		t.Fatalf("self-confirmed APC demo login should fire despite weak vendor, got %v", got)
	}
	if f := hasFinding(got, "http.apc.pcnsControl"); f == nil {
		t.Fatalf("self-confirmed APC PCNS endpoint should fire despite weak vendor, got %v", got)
	}
}

func TestAPCChecksIgnoreGeneric2xxPages(t *testing.T) {
	generic := `<!DOCTYPE html> <html> <body> <input type="hidden" id="http" name="http" value="5000"> <input type="hidden" id="https" name="https" value="443"> </body> </html>`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(generic))
	}))
	defer srv.Close()
	tgt := apcTarget(t, srv.URL, "cyberpower", true)

	if f := hasFinding(runAPCDemoBackdoor(context.Background(), tgt), "http.apc.pcnsControl"); f != nil {
		t.Fatalf("generic /macontrol.htm response must not report pcnsControl, got %+v", f)
	}
	if f := hasFinding(apcConfirm(context.Background(), tgt), "http.apc.limitedStatus"); f != nil {
		t.Fatalf("generic /limstat.htm response must not report limitedStatus, got %+v", f)
	}
}

func TestAPCTestDriveMarker_Found(t *testing.T) {
	srv := nmcDemoServer(t, true, http.StatusOK)
	defer srv.Close()

	got := runAPCTestDriveMarker(context.Background(), apcTarget(t, srv.URL, "apc", true))
	f := hasFinding(got, "http.apc.testDriveMarker")
	if f == nil {
		t.Fatalf("expected apc.testDriveMarker finding, got %+v", got)
	}
	if f.Risk != "medium" {
		t.Errorf("risk = %s, want medium", f.Risk)
	}
}

func TestAPCTestDriveMarker_NotFound(t *testing.T) {
	srv := nmcDemoServer(t, false, http.StatusOK)
	defer srv.Close()

	got := runAPCTestDriveMarker(context.Background(), apcTarget(t, srv.URL, "apc", true))
	if f := hasFinding(got, "http.apc.testDriveMarker"); f != nil {
		t.Fatalf("expected no apc.testDriveMarker finding, got %+v", f)
	}
}

// userField returns the "user" field value of a finding, or "".
func userField(f *engine.Finding) string {
	for _, kv := range f.Fields {
		if engine.CanonicalFieldKey(kv.Key) == "username" {
			return kv.Val
		}
	}
	return ""
}
