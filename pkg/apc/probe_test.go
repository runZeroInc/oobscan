package apc

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// nmcServer emulates the APC NMC web tier: /home.htm 303-redirects to
// /NMC/<token>/logon.htm; a login POST with the right creds 303-redirects to the
// bare /NMC/<newtoken>/ base, a wrong one to /NMC/<token>/Password. limstat and
// macontrol behaviour are configurable to exercise each confirmation path.
func nmcServer(goodUser, goodPass string, limstatOpen bool, macontrolStatus int) *httptest.Server {
	mux := http.NewServeMux()
	// Fresh unauth session: /home.htm -> /NMC/<tok>/logon.htm (also the protected
	// baseline that MacontrolExempt compares against).
	mux.HandleFunc("/home.htm", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("WebServer", "")
		http.Redirect(w, r, "/NMC/TOK123/logon.htm", http.StatusSeeOther)
	})
	mux.HandleFunc("/NMC/TOK123/Forms/login1", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.FormValue("login_username") == goodUser && r.FormValue("login_password") == goodPass {
			http.Redirect(w, r, "/NMC/NEWTOK9/", http.StatusSeeOther) // authed base
			return
		}
		http.Redirect(w, r, "/NMC/TOK123/Password", http.StatusSeeOther) // failed
	})
	// Authenticated landing page (login proof is scraped from here).
	mux.HandleFunc("/NMC/NEWTOK9/home.htm", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("<html><title>APC</title>Model: AP9631 PF:v6.8.2</html>"))
	})
	mux.HandleFunc("/NMC/NEWTOK9/logout.htm", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/limstat.htm", func(w http.ResponseWriter, r *http.Request) {
		if limstatOpen {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("<html>UPS Load 42% Runtime 30m Battery OK</html>"))
			return
		}
		http.Redirect(w, r, "/NMC/TOK123/logon.htm", http.StatusSeeOther)
	})
	mux.HandleFunc("/macontrol.htm", func(w http.ResponseWriter, r *http.Request) {
		if macontrolStatus == http.StatusSeeOther {
			// Login-gated: redirect to logon.htm (the endpoint is behind the web
			// session gate, i.e. not exempt).
			http.Redirect(w, r, "/NMC/TOK123/logon.htm", http.StatusSeeOther)
			return
		}
		w.WriteHeader(macontrolStatus)
		if macontrolStatus >= 200 && macontrolStatus < 300 {
			_, _ = w.Write([]byte("<html><head><title>MACONTROL</title></head><body>MV=v1.7.0\nPC=192.0.2.10\nDT=07/11/2026\nTM=23:57:39\nSR=49\nSU=61FC032F\nRD=36AF\nCI=0\nCS=71be7a6e4566f9c426f190393b41321b\nMD=5072ffa89bc1b122f271be5c44c66f8b</body></html>"))
		}
	})
	return httptest.NewServer(mux)
}

func TestLogin(t *testing.T) {
	srv := nmcServer("apc", "apc", false, http.StatusForbidden)
	defer srv.Close()
	c := newClient(srv.URL, 3*time.Second)

	ok, proof, err := c.Login(context.Background(), "apc", "apc")
	if err != nil || !ok {
		t.Fatalf("correct creds: ok=%v err=%v, want ok=true", ok, err)
	}
	for _, want := range []string{"authedPath=/NMC/NEWTOK9/home.htm", "status=200", "AP9631"} {
		if !strings.Contains(proof, want) {
			t.Errorf("proof %q missing dynamic marker %q", proof, want)
		}
	}
	bad, _, err := c.Login(context.Background(), "apc", "nope")
	if err != nil {
		t.Fatalf("wrong creds err=%v", err)
	}
	if bad {
		t.Errorf("wrong creds: ok=true, want false")
	}
}

func TestLoginNotNMC(t *testing.T) {
	// A server that never issues an /NMC/<token>/ redirect isn't an NMC login.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	c := newClient(srv.URL, 3*time.Second)
	if ok, _, err := c.Login(context.Background(), "apc", "apc"); ok || err == nil {
		t.Errorf("non-NMC: ok=%v err=%v, want ok=false err!=nil", ok, err)
	}
}

func TestLoginPhantomBase(t *testing.T) {
	// FP guard: a device that mints a fresh /NMC/<token>/ base on the login POST
	// regardless of credentials, but then bounces the authenticated GET back to
	// logon.htm (the credential was not actually accepted), must not be reported as
	// a successful login. The bare-base redirect target alone is not proof.
	mux := http.NewServeMux()
	mux.HandleFunc("/home.htm", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/NMC/TOK123/logon.htm", http.StatusSeeOther)
	})
	mux.HandleFunc("/NMC/TOK123/Forms/login1", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/NMC/PHANTOM1/", http.StatusSeeOther) // bare base for any creds
	})
	mux.HandleFunc("/NMC/PHANTOM1/home.htm", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/NMC/TOK123/logon.htm", http.StatusSeeOther) // session not real
	})
	mux.HandleFunc("/NMC/PHANTOM1/logout.htm", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	c := newClient(srv.URL, 3*time.Second)
	if ok, _, err := c.Login(context.Background(), "apc", "apc"); ok || err != nil {
		t.Errorf("phantom base (authed GET bounces to logon): ok=%v err=%v, want ok=false err=nil", ok, err)
	}
}

func TestLoginAuthedPageReservesLoginForm(t *testing.T) {
	// FP guard variant: the authed GET returns 200 but re-serves the login form
	// (some builds serve logon.htm as 200 instead of redirecting). The login-form
	// markers must veto the success.
	mux := http.NewServeMux()
	mux.HandleFunc("/home.htm", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/NMC/TOK123/logon.htm", http.StatusSeeOther)
	})
	mux.HandleFunc("/NMC/TOK123/Forms/login1", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/NMC/PHANTOM2/", http.StatusSeeOther)
	})
	mux.HandleFunc("/NMC/PHANTOM2/home.htm", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`<html><form><input name="login_username"><input name="login_password"></form></html>`))
	})
	mux.HandleFunc("/NMC/PHANTOM2/logout.htm", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	c := newClient(srv.URL, 3*time.Second)
	if ok, _, err := c.Login(context.Background(), "apc", "apc"); ok || err != nil {
		t.Errorf("authed GET re-serves login form: ok=%v err=%v, want ok=false err=nil", ok, err)
	}
}

func TestDemoLogin(t *testing.T) {
	// A unit that accepts the demo credential (demo/Test-Drive or planted
	// testdrive522.ini) authenticates apc/jmm627.
	srv := nmcServer(DemoUser, DemoPassword, false, http.StatusForbidden)
	defer srv.Close()
	ok, proof, err := newClient(srv.URL, 3*time.Second).DemoLogin(context.Background())
	if err != nil || !ok {
		t.Fatalf("demo unit: ok=%v err=%v, want ok=true", ok, err)
	}
	if proof == "" {
		t.Error("expected a login proof from the authed home page")
	}

	// A hardened production unit (gate rejects jmm627) must not authenticate.
	hardened := nmcServer("apc", "apc", false, http.StatusForbidden)
	defer hardened.Close()
	if ok, _, err := newClient(hardened.URL, 3*time.Second).DemoLogin(context.Background()); ok || err != nil {
		t.Errorf("hardened unit: ok=%v err=%v, want ok=false err=nil", ok, err)
	}
}

func TestMacontrolExempt(t *testing.T) {
	// 200 -> endpoint present and served outside the web-session gate.
	open := nmcServer("apc", "apc", false, http.StatusOK)
	defer open.Close()
	if info, snip, err := newClient(open.URL, 3*time.Second).MacontrolExempt(context.Background()); err != nil || info == nil || snip == "" {
		t.Errorf("200 macontrol: info=%+v snip=%q err=%v, want parsed fields with a body snippet", info, snip, err)
	} else if info.MV != "v1.7.0" || info.PC != "192.0.2.10" || info.CS != "71be7a6e4566f9c426f190393b41321b" {
		t.Errorf("parsed macontrol fields = %+v", info)
	}

	// A 403 denial page does not prove the control endpoint is exposed.
	forbidden := nmcServer("apc", "apc", false, http.StatusForbidden)
	defer forbidden.Close()
	if info, _, err := newClient(forbidden.URL, 3*time.Second).MacontrolExempt(context.Background()); err != nil || info != nil {
		t.Errorf("403 macontrol: info=%+v err=%v, want no finding", info, err)
	}

	// A login redirect (303 -> logon.htm) means the endpoint IS behind the web
	// session gate -> not exempt.
	gated := nmcServer("apc", "apc", false, http.StatusSeeOther)
	defer gated.Close()
	if info, _, err := newClient(gated.URL, 3*time.Second).MacontrolExempt(context.Background()); err != nil || info != nil {
		t.Errorf("login-gated macontrol: info=%+v err=%v, want no finding", info, err)
	}
}

func TestAPCProbeIgnoresGeneric2xxPages(t *testing.T) {
	generic := `<!DOCTYPE html> <html> <body> <input type="hidden" id="http" name="http" value="5000"> <input type="hidden" id="https" name="https" value="443"> </body> </html>`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(generic))
	}))
	defer srv.Close()
	c := newClient(srv.URL, 3*time.Second)

	if ok, _, err := c.LimitedStatusOpen(context.Background()); err != nil || ok {
		t.Errorf("generic /limstat.htm response: ok=%v err=%v, want ok=false err=nil", ok, err)
	}
	if info, _, err := c.MacontrolExempt(context.Background()); err != nil || info != nil {
		t.Errorf("generic /macontrol.htm response: info=%+v err=%v, want no finding", info, err)
	}
}

func TestLimitedStatusOpenRejectsJetKVMFallbackPage(t *testing.T) {
	jetKVM := `<!doctype html>
<html lang="en">
  <head>
    <title>JetKVM</title>
    <link rel="preload" href="/static/CircularXXWeb.woff2" as="font">
    <script type="module" src="/static/rolldown-runtime.js"></script>
    <script type="module" src="/static/LoadingSpinner.js"></script>
    <meta name="description" content="A web-based KVM console for managing remote servers.">
  </head>
  <body><div id="root"></div></body>
</html>`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(jetKVM))
	}))
	defer srv.Close()

	if ok, _, err := newClient(srv.URL, 3*time.Second).LimitedStatusOpen(context.Background()); err != nil || ok {
		t.Errorf("JetKVM fallback page: ok=%v err=%v, want ok=false err=nil", ok, err)
	}
}

func TestLimitedStatusOpen(t *testing.T) {
	open := nmcServer("apc", "apc", true, http.StatusForbidden)
	defer open.Close()
	if ok, snip, err := newClient(open.URL, 3*time.Second).LimitedStatusOpen(context.Background()); err != nil || !ok || snip == "" {
		t.Errorf("enabled limstat: ok=%v snip=%q err=%v, want ok=true, snippet", ok, snip, err)
	}

	closed := nmcServer("apc", "apc", false, http.StatusForbidden)
	defer closed.Close()
	if ok, _, err := newClient(closed.URL, 3*time.Second).LimitedStatusOpen(context.Background()); err != nil || ok {
		t.Errorf("disabled limstat: ok=%v err=%v, want ok=false", ok, err)
	}
}
