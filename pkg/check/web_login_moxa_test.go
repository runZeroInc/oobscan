package check

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// TestMoxaEncodeKnownVector pins the EncUser/EncPasswd transform to the vector
// verified byte-for-byte from the shipped nport.js/sha256.js: with the nonce
// "1699887766", encodePassword("moxa", SHA256(nonce)) is this exact 64-hex value.
func TestMoxaEncodeKnownVector(t *testing.T) {
	const nonce = "1699887766"
	const want = "2697053d206bc17da0d7ddaf048e3a287daf4f69c400b7d8ead510963569953d"
	if got := moxaEncode("moxa", nonce); got != want {
		t.Fatalf("moxaEncode(moxa, %q) = %s, want %s", nonce, got, want)
	}
	// The blank secret encodes to the raw SHA-256 digest (no XOR applied).
	sum := sha256.Sum256([]byte(nonce))
	if got := moxaEncode("", nonce); got != hex.EncodeToString(sum[:]) {
		t.Errorf("moxaEncode(\"\", nonce) should equal the raw digest hex")
	}
}

// moxaDecode is the independent inverse of moxaEncode used only by the emulator:
// XOR the hex payload against SHA256(nonce) and take the leading non-zero run.
// If the adapter's forward transform were wrong, this would not recover the
// plaintext the emulator accepts.
func moxaDecode(enc, nonce string) string {
	raw, err := hex.DecodeString(enc)
	if err != nil {
		return "\x00invalid"
	}
	sum := sha256.Sum256([]byte(nonce))
	var b []byte
	for i := 0; i < len(raw) && i < 32; i++ {
		c := raw[i] ^ sum[i]
		if c == 0 {
			break
		}
		b = append(b, c)
	}
	return string(b)
}

// moxaLoginPage renders the real NPort 6000 Login.htm shape (login form, hidden
// FakeChallenge nonce, and the identical "<series> Web Console" title). This is
// both the initial login page and the rejected-credential re-render.
func moxaLoginPage(result string) string {
	const nonce = "1699887766"
	return fmt.Sprintf(`<title>NPort 6000 Web Console</title><script>${NPORT.JS}</script>`+
		`<form name=InputPassword method=post action=/ onsubmit="return SetPass(this);">`+
		`<input type=hidden name=EncUser><input type=hidden name=EncPasswd>`+
		`<input type=hidden name=FakeChallenge value=%s>`+
		`<h2><font color=#ff0000>%s</font></h2>`+
		`<input type=image value=Login name=Submit src=~7Elogin.gif></form>`, nonce, result)
}

// moxaFrameset is the authenticated console landing page (index_frameset.htm):
// no cookie, no redirect, HTTP 200 -- a <frameset> whose child frames are the
// authenticated-only console. Note the title matches the login page's title.
const moxaFrameset = `<title>NPort 6000 Web Console</title>` +
	`<frameset rows=57,1* frameborder=NO><frame name=top scrolling=no target=contents src=top.htm noresize>` +
	`<frameset cols=300,*><frame name=contents target=main src=contents.htm>` +
	`<frame name=main src=main.htm marginwidth=0 marginheight=0></frameset></frameset>` +
	`<noframes><body background=bg.gif>frames unsupported</noframes>`

// moxaEmulator serves Login.htm with a fixed FakeChallenge and decodes the
// EncUser/EncPasswd and, on a match, serves the authenticated frameset landing
// page (HTTP 200, no cookie, no redirect) and marks the source-IP session live;
// otherwise it re-renders Login.htm. The frame-source pages (top/contents/main)
// return authenticated console content only once the session is live, and a 307
// bounce to the login page before then -- mirroring the real device.
func moxaEmulator(t *testing.T, wantUser, wantPass string, posts *int32) *httptest.Server {
	t.Helper()
	var authed int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "MoxaHttp/2.2")
		switch r.URL.Path {
		case "/top.htm", "/contents.htm", "/main.htm":
			if atomic.LoadInt32(&authed) == 1 {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`<title>NPort 6000 Web Console</title><body>` +
					`Overview &nbsp; Model NPort 6650 &nbsp; Firmware V3.4.13 &nbsp;` +
					`<a href=SysInfo.htm>System</a><a href=Network.htm>Network</a></body>`))
				return
			}
			w.Header().Set("Location", "/") // unauthenticated: bounce to login
			w.WriteHeader(http.StatusTemporaryRedirect)
			return
		}
		if r.Method == http.MethodGet {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(moxaLoginPage("")))
			return
		}
		if posts != nil {
			atomic.AddInt32(posts, 1) // count credentialed POSTs
		}
		_ = r.ParseForm()
		u := moxaDecode(r.PostForm.Get("EncUser"), r.PostForm.Get("FakeChallenge"))
		p := moxaDecode(r.PostForm.Get("EncPasswd"), r.PostForm.Get("FakeChallenge"))
		if u == wantUser && p == wantPass {
			atomic.StoreInt32(&authed, 1)
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(moxaFrameset)) // success: frameset landing, no cookie/redirect
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(moxaLoginPage("Login Failed !"))) // rejected: re-render login
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestMoxaAdapterLogin_Success(t *testing.T) {
	var posts int32
	srv := moxaEmulator(t, "admin", "moxa", &posts)
	host, port := splitHostPort(t, srv.URL)
	tgt := mkTargetWithIdentity(t, host, port, "moxa", "NPort 6000", map[string]string{"web.port": port, "web.scheme": "http"})

	got := runWebBasicDefaultCreds(context.Background(), tgt)
	f := hasFinding(got, "http.moxa.defaultCreds")
	if f == nil {
		t.Fatalf("expected http.moxa.defaultCreds via moxa adapter, got %+v", got)
	}
	if via := fieldVal(f.Fields, "loginVia"); via != "httpForm" {
		t.Errorf("loginVia = %q, want httpForm", via)
	}
	if u, p := fieldVal(f.Fields, "username"), fieldVal(f.Fields, "password"); u != "admin" || p != "moxa" {
		t.Errorf("recovered %q/%q, want admin/moxa", u, p)
	}
	proof := fieldVal(f.Fields, "proof")
	if !strings.Contains(proof, "frames=") || !strings.Contains(proof, "authedPath=") || !strings.Contains(proof, "marker=") {
		t.Errorf("proof lacks dynamic authed-console evidence: %q", proof)
	}
	if posts > maxWebBasicAttempts {
		t.Errorf("credentialed POSTs = %d, exceeds cap %d", posts, maxWebBasicAttempts)
	}
}

func TestMoxaAdapterLogin_WrongCreds(t *testing.T) {
	// The emulator accepts only a rotated password and returns the challenge form
	// for shipped defaults.
	srv := moxaEmulator(t, "admin", "s3cret-rotated", nil)
	host, port := splitHostPort(t, srv.URL)
	tgt := mkTargetWithIdentity(t, host, port, "moxa", "NPort 6000", map[string]string{"web.port": port, "web.scheme": "http"})

	if got := runWebBasicDefaultCreds(context.Background(), tgt); len(got) != 0 {
		t.Fatalf("expected no finding when defaults are rejected, got %+v", got)
	}
}

// TestMoxaAdapterLogin_RedirectTrap rejects unconditional redirects that never
// produce an authenticated frameset.
func TestMoxaAdapterLogin_RedirectTrap(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "MoxaHttp/2.3") // passes the vendor gate via the server banner
		switch {
		case r.URL.Path == "/moxa/home.htm":
			w.Header().Set("Location", "/moxa/Login.htm") // authed-only page bounces to login
			w.WriteHeader(http.StatusTemporaryRedirect)
		case r.Method == http.MethodGet:
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(moxaLoginPage(""))) // login page carries FakeChallenge
		default: // POST / : unconditional redirect regardless of credential
			w.Header().Set("Location", "/moxa/home.htm")
			w.WriteHeader(http.StatusTemporaryRedirect)
			_, _ = w.Write([]byte(`<a href="/moxa/home.htm">/moxa/home.htm</a>`))
		}
	}))
	t.Cleanup(srv.Close)
	host, port := splitHostPort(t, srv.URL)
	tgt := mkTargetWithIdentity(t, host, port, "moxa", "MiiNePort", map[string]string{"web.port": port, "web.scheme": "http"})

	if got := runWebBasicDefaultCreds(context.Background(), tgt); len(got) != 0 {
		t.Fatalf("unconditional 307->/moxa/home.htm must NOT be reported as a default-cred hit, got %+v", got)
	}
}
