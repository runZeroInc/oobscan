package httpscan

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"
	"time"
)

func tsHostPort(t *testing.T, ts *httptest.Server) (string, int) {
	t.Helper()
	u, err := url.Parse(ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	p, _ := strconv.Atoi(u.Port())
	return u.Hostname(), p
}

func TestCheckSMCConfigTftpd(t *testing.T) {
	// Leaky: /cgi/config_tftpd.cgi returns raw U-Boot env (fw_getenv dump).
	leak := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/cgi/config_tftpd.cgi" {
			_, _ = io.WriteString(w, "baudrate=115200\nethaddr=0c:c4:7a:aa:bb:cc\nbootargs=console=ttyS1,115200\nipaddr=10.0.0.1\n")
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer leak.Close()
	h, p := tsHostPort(t, leak)
	res, err := CheckSMCConfigTftpd(h, p, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Leaked {
		t.Fatalf("expected pre-auth env leak, got %+v", res)
	}
	if len(res.Matched) < 2 {
		t.Errorf("expected >=2 U-Boot signatures, got %v", res.Matched)
	}

	// Not a leak: a login redirect page (patched / auth-gated firmware).
	login := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `<html><head><meta http-equiv="refresh" content="0; url=/#login"></head></html>`)
	}))
	defer login.Close()
	h2, p2 := tsHostPort(t, login)
	res2, _ := CheckSMCConfigTftpd(h2, p2, 3*time.Second)
	if res2.Leaked {
		t.Errorf("login redirect must not be reported as a leak: %+v", res2)
	}
}

func TestCheckFujitsuSCCI(t *testing.T) {
	// Leaky: POST /nwsi/ returns SCCI identity XML with no auth.
	leak := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == "/nwsi/" {
			_, _ = io.WriteString(w, `<?xml version="1.0"?><SCCI><System><SystemName>PRIMERGY RX2540</SystemName><SerialNumber>YLVK123456</SerialNumber></System></SCCI>`)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer leak.Close()
	h, p := tsHostPort(t, leak)
	res, err := CheckFujitsuSCCI(h, p, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Leaked {
		t.Fatalf("expected unauth identity leak, got %+v", res)
	}

	// Not a leak: 401 (auth required).
	deny := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer deny.Close()
	h2, p2 := tsHostPort(t, deny)
	res2, _ := CheckFujitsuSCCI(h2, p2, 3*time.Second)
	if res2.Leaked {
		t.Errorf("401 must not be reported as a leak: %+v", res2)
	}
}
