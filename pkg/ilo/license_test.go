package ilo

import (
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestFetchLicenseKey(t *testing.T) {
	// iLO serves the license block unauthenticated with a real activation key.
	withKey := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/xmldata" && r.URL.Query().Get("item") == "CpqKey" {
			_, _ = w.Write([]byte(`<PROLIANT><CpqKey><LNAME>iLO Advanced</LNAME><LTYPE>Advanced</LTYPE><KEY>ABCDE-FGHIJ-KLMNO-PQRST-UVWXY</KEY></CpqKey></PROLIANT>`))
			return
		}
		http.NotFound(w, r)
	}))
	defer withKey.Close()

	lk, ok := FetchLicenseKey(hostOf(t, withKey.URL), 2*time.Second)
	if !ok {
		t.Fatal("expected a disclosed license key")
	}
	if lk.Key != "ABCDE-FGHIJ-KLMNO-PQRST-UVWXY" {
		t.Errorf("key = %q", lk.Key)
	}
	if !strings.Contains(lk.Name, "Advanced") {
		t.Errorf("name = %q", lk.Name)
	}

	// An unlicensed iLO returns an empty <KEY> -> not a disclosure.
	empty := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`<PROLIANT><CpqKey><LNAME></LNAME><KEY></KEY></CpqKey></PROLIANT>`))
	}))
	defer empty.Close()
	if _, ok := FetchLicenseKey(hostOf(t, empty.URL), 2*time.Second); ok {
		t.Error("empty <KEY> must not be reported as a disclosure")
	}
}

func hostOf(t *testing.T, srvURL string) string {
	t.Helper()
	hp := strings.TrimPrefix(srvURL, "http://")
	if _, _, err := net.SplitHostPort(hp); err != nil {
		t.Fatalf("split %q: %v", hp, err)
	}
	return hp
}
