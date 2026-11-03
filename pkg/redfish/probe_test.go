package redfish

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestGuessVendorAMIFromOEMBlock(t *testing.T) {
	// ASRock Rack service root brands top-level fields as ASRock, but carries
	// the AMI key only under Oem.
	sr := &ServiceRoot{Vendor: "ASRock", Product: "ASRockRack", Name: "Root Service"}
	sr.Oem.Ami = map[string]any{"@odata.type": "#AMIServiceRoot.v1_0_0.AMIServiceRoot"}
	if v := guessVendor(sr, "webserver/1.0"); v != "ami" {
		t.Fatalf("Oem.Ami populated -> want vendor ami, got %q", v)
	}
}

func TestGuessVendorAMIFromServiceRootMarker(t *testing.T) {
	sr := &ServiceRoot{Product: "ASRock Rack BMC"}
	if v := guessVendor(sr, ""); v != "ami" {
		t.Fatalf("ASRock marker -> want vendor ami, got %q", v)
	}
	sr2 := &ServiceRoot{Name: "MegaRAC Redfish Service"}
	if v := guessVendor(sr2, ""); v != "ami" {
		t.Fatalf("MegaRAC marker -> want vendor ami, got %q", v)
	}
}

func TestGuessVendorDellStillWorks(t *testing.T) {
	sr := &ServiceRoot{Product: "Integrated Dell Remote Access Controller"}
	if v := guessVendor(sr, ""); v != "dell" {
		t.Fatalf("Dell iDRAC -> want vendor dell, got %q", v)
	}
}

func TestGuessVendorFallsBackToServerHeader(t *testing.T) {
	// Redfish body self-identifies nothing (the 87/100 case). The Server header
	// alone must still resolve the vendor via bmcfp.
	sr := &ServiceRoot{} // empty identity fields
	if v := guessVendor(sr, "Mbedthis-Appweb/2.4.2"); v != "dell" {
		t.Fatalf("bare iDRAC Appweb server header -> want dell, got %q", v)
	}
	if v := guessVendor(sr, "HPE-iLO-Server/1.30"); v != "hpe" {
		t.Fatalf("iLO server header -> want hpe, got %q", v)
	}
	if v := guessVendor(sr, "nginx/1.24.0"); v != "" {
		t.Fatalf("non-BMC server header -> want empty, got %q", v)
	}
}

func TestAMI54085Verdict(t *testing.T) {
	redfishBody := []byte(`{"@odata.type":"#Manager.v1_5_0.Manager","@odata.id":"/redfish/v1/Managers/Self","Id":"Self"}`)
	loginBody := []byte(`<!DOCTYPE html><html><head><title>Login</title></head><body>Please log in</body></html>`)

	cases := []struct {
		name        string
		plainStatus int
		spoofStatus int
		spoofBody   []byte
		want        bool
	}{
		{
			name:        "patched BMC denies both -> no finding",
			plainStatus: 401,
			spoofStatus: 401,
			spoofBody:   nil,
			want:        false,
		},
		{
			name:        "vulnerable: 401 flips to 200 with @odata body -> finding",
			plainStatus: 401,
			spoofStatus: 200,
			spoofBody:   redfishBody,
			want:        true,
		},
		{
			name:        "vulnerable via 403 -> finding",
			plainStatus: 403,
			spoofStatus: 200,
			spoofBody:   redfishBody,
			want:        true,
		},
		{
			name:        "resource served unauth (plain 200) is not this bug",
			plainStatus: 200,
			spoofStatus: 200,
			spoofBody:   redfishBody,
			want:        false,
		},
		{
			name:        "spoofed 200 returns a login page -> no finding",
			plainStatus: 401,
			spoofStatus: 200,
			spoofBody:   loginBody,
			want:        false,
		},
		{
			name:        "spoofed 200 returns non-Redfish junk -> no finding",
			plainStatus: 401,
			spoofStatus: 200,
			spoofBody:   []byte(`{"error":"nope"}`),
			want:        false,
		},
		{
			name:        "spoof still denied -> no finding",
			plainStatus: 401,
			spoofStatus: 403,
			spoofBody:   nil,
			want:        false,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := ami54085Verdict(c.plainStatus, c.spoofStatus, c.spoofBody)
			if got != c.want {
				t.Errorf("ami54085Verdict(%d, %d, %q) = %v, want %v",
					c.plainStatus, c.spoofStatus, c.spoofBody, got, c.want)
			}
		})
	}
}

func TestProbeAMI54085PublishedDifferential(t *testing.T) {
	vuln := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/redfish/v1/Systems" {
			http.NotFound(w, r)
			return
		}
		if r.Header.Get("X-Server-Addr") == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if r.Header.Get("X-Server-Addr") != "169.254.0.17:" || r.Header.Get("X-Forwarded-For") != "" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		_, _ = w.Write([]byte(`{"@odata.type":"#ComputerSystemCollection","Members":[]}`))
	}))
	defer vuln.Close()

	got, plain, spoof := probeAMI54085(vuln.Client(), vuln.URL, 3*time.Second)
	if !got || plain != http.StatusUnauthorized || spoof != http.StatusOK {
		t.Fatalf("published 54085 differential = (%v, %d, %d), want (true, 401, 200)", got, plain, spoof)
	}
}

func TestLooksLikeRedfishAndLogin(t *testing.T) {
	if !looksLikeRedfish([]byte(`{"@odata.type":"#Manager.v1_0_0.Manager"}`)) {
		t.Error("expected @odata.type body to look like Redfish")
	}
	if looksLikeRedfish([]byte(`<html>login</html>`)) {
		t.Error("HTML login page should not look like Redfish")
	}
	if !looksLikeLogin([]byte(`<!DOCTYPE html><html>...`)) {
		t.Error("expected doctype/html to look like login page")
	}
	if looksLikeLogin([]byte(`{"@odata.id":"/redfish/v1/Managers/Self"}`)) {
		t.Error("JSON Redfish body should not look like a login page")
	}
}
