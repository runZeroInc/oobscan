package redfish

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// A representative (synthetic) Intel Server Board BMC 2.94 service root. No real
// host data: the version/build tag/OEM markers are the audited fingerprint only.
const intelBMC294ServiceRoot = `{
  "@odata.id": "/redfish/v1/",
  "Id": "RootService",
  "Name": "Root Service",
  "RedfishVersion": "1.11.0",
  "Vendor": "Intel",
  "Oem": {
    "Intel": {
      "@odata.type": "#Intel.Oem.ServiceRoot",
      "FirmwareVersion": "2.94.195893f7",
      "BuildTag": "v2.94d-rel-qsbr-2025q4-wht-can5",
      "Actions": {
        "#Intel.Oem.UpdateBMC": {"target": "/redfish/v1/UpdateService/Actions/Oem/Intel.Oem.UpdateBMC"},
        "#Intel.Oem.UpdateBIOS": {"target": "/redfish/v1/UpdateService/Actions/Oem/Intel.Oem.UpdateBIOS"},
        "#Intel.Oem.PutFileToImage": {"target": "/redfish/v1/UpdateService/Actions/Oem/Intel.Oem.PutFileToImage"}
      }
    }
  }
}`

// A generic (non-Intel) AMI MegaRAC service root that must not be attributed as
// an Intel BMC 2.94 unit.
const genericAMIServiceRoot = `{
  "@odata.id": "/redfish/v1/",
  "Id": "RootService",
  "Name": "Root Service",
  "RedfishVersion": "1.11.0",
  "Oem": {"Ami": {"@odata.type": "#Ami.Oem"}}
}`

func TestAnalyzeIntelBMC294(t *testing.T) {
	cases := []struct {
		name         string
		body         string
		wantIntel    bool
		wantOEM      bool
		wantBMC294   bool
		wantFW       string
		wantBuildTag string
	}{
		{
			name:         "full 2.94 service root",
			body:         intelBMC294ServiceRoot,
			wantIntel:    true,
			wantOEM:      true,
			wantBMC294:   true,
			wantFW:       "2.94.195893f7",
			wantBuildTag: "v2.94d-rel-qsbr-2025q4-wht-can5",
		},
		{
			name:       "generic AMI is not Intel 2.94",
			body:       genericAMIServiceRoot,
			wantIntel:  false,
			wantOEM:    false,
			wantBMC294: false,
		},
		{
			name:       "Intel OEM key but no 2.94 version -> Intel, not 2.94",
			body:       `{"Oem":{"Intel":{"FirmwareVersion":"2.88.abcdef01"}}}`,
			wantIntel:  true,
			wantOEM:    false,
			wantBMC294: false,
			wantFW:     "2.88.abcdef01",
		},
		{
			name:         "build-tag-only Intel attribution still confirms 2.94",
			body:         `{"Vendor":"Intel","Oem":{"Intel":{"BuildTag":"v2.94d-rel-qsbr-2025q4-wht-can5"}}}`,
			wantIntel:    true,
			wantOEM:      false,
			wantBMC294:   true,
			wantBuildTag: "v2.94d-rel-qsbr-2025q4-wht-can5",
		},
		{
			name:       "version string alone confirms build even without OEM key",
			body:       `{"SomeField":"2.94.195893f7"}`,
			wantIntel:  false,
			wantOEM:    false,
			wantBMC294: true,
			wantFW:     "2.94.195893f7",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var info IntelBMC294Info
			analyzeIntelBMC294([]byte(tc.body), &info)
			if info.IsIntel != tc.wantIntel {
				t.Errorf("IsIntel = %v, want %v", info.IsIntel, tc.wantIntel)
			}
			if info.HasIntelOEM != tc.wantOEM {
				t.Errorf("HasIntelOEM = %v, want %v", info.HasIntelOEM, tc.wantOEM)
			}
			if info.IsBMC294 != tc.wantBMC294 {
				t.Errorf("IsBMC294 = %v, want %v", info.IsBMC294, tc.wantBMC294)
			}
			if tc.wantFW != "" && info.FirmwareVersion != tc.wantFW {
				t.Errorf("FirmwareVersion = %q, want %q", info.FirmwareVersion, tc.wantFW)
			}
			if tc.wantBuildTag != "" && info.BuildTag != tc.wantBuildTag {
				t.Errorf("BuildTag = %q, want %q", info.BuildTag, tc.wantBuildTag)
			}
		})
	}
}

func TestIntelBMC294Advisories(t *testing.T) {
	// A confirmed unit exposes all four advisories, all INFO-severity.
	confirmed := IntelBMC294Info{IsBMC294: true}
	adv := confirmed.Advisories()
	if len(adv) != 4 {
		t.Fatalf("confirmed 2.94 should expose 4 advisories, got %d", len(adv))
	}
	for _, a := range adv {
		if a.Severity != "info" {
			t.Errorf("advisory %s severity = %q, want info", a.ID, a.Severity)
		}
		if a.Location == "" || a.Description == "" {
			t.Errorf("advisory %s missing location/description", a.ID)
		}
	}
	// A non-2.94 host exposes none (never emit the advisory off-version).
	if got := (IntelBMC294Info{IsBMC294: false}).Advisories(); got != nil {
		t.Errorf("non-2.94 host must expose no advisories, got %d", len(got))
	}
}

func TestFetchIntelBMC294(t *testing.T) {
	t.Run("confirmed 2.94 unit", func(t *testing.T) {
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/redfish/v1/" {
				w.Header().Set("Server", "lighttpd/1.4.55")
				w.WriteHeader(200)
				_, _ = w.Write([]byte(intelBMC294ServiceRoot))
				return
			}
			w.WriteHeader(404)
		}))
		defer srv.Close()
		h, p := hostPort(t, srv.URL)

		info := FetchIntelBMC294(h, p, 3*time.Second)
		if !info.Reachable {
			t.Fatal("expected service root reachable")
		}
		if !info.IsIntel || !info.HasIntelOEM || !info.IsBMC294 {
			t.Fatalf("expected confirmed Intel 2.94, got %+v", info)
		}
		if info.FirmwareVersion != "2.94.195893f7" {
			t.Errorf("FirmwareVersion = %q", info.FirmwareVersion)
		}
		if info.ServerHeader != "lighttpd/1.4.55" {
			t.Errorf("ServerHeader = %q", info.ServerHeader)
		}
		if len(info.Advisories()) != 4 {
			t.Errorf("expected 4 version-gated advisories")
		}
	})

	t.Run("generic AMI unit is not flagged", func(t *testing.T) {
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(200)
			_, _ = w.Write([]byte(genericAMIServiceRoot))
		}))
		defer srv.Close()
		h, p := hostPort(t, srv.URL)

		info := FetchIntelBMC294(h, p, 3*time.Second)
		if !info.Reachable {
			t.Fatal("expected reachable")
		}
		if info.IsBMC294 {
			t.Errorf("generic AMI must not be flagged as Intel 2.94: %+v", info)
		}
		if info.Advisories() != nil {
			t.Errorf("generic AMI must expose no advisories")
		}
	})

	t.Run("auth-gated service root is reachable but unread", func(t *testing.T) {
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(401)
		}))
		defer srv.Close()
		h, p := hostPort(t, srv.URL)

		info := FetchIntelBMC294(h, p, 3*time.Second)
		if !info.Reachable {
			t.Error("a 401 service root should still be Reachable")
		}
		if info.IsBMC294 {
			t.Error("must not claim 2.94 from a 401 (no readable body)")
		}
	})
}

func TestExtractJSONStringField(t *testing.T) {
	cases := []struct {
		name string
		in   string
		key  string
		want string
	}{
		{"simple", `{"FirmwareVersion":"2.94.195893f7"}`, "FirmwareVersion", "2.94.195893f7"},
		{"spaced colon", `{"FirmwareVersion" : "x"}`, "FirmwareVersion", "x"},
		{"nested", `{"Oem":{"Intel":{"FirmwareVersion":"nest"}}}`, "FirmwareVersion", "nest"},
		{"absent", `{"Other":"y"}`, "FirmwareVersion", ""},
		{"non-string value", `{"FirmwareVersion":123}`, "FirmwareVersion", ""},
		{"empty value", `{"FirmwareVersion":""}`, "FirmwareVersion", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := extractJSONStringField([]byte(tc.in), tc.key); got != tc.want {
				t.Errorf("extractJSONStringField(%q,%q) = %q, want %q", tc.in, tc.key, got, tc.want)
			}
		})
	}
}

func TestExtractQuotedContaining(t *testing.T) {
	cases := []struct {
		name   string
		in     string
		substr string
		want   string
	}{
		{"build tag", `{"BuildTag":"v2.94d-rel-qsbr-2025q4-wht-can5"}`, "wht-can5", "v2.94d-rel-qsbr-2025q4-wht-can5"},
		{"case-insensitive", `{"t":"HELLO-WHT-CAN5-END"}`, "wht-can5", "HELLO-WHT-CAN5-END"},
		{"absent", `{"t":"nope"}`, "wht-can5", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := extractQuotedContaining([]byte(tc.in), tc.substr); got != tc.want {
				t.Errorf("extractQuotedContaining(%q,%q) = %q, want %q", tc.in, tc.substr, got, tc.want)
			}
		})
	}
}
