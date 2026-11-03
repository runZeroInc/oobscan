package redfish

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestOemVendorFromExtensionKey(t *testing.T) {
	cases := []struct {
		body        string
		wantVendor  string
		wantProduct string
	}{
		{`{"Oem":{"Hpe":{"@odata.type":"#HpeiLO.v2"}}}`, "hpe", "iLO"},
		{`{"Oem":{"Dell":{"@odata.type":"#DellServiceRoot"}}}`, "dell", "iDRAC"},
		{`{"Oem":{"Cisco":{}}}`, "cisco", "CIMC"},
		{`{"Oem":{"Fujitsu":{}}}`, "fujitsu", "iRMC"},
		{`{"Oem":{"Quanta":{}}}`, "quanta", "BMC"},
		{`{"Oem":{"Huawei":{}}}`, "huawei", "iBMC"},
		{`{"Oem":{"Unknownvendor":{}}}`, "", ""},
	}
	for _, c := range cases {
		var sr ServiceRoot
		if err := json.Unmarshal([]byte(c.body), &sr); err != nil {
			t.Fatalf("unmarshal %s: %v", c.body, err)
		}
		v, p := sr.OemVendor()
		if v != c.wantVendor || p != c.wantProduct {
			t.Errorf("%s -> vendor=%q product=%q, want vendor=%q product=%q", c.body, v, p, c.wantVendor, c.wantProduct)
		}
	}
}

func TestOemBlockPreservesTypedFields(t *testing.T) {
	var sr ServiceRoot
	if err := json.Unmarshal([]byte(`{"Oem":{"Supermicro":{"BoardId":"X11"},"Dell":{"x":1}}}`), &sr); err != nil {
		t.Fatal(err)
	}
	if sr.Oem.Supermicro == nil || sr.Oem.Dell == nil {
		t.Fatalf("typed Oem sub-blocks not populated: %+v", sr.Oem)
	}
	if _, ok := sr.Oem.Raw["supermicro"]; !ok {
		t.Fatalf("Raw not lower-cased/populated: %+v", sr.Oem.Raw)
	}
}

func TestIsRedfishGate(t *testing.T) {
	cases := []struct {
		name string
		r    *Result
		want bool
	}{
		{"nil", nil, false},
		{"status zero", &Result{Status: 0}, false},
		{"genuine root", &Result{Status: 200, RawRoot: []byte(`{"@odata.id":"/redfish/v1/","Members":[]}`)}, true},
		{"html login 200", &Result{Status: 200, RawRoot: []byte(`<!doctype html><html><body>login</body></html>`)}, false},
		{"5xx", &Result{Status: 503, RawRoot: []byte(`{"@odata.id":"/redfish/v1/"}`)}, false},
		{"auth-required 401 json root", &Result{Status: 401, RawRoot: []byte(`{"@odata.id":"/redfish/v1/","Members":[]}`)}, true},
	}
	for _, c := range cases {
		if got := c.r.IsRedfish(); got != c.want {
			t.Errorf("%s: IsRedfish()=%v want %v", c.name, got, c.want)
		}
	}
}

func TestAccountLockoutThreshold(t *testing.T) {
	newServer := func(body string, code int) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/redfish/v1/AccountService" {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			w.WriteHeader(code)
			_, _ = w.Write([]byte(body))
		}))
	}
	per := 2 * time.Second

	ts := newServer(`{"AccountLockoutThreshold":5}`, 200)
	defer ts.Close()
	if got := AccountLockoutThreshold(ts.Client(), ts.URL, per); got != 5 {
		t.Errorf("threshold 5 -> got %d", got)
	}

	ts0 := newServer(`{"AccountLockoutThreshold":0}`, 200)
	defer ts0.Close()
	if got := AccountLockoutThreshold(ts0.Client(), ts0.URL, per); got != 0 {
		t.Errorf("threshold 0 (never lock) -> got %d, want 0", got)
	}

	tsMissing := newServer(`{"Id":"AccountService"}`, 200)
	defer tsMissing.Close()
	if got := AccountLockoutThreshold(tsMissing.Client(), tsMissing.URL, per); got != 0 {
		t.Errorf("unset threshold -> got %d, want 0", got)
	}

	ts404 := newServer(``, 404)
	defer ts404.Close()
	if got := AccountLockoutThreshold(ts404.Client(), ts404.URL, per); got != 0 {
		t.Errorf("404 AccountService -> got %d, want 0", got)
	}
}
