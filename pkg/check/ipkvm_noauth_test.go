package check

import "testing"

// Firing on any 2xx with a body is wrong: several of these appliances -- and the
// Lantronix SecureLinx Spider, which serves the same /device/status route -- answer an
// unauthenticated request with 200 and the login page. The body has to look like
// device data.
func TestIPKVMUnauthDataRejectsLoginPages(t *testing.T) {
	cases := []struct {
		name    string
		body    string
		wantOK  bool
		wantWhy string
	}{
		{
			name: "securelinx spider login page (the oob60 false positive)",
			body: `<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" ` +
				`"http://www.w3c.org/TR/1999/REC-html401-19991224/loose.dtd"> <html> <head> ` +
				`<META HTTP-EQUIV="Content-Type" CONTENT="text/html; charset=iso-8859-1">`,
			wantOK: false,
		},
		{
			name:   "bare html landing page",
			body:   `<html><head><title>Login</title></head><body><form action="/login">`,
			wantOK: false,
		},
		{
			name:   "xml error document served as 200",
			body:   `<?xml version="1.0"?><error>unauthorized</error>`,
			wantOK: false,
		},
		{
			name:   "plain text with no appliance tell",
			body:   `Not Found`,
			wantOK: false,
		},
		{
			name:    "pikvm kvmd json",
			body:    `{"ok":true,"result":{"streamer":{"encoder":{"type":"cpu"}}}}`,
			wantOK:  true,
			wantWhy: "json body",
		},
		{
			name:    "jetkvm status json",
			body:    `{"nopassword":true,"version":"0.3.8"}`,
			wantOK:  true,
			wantWhy: "json body",
		},
		{
			name:    "json array payload",
			body:    `[{"id":0,"state":"on"}]`,
			wantOK:  true,
			wantWhy: "json body",
		},
		{
			name:    "device/ui-config.js assignment",
			body:    `var uiConfig = {"hostname":"kvm","vnc_enabled":true};`,
			wantOK:  true,
			wantWhy: "js config object",
		},
		{
			name:    "kvmd html app shell is real device data",
			body:    `<!DOCTYPE html><html><head><title>PiKVM</title><script src="/share/js/kvmd.js">`,
			wantOK:  true,
			wantWhy: "html naming kvmd",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			why, ok := ipkvmUnauthData(tc.body)
			if ok != tc.wantOK {
				t.Fatalf("ipkvmUnauthData(%.60q) ok = %v, want %v (why=%q)", tc.body, ok, tc.wantOK, why)
			}
			if tc.wantOK && why != tc.wantWhy {
				t.Errorf("why = %q, want %q", why, tc.wantWhy)
			}
			if !ok && why != "" {
				t.Errorf("rejected body returned a non-empty reason %q", why)
			}
		})
	}
}

// An empty or whitespace-only body is never evidence.
func TestIPKVMUnauthDataRejectsEmptyBody(t *testing.T) {
	for _, body := range []string{"", "   ", "\n\t "} {
		if why, ok := ipkvmUnauthData(body); ok {
			t.Errorf("ipkvmUnauthData(%q) = %q, true; want false", body, why)
		}
	}
}
