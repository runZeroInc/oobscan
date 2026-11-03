package idrac

import "testing"

func TestParseDefaultCredInPlace(t *testing.T) {
	cases := []struct {
		name        string
		body        string
		wantKnown   bool
		wantInPlace bool
	}{
		{
			name:        "default cred still in place (1)",
			body:        `<?xml version="1.0"?><root><defaultCred_inplace>1</defaultCred_inplace></root>`,
			wantKnown:   true,
			wantInPlace: true,
		},
		{
			name:        "default cred changed (0)",
			body:        `<root><defaultCred_inplace>0</defaultCred_inplace></root>`,
			wantKnown:   true,
			wantInPlace: false,
		},
		{
			name:        "true keyword",
			body:        `<root><defaultCred_inplace>true</defaultCred_inplace></root>`,
			wantKnown:   true,
			wantInPlace: true,
		},
		{
			name:        "tag absent (e.g. iDRAC6 blind to its own state)",
			body:        `<root><something>x</something></root>`,
			wantKnown:   false,
			wantInPlace: false,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			known, inplace := parseDefaultCredInPlace(c.body)
			if known != c.wantKnown {
				t.Errorf("known = %v, want %v", known, c.wantKnown)
			}
			if inplace != c.wantInPlace {
				t.Errorf("inplace = %v, want %v", inplace, c.wantInPlace)
			}
		})
	}
}

func TestParseAIMProp(t *testing.T) {
	body := `<?xml version="1.0"?><aimGetProp><fwVersionFull>2.83.83.83</fwVersionFull><status>ok</status></aimGetProp>`
	if got := parseAIMProp(body, "fwVersionFull"); got != "2.83.83.83" {
		t.Errorf("parseAIMProp fwVersionFull = %q, want %q", got, "2.83.83.83")
	}
	if got := parseAIMProp(body, "hostname"); got != "" {
		t.Errorf("parseAIMProp missing prop = %q, want empty", got)
	}
	// Whitespace is trimmed.
	body2 := `<aimGetProp><fwVersionFull>  3.30.30.30  </fwVersionFull></aimGetProp>`
	if got := parseAIMProp(body2, "fwVersionFull"); got != "3.30.30.30" {
		t.Errorf("parseAIMProp trimmed = %q, want %q", got, "3.30.30.30")
	}
	jsonBody := `{"aimGetProp":{"hostname":"idrac-ABCD123","gui_str_title_bar":"iDRAC Settings","OEMHostName":"node-1","fwVersion":"2.82.82.82","sysDesc":"PowerEdge","status":"ok"}}`
	if got := parseAIMProp(jsonBody, "hostname"); got != "idrac-ABCD123" {
		t.Errorf("parseAIMProp(json hostname) = %q, want %q", got, "idrac-ABCD123")
	}
	if got := parseAIMProp(jsonBody, "fwVersion"); got != "2.82.82.82" {
		t.Errorf("parseAIMProp(json fwVersion) = %q, want %q", got, "2.82.82.82")
	}
}

func TestParseBMCInfo(t *testing.T) {
	body := []byte(`{"Attributes":{"ADEnabled":"Enabled","GUITitleBar":"iDRAC","FwVer":"7.00.00.00","IsOEMBranded":"false","License":"Enterprise","SSOEnabled":"Disabled","ServerGen":"16G","SystemLockdown":"Disabled","SystemModelName":"PowerEdge R760","TFAEnabled":"Disabled","iDRACName":"idrac-r760"}}`)
	bmc, ok := parseBMCInfo(body)
	if !ok {
		t.Fatal("parseBMCInfo returned ok=false")
	}
	if bmc.FwVersion != "7.00.00.00" {
		t.Fatalf("FwVersion=%q, want 7.00.00.00", bmc.FwVersion)
	}
	if bmc.SystemModelName != "PowerEdge R760" {
		t.Fatalf("SystemModelName=%q, want PowerEdge R760", bmc.SystemModelName)
	}
}

func TestParseAboutPage(t *testing.T) {
	body := `<html><script>var fwVer = "1.95";</script><p>Integrated Dell Remote Access Controller 6</p></html>`
	fw, gen, ok := parseAboutPage(body)
	if !ok {
		t.Fatal("parseAboutPage returned ok=false")
	}
	if fw != "1.95" || gen != "6" {
		t.Fatalf("parseAboutPage fw=%q gen=%q, want 1.95/6", fw, gen)
	}
}
