package check

import "testing"

// TestTrippliteLogsXmlExcludesLoginPage locks the false-positive guard: the
// PowerAlert login page is XHTML ("<?xml?>") containing "login" (matches the
// "log" substring), so a build that session-gates /logs/datalog.xml and serves
// the login page there must not be reported as a datalog disclosure.
func TestTrippliteLogsXmlExcludesLoginPage(t *testing.T) {
	var match func(int, string, []byte) bool
	for _, p := range preauthProbes {
		if p.id == "http.tripplite.logsXml" {
			match = p.match
		}
	}
	if match == nil {
		t.Fatal("http.tripplite.logsXml probe not found")
	}
	// Real pre-auth datalog XML -> true positive.
	datalog := []byte(`<?xml version="1.0"?><datalog><record t="1"/><record t="2"/></datalog>`)
	if !match(200, "text/xml", datalog) {
		t.Error("real datalog.xml should match (regressed true positive)")
	}
	// The PowerAlert login form served in place of /logs -> must be excluded.
	loginPage := []byte(`<?xml version="1.0"?><html><body><div id="logincontainer">` +
		`<form action="/pal.htm"><input name="paun"><input name="papwd"></form></div>Login</body></html>`)
	if match(200, "text/html", loginPage) {
		t.Error("PowerAlert login page must not match http.tripplite.logsXml (false positive)")
	}
}

func TestPreauthProbesRegistered(t *testing.T) {
	want := map[string]bool{
		"http.raritan.loginOptions":   false,
		"http.rittal.restMetrics":     false,
		"http.westermo.alarmCgi":      false,
		"http.tripplite.logsXml":      false,
		"http.tinypilot.hostnameLeak": false,
		"http.sierra.getPublic":       false,
	}
	for _, c := range All() {
		if _, ok := want[c.Name]; ok {
			want[c.Name] = true
			if c.Run == nil {
				t.Errorf("%s has nil Run", c.Name)
			}
		}
	}
	for n, seen := range want {
		if !seen {
			t.Errorf("preauth probe %q not registered", n)
		}
	}
	// The probe table and the registered checks must be 1:1.
	if len(preauthProbes) != len(want) {
		t.Errorf("preauthProbes has %d rows, expected %d", len(preauthProbes), len(want))
	}
}
