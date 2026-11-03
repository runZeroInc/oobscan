package check

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/runZeroInc/oobscan/pkg/engine"
	"github.com/runZeroInc/oobscan/pkg/snmp"
)

func TestUPnPSDK(t *testing.T) {
	cases := []struct{ server, name, ver string }{
		{"Linux/2.6, UPnP/1.0, Portable SDK for UPnP devices/1.6.18", "Portable SDK for UPnP devices", "1.6.18"},
		{"Intel SDK for UPnP devices/1.3.1", "Intel SDK for UPnP devices", "1.3.1"},
		{"lighttpd/1.4.35", "", ""},
	}
	for _, c := range cases {
		n, v := upnpSDK(c.server)
		if n != c.name || v != c.ver {
			t.Errorf("upnpSDK(%q) = %q/%q, want %q/%q", c.server, n, v, c.name, c.ver)
		}
	}
}

func TestVersionLess(t *testing.T) {
	cases := []struct {
		a, b string
		want bool
	}{
		{"1.6.6", "1.6.18", true},
		{"1.6.18", "1.6.18", false},
		{"1.6.19", "1.6.18", false},
		{"1.5.0", "1.6.18", true},
		{"2.0.0", "1.6.18", false},
	}
	for _, c := range cases {
		if got := versionLess(c.a, c.b); got != c.want {
			t.Errorf("versionLess(%q,%q)=%v want %v", c.a, c.b, got, c.want)
		}
	}
}

func TestSMCDeviceDescFields(t *testing.T) {
	body := []byte(`<?xml version="1.0"?>
<root xmlns="urn:schemas-upnp-org:device-1-0">
  <specVersion><major>1</major><minor>0</minor></specVersion>
  <device>
    <deviceType>urn:schemas-upnp-org:device:management:1</deviceType>
    <friendlyName>SMCI_0:25:90:79:3f:d6</friendlyName>
    <manufacturer>SMC Incorporated</manufacturer>
    <manufacturerURL>http://www.supermicro.com</manufacturerURL>
    <modelDescription>IPMI Console</modelDescription>
    <modelName>IPMI Console</modelName>
    <modelNumber>1.0</modelNumber>
    <modelURL>http://www.supermicro.com</modelURL>
    <serialNumber></serialNumber>
    <UDN>uuid:Upnp-IPMI-1_0-1234567890001</UDN>
    <UPC></UPC>
    <presentationURL>/</presentationURL>
  </device>
</root>`)
	fields, ok := smcDeviceDescFields(body)
	if !ok {
		t.Fatal("expected valid Supermicro device descriptor")
	}
	got := fieldValues(fields)
	want := map[string]string{
		"specVersion":      "1.0",
		"deviceType":       "urn:schemas-upnp-org:device:management:1",
		"friendlyName":     "SMCI_0:25:90:79:3f:d6",
		"manufacturer":     "SMC Incorporated",
		"manufacturerURL":  "http://www.supermicro.com",
		"modelDescription": "IPMI Console",
		"modelName":        "IPMI Console",
		"modelNumber":      "1.0",
		"modelURL":         "http://www.supermicro.com",
		"udn":              "uuid:Upnp-IPMI-1_0-1234567890001",
		"presentationURL":  "/",
	}
	for key, value := range want {
		if got[key] != value {
			t.Errorf("%s = %q, want %q", key, got[key], value)
		}
	}
	if _, exists := got["serialNumber"]; exists {
		t.Error("empty serialNumber should be omitted")
	}
	if _, exists := got["upc"]; exists {
		t.Error("empty upc should be omitted")
	}
}

func TestSMCDeviceDescFieldsRejectsNonDescriptorXML(t *testing.T) {
	for _, body := range [][]byte{
		[]byte(`<html><body>not found</body></html>`),
		[]byte(`<root><error>not found</error></root>`),
		[]byte(`<root>`),
	} {
		if fields, ok := smcDeviceDescFields(body); ok {
			t.Errorf("smcDeviceDescFields(%q) = %+v, want rejection", body, fields)
		}
	}
}

func fieldValues(fields engine.Fields) map[string]string {
	values := make(map[string]string, len(fields))
	for _, field := range fields {
		values[field.Key] = field.Val
	}
	return values
}

func TestSNMPPrivateRequiresConfirmedWrite(t *testing.T) {
	original := verifySNMPWrite
	t.Cleanup(func() { verifySNMPWrite = original })
	target := &engine.Target{Host: "192.0.2.1", Timeout: time.Second}
	target.SetEvidence("snmp.private", &snmp.Result{Version: 1, SysDescr: "test agent"})

	verifySNMPWrite = func(string, int, string, int, time.Duration) (*snmp.WriteVerification, error) {
		return nil, context.DeadlineExceeded
	}
	findings := runSNMP(context.Background(), target)
	if len(findings) != 1 || findings[0].Risk != "medium" || explainField(findings[0], "access") != "readOnly" {
		t.Fatalf("unverified private community findings = %+v", findings)
	}

	verifySNMPWrite = func(string, int, string, int, time.Duration) (*snmp.WriteVerification, error) {
		return &snmp.WriteVerification{OID: "1.3.6.1.2.1.1.6.0"}, nil
	}
	findings = runSNMP(context.Background(), target)
	if len(findings) != 1 || findings[0].Risk != "high" || explainField(findings[0], "access") != "readWrite" {
		t.Fatalf("verified private community findings = %+v", findings)
	}
	if proof := explainField(findings[0], "proof"); !strings.Contains(proof, "operation=setSameValue") {
		t.Fatalf("verified write proof = %q", proof)
	}
}

// A v3 credential that authenticates (read) is medium/readOnly until the
// idempotent same-value SET confirms write access, which lifts it to
// high/readWrite -- the same gate the v1/v2c communities use.
func TestSNMPV3RequiresConfirmedWrite(t *testing.T) {
	original := verifySNMPV3Write
	t.Cleanup(func() { verifySNMPV3Write = original })

	mkTarget := func() *engine.Target {
		target := &engine.Target{Host: "192.0.2.1", Timeout: time.Second}
		target.SetEvidence("snmpv3", &snmp.Result{Version: 3, V3Supported: true, EngineID: "deadbeef"})
		return target
	}
	v3Creds := []snmp.V3Cred{{Name: "test", User: "admn", AuthProto: "SHA", AuthPass: "initial1"}}

	// Unwritable: SET fails -> medium/readOnly.
	verifySNMPV3Write = func(string, int, snmp.V3Cred, time.Duration) (*snmp.WriteVerification, error) {
		return nil, context.DeadlineExceeded
	}
	findings := renderV3Hit(t, mkTarget(), v3Creds)
	if findings.Risk != "medium" || explainField(findings, "access") != "readOnly" {
		t.Fatalf("unverified v3 finding = risk=%q access=%q", findings.Risk, explainField(findings, "access"))
	}
	if proof := explainField(findings, "proof"); !strings.Contains(proof, "operation=read") {
		t.Fatalf("unverified v3 proof = %q", proof)
	}

	// Writable: SET confirmed -> high/readWrite.
	verifySNMPV3Write = func(string, int, snmp.V3Cred, time.Duration) (*snmp.WriteVerification, error) {
		return &snmp.WriteVerification{OID: "1.3.6.1.2.1.1.6.0"}, nil
	}
	findings = renderV3Hit(t, mkTarget(), v3Creds)
	if findings.Risk != "high" || explainField(findings, "access") != "readWrite" {
		t.Fatalf("verified v3 finding = risk=%q access=%q", findings.Risk, explainField(findings, "access"))
	}
	if proof := explainField(findings, "proof"); !strings.Contains(proof, "operation=setSameValue") {
		t.Fatalf("verified v3 proof = %q", proof)
	}
}

// renderV3Hit runs runSNMP with the v3 cred sweep stubbed to a single
// always-succeeding credential and returns the v3.defaultCreds finding.
func renderV3Hit(t *testing.T, target *engine.Target, creds []snmp.V3Cred) engine.Finding {
	t.Helper()
	originalTry := tryV3CredsFn
	t.Cleanup(func() { tryV3CredsFn = originalTry })
	tryV3CredsFn = func(_ context.Context, _ string, _ int, _ []snmp.V3Cred, _ time.Duration) *snmpV3Hit {
		return &snmpV3Hit{cred: creds[0], res: &snmp.Result{Version: 3, V3User: creds[0].User, V3Level: "authNoPriv", SysDescr: "test agent"}}
	}
	for _, f := range runSNMP(context.Background(), target) {
		if f.Check == "snmp.v3.defaultCreds" {
			return f
		}
	}
	t.Fatalf("no snmp.v3.defaultCreds finding rendered")
	return engine.Finding{}
}

// TestSNMPV3DefaultCredsHuaweiCVE locks that the CVE-2026-65198 disclosure CVE is
// attached only when the matched profile is one of the two shipped USM keys
// named in that advisory; an unrelated vendor's default v3 credential is a
// different (undisclosed) weakness and must not carry that CVE.
func TestSNMPV3DefaultCredsHuaweiCVE(t *testing.T) {
	originalWrite := verifySNMPV3Write
	t.Cleanup(func() { verifySNMPV3Write = originalWrite })
	verifySNMPV3Write = func(string, int, snmp.V3Cred, time.Duration) (*snmp.WriteVerification, error) {
		return nil, context.DeadlineExceeded
	}
	target := &engine.Target{Host: "192.0.2.1", Timeout: time.Second}
	target.SetEvidence("snmpv3", &snmp.Result{Version: 3, V3Supported: true, EngineID: "deadbeef"})
	huaweiCreds := []snmp.V3Cred{{Name: "huawei-usm-customization", User: "Administrator", AuthProto: "SHA256", PrivProto: "AES"}}
	f := renderV3Hit(t, target, huaweiCreds)
	if len(f.CVE) != 1 || f.CVE[0] != "CVE-2026-65198" {
		t.Errorf("CVE = %v, want [CVE-2026-65198]", f.CVE)
	}

	target2 := &engine.Target{Host: "192.0.2.2", Timeout: time.Second}
	target2.SetEvidence("snmpv3", &snmp.Result{Version: 3, V3Supported: true, EngineID: "deadbeef"})
	otherCreds := []snmp.V3Cred{{Name: "test", User: "admn", AuthProto: "SHA", AuthPass: "initial1"}}
	f2 := renderV3Hit(t, target2, otherCreds)
	if len(f2.CVE) != 0 {
		t.Errorf("CVE = %v, want none for a non-Huawei profile", f2.CVE)
	}
}

func TestSNMPCredentialVendorPreservesProductIdentity(t *testing.T) {
	target := &engine.Target{Identity: &engine.Identity{Vendor: "lantronix"}}
	target.SetEvidence("snmp", &snmp.Result{VendorGuess: "net-snmp"})
	if got := snmpCredentialVendor(target); got != "lantronix" {
		t.Fatalf("snmpCredentialVendor() = %q, want lantronix", got)
	}

	unknown := &engine.Target{Identity: &engine.Identity{Vendor: "unknown-vendor"}}
	unknown.SetEvidence("snmp", &snmp.Result{VendorGuess: "net-snmp"})
	if got := snmpCredentialVendor(unknown); got != "" {
		t.Fatalf("unmatched vendor = %q, want full-list fallback", got)
	}
}
