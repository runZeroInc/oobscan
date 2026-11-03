package snmp

import (
	"testing"
	"time"

	"github.com/gosnmp/gosnmp"
)

func TestProbeRejectsInvalidPorts(t *testing.T) {
	for _, port := range []int{-1, 65536} {
		if _, err := Probe("192.0.2.1", port, "public", 1, time.Second); err == nil {
			t.Errorf("Probe accepted port %d", port)
		}
		if _, err := ProbeV3("192.0.2.1", port, time.Second); err == nil {
			t.Errorf("ProbeV3 accepted port %d", port)
		}
		if result, ok := TryV3("192.0.2.1", port, V3Cred{}, time.Second); ok || result != nil {
			t.Errorf("TryV3 accepted port %d", port)
		}
		if _, err := VerifyWriteV3("192.0.2.1", port, V3Cred{}, time.Second); err == nil {
			t.Errorf("VerifyWriteV3 accepted port %d", port)
		}
	}
}

func TestV3ClientRejectsBadLocalizedKey(t *testing.T) {
	if _, err := v3Client("192.0.2.1", 161, V3Cred{User: "u", AuthProto: "SHA256", AuthKeyHex: "zz"}, time.Second, 1); err == nil {
		t.Error("v3Client accepted malformed localized auth key hex")
	}
	if _, err := v3Client("192.0.2.1", 161, V3Cred{User: "u", AuthProto: "SHA256", PrivProto: "AES", PrivKeyHex: "zz"}, time.Second, 1); err == nil {
		t.Error("v3Client accepted malformed localized priv key hex")
	}
}

func TestV3SecurityLevel(t *testing.T) {
	cases := []struct {
		name  string
		cred  V3Cred
		flags gosnmp.SnmpV3MsgFlags
		level string
	}{
		{"no-auth", V3Cred{}, gosnmp.NoAuthNoPriv | gosnmp.Reportable, "noAuthNoPriv"},
		{"auth-only", V3Cred{AuthProto: "SHA"}, gosnmp.AuthNoPriv | gosnmp.Reportable, "authNoPriv"},
		{"auth-private", V3Cred{AuthProto: "SHA", PrivProto: "AES"}, gosnmp.AuthPriv | gosnmp.Reportable, "authPriv"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			flags, level := v3SecurityLevel(tc.cred)
			if flags != tc.flags || level != tc.level {
				t.Fatalf("v3SecurityLevel() = %v/%q, want %v/%q", flags, level, tc.flags, tc.level)
			}
		})
	}
}

func TestDefaultV3CredsForVendor(t *testing.T) {
	apc := DefaultV3CredsFor("apc")
	if len(apc) != 2 {
		t.Fatalf("APC profiles = %d, want 2", len(apc))
	}
	for _, cred := range apc {
		if cred.Vendor != "apc" {
			t.Fatalf("APC selection included %+v", cred)
		}
	}
	serverTech := DefaultV3CredsFor("servertech")
	if len(serverTech) != 2 || serverTech[0].AuthPass != "initial1" || serverTech[0].PrivPass != "initial1" {
		t.Fatalf("Server Technology PRO profile = %+v", serverTech)
	}
	if got := DefaultV3CredsFor("unknown-vendor"); len(got) != 0 {
		t.Fatalf("known unmatched vendor profiles = %d, want 0", len(got))
	}
	if got := DefaultV3CredsFor(""); len(got) != len(DefaultV3Creds) {
		t.Fatalf("unknown vendor profiles = %d, want %d", len(got), len(DefaultV3Creds))
	}
}

func TestDefaultV3CredsWithLocalized(t *testing.T) {
	// Huawei ships no passphrase profile, so the passphrase-only selector is empty.
	if got := DefaultV3CredsFor("huawei"); len(got) != 0 {
		t.Fatalf("DefaultV3CredsFor(huawei) = %d, want 0 (no passphrase profile)", len(got))
	}
	// The localized selector adds the raw-localized-key creds. They are appended
	// broadly (not vendor-filtered), so a Huawei host gets exactly the localized
	// creds and nothing else.
	huawei := DefaultV3CredsWithLocalized("huawei")
	if len(huawei) != len(LocalizedV3Creds) {
		t.Fatalf("DefaultV3CredsWithLocalized(huawei) = %d, want %d", len(huawei), len(LocalizedV3Creds))
	}
	for _, c := range huawei {
		if !c.hasRawKey() {
			t.Errorf("Huawei localized cred %q missing raw key", c.Name)
		}
		if c.AuthKeyHex == "" || c.AuthKeyHex != c.PrivKeyHex {
			t.Errorf("Huawei cred %q expected AuthKey==PrivKey (auth==priv)", c.Name)
		}
	}
	// The localized creds are tried regardless of vendor: an APC host gets its
	// two passphrase profiles plus all the localized creds.
	apc := DefaultV3CredsWithLocalized("apc")
	if len(apc) != 2+len(LocalizedV3Creds) {
		t.Fatalf("DefaultV3CredsWithLocalized(apc) = %d, want %d (2 apc + localized)", len(apc), 2+len(LocalizedV3Creds))
	}
	localizedSeen := 0
	for _, c := range apc {
		if c.hasRawKey() {
			localizedSeen++
		}
	}
	if localizedSeen != len(LocalizedV3Creds) {
		t.Fatalf("apc selection carried %d localized creds, want %d", localizedSeen, len(LocalizedV3Creds))
	}
}

func TestWritableSystemPDU(t *testing.T) {
	packet := &gosnmp.SnmpPacket{Variables: []gosnmp.SnmpPDU{
		{Name: "." + oidSysContact, Type: gosnmp.NoSuchObject, Value: nil},
		{Name: oidSysLocation, Type: gosnmp.OctetString, Value: []byte("rack 4")},
	}}
	pdu, ok := writableSystemPDU(packet)
	if !ok || pdu.Name != oidSysLocation || string(pdu.Value.([]byte)) != "rack 4" {
		t.Fatalf("writableSystemPDU() = %+v/%v", pdu, ok)
	}

	packet.Error = gosnmp.ReadOnly
	if _, ok := writableSystemPDU(packet); ok {
		t.Fatal("packet with SNMP error must not provide a writable PDU")
	}
}
