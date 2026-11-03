package ipmi

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"testing"
)

// TestCrackRAKPRecoversVendorDefault proves the offline crack path recovers a
// vendor default (root:calvin) from a leaked RAKP-2 hash, and - critically -
// that the raw-key HMAC verifier agrees with a wire built the pyghmi way
// (20-byte NUL-padded key). They must match for any sub-64-byte password
// because HMAC zero-pads the key to the block size internally.
func TestCrackRAKPRecoversVendorDefault(t *testing.T) {
	clientSID := uint32(0xa4a3a2a0)
	bmcSID := uint32(0x02000000)
	cRand := bytes.Repeat([]byte{0x11}, 16)
	bmcRand := bytes.Repeat([]byte{0x22}, 16)
	bmcGUID := bytes.Repeat([]byte{0x33}, 16)
	const user, pass = "root", "calvin"

	wire := buildRAKP2Wire(clientSID, bmcSID, cRand, bmcRand, bmcGUID, user, pass)
	res := &RAKPResult{Username: user, AuthAlgo: RAKPHMACSHA1, ClientSID: clientSID, BMCSID: bmcSID, ClientRand: cRand}
	if err := parseRAKP2(wire, res); err != nil {
		t.Fatalf("parseRAKP2: %v", err)
	}

	cr := CrackRAKP(res, CrackOptions{Vendor: "dell"})
	if cr == nil {
		t.Fatal("CrackRAKP did not recover the password")
	}
	if cr.Password != pass {
		t.Errorf("recovered %q, want %q", cr.Password, pass)
	}
	if cr.PasswordType != "default" {
		t.Errorf("password type = %q, want default", cr.PasswordType)
	}
}

// TestCrackRAKPNoHash guards the empty-hash short-circuit.
func TestCrackRAKPNoHash(t *testing.T) {
	if CrackRAKP(&RAKPResult{AuthAlgo: RAKPHMACSHA1}, CrackOptions{}) != nil {
		t.Error("CrackRAKP should return nil with no hash")
	}
}

func TestCrackRAKPSMCRAKPFixedKey(t *testing.T) {
	r := &RAKPResult{
		Username:   "ADMIN",
		AuthAlgo:   RAKPHMACSHA1,
		ClientSID:  0x11223344,
		BMCSID:     0x55667788,
		ClientRand: bytes.Repeat([]byte{0x11}, 16),
		BMCRand:    bytes.Repeat([]byte{0x22}, 16),
		BMCGUID:    bytes.Repeat([]byte{0x33}, 16),
	}
	mac := hmac.New(sha1.New, smcRAKPFixedKey)
	mac.Write(r.Salt())
	r.RAKPHash = mac.Sum(nil)

	cr := CrackRAKP(r, CrackOptions{Vendor: "supermicro"})
	if cr == nil {
		t.Fatal("CrackRAKP returned nil")
	}
	if cr.PasswordType != "smcrakp-fixed-key" {
		t.Fatalf("PasswordType=%q, want smcrakp-fixed-key", cr.PasswordType)
	}
}
