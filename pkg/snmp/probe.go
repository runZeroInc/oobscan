// Package snmp fingerprints OOB devices over SNMP v1, v2c, and v3: a GET of the
// four system-group OIDs with a community string for v1/v2c, and for v3 USM
// engine-ID discovery (an unauthenticated request elicits a Report PDU disclosing
// the authoritative engine ID) plus optional testing of known default credentials.
// USM crypto is delegated to github.com/gosnmp/gosnmp rather than re-derived.
package snmp

import (
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/gosnmp/gosnmp"
)

// probeRetries is the number of retransmits per SNMP GET. gosnmp counts this on
// top of the first send, so 1 means two datagrams and at most two timeouts.
const probeRetries = 1

// System-group OIDs (string form for gosnmp).
const (
	oidSysDescr    = "1.3.6.1.2.1.1.1.0"
	oidSysObjectID = "1.3.6.1.2.1.1.2.0"
	oidSysContact  = "1.3.6.1.2.1.1.4.0"
	oidSysName     = "1.3.6.1.2.1.1.5.0"
	oidSysLocation = "1.3.6.1.2.1.1.6.0"
)

// VendorByEnterpriseID maps an IANA enterprise number (the arc after
// 1.3.6.1.4.1.) in sysObjectID to a vendor slug.
var VendorByEnterpriseID = map[uint32]string{
	9:     "cisco",
	232:   "hpe",
	311:   "microsoft",
	318:   "apc",
	674:   "dell",
	534:   "eaton",
	2606:  "lantronix",
	2697:  "supermicro-ami",
	6574:  "synology",
	8072:  "net-snmp",
	10876: "supermicro",
	20301: "avocent",
	21317: "raritan",
	41112: "ubiquiti",
	// --- KB gap additions ---
	332:   "digi",
	8691:  "moxa",
	2011:  "huawei",
	37945: "inspur",
	3183:  "inspur",
	1718:  "servertech",
	19046: "lenovo",
	343:   "intel",
}

// Result captures what a probe produced.
type Result struct {
	Host         string
	Port         int
	Community    string
	Version      int // 0=v1, 1=v2c, 3=v3
	SysDescr     string
	SysObjectID  string
	SysName      string
	SysLocation  string
	EnterpriseID uint32
	VendorGuess  string
	// Responded records that the agent answered this community at all, which is
	// the only sound test of whether the community is accepted: a v1/v2c agent
	// stays silent on a wrong one. Some agents restrict individual system-group
	// objects, so an empty SysDescr says nothing about whether we are in.
	Responded bool
	// v3
	V3Supported bool
	EngineID    string // hex authoritative engine ID (USM)
	EngineBoots uint32
	V3User      string // set when a v3 credential authenticated
	V3Level     string // "noAuthNoPriv" | "authNoPriv" | "authPriv"
}

// Probe sends GET(sysDescr, sysObjectID, sysName, sysLocation) over v1 or v2c.
// version: 0=v1, 1=v2c. community defaults to "public".
func Probe(host string, port int, community string, version int, timeout time.Duration) (*Result, error) {
	if port == 0 {
		port = 161
	}
	if port < 1 || port > 65535 {
		return nil, fmt.Errorf("invalid SNMP port %d", port)
	}
	if community == "" {
		community = "public"
	}
	ver := gosnmp.Version2c
	if version == 0 {
		ver = gosnmp.Version1
	}
	g := &gosnmp.GoSNMP{
		Target:    host,
		Port:      uint16(port),
		Community: community,
		Version:   ver,
		Timeout:   timeout,
		// One retransmit. This is a single UDP datagram to a host that may be
		// several thousand miles away, and a dropped reply is indistinguishable
		// from a refused community, so no retry turns loss into a false negative.
		Retries: probeRetries,
		MaxOids: 4,
	}
	if err := g.Connect(); err != nil {
		return nil, err
	}
	defer g.Conn.Close()

	r := &Result{Host: host, Port: port, Community: community, Version: version}
	oids := []string{oidSysDescr, oidSysObjectID, oidSysName, oidSysLocation}
	resp, err := g.Get(oids)
	if err != nil {
		return nil, err
	}
	if resp.Error == gosnmp.NoError {
		r.Responded = true
		assignSystemGroup(r, resp.Variables)
	} else {
		// Under v1 the error status applies to the whole PDU, so one object the
		// agent does not implement (sysLocation on plenty of BMCs) discards the
		// three that it does. Ask again one OID at a time.
		for _, oid := range oids {
			one, err := g.Get([]string{oid})
			if err != nil {
				continue
			}
			if one.Error == gosnmp.NoError {
				r.Responded = true
				assignSystemGroup(r, one.Variables)
			}
		}
	}
	r.VendorGuess = vendorFromOID(r.SysObjectID, &r.EnterpriseID)
	return r, nil
}

// WriteVerification records a successful idempotent SET of a system-group
// object back to the exact value and ASN.1 type returned by the preceding GET.
type WriteVerification struct {
	OID string
}

// VerifyWrite tests whether a v1/v2c community can write. It reads
// sysContact and sysLocation, then SETs one writable OctetString to its current
// value. The value is preserved, but firmware may still log or apply the write.
func VerifyWrite(host string, port int, community string, version int, timeout time.Duration) (*WriteVerification, error) {
	if port == 0 {
		port = 161
	}
	if port < 1 || port > 65535 {
		return nil, fmt.Errorf("invalid SNMP port %d", port)
	}
	ver := gosnmp.Version2c
	if version == 0 {
		ver = gosnmp.Version1
	}
	g := &gosnmp.GoSNMP{
		Target: host, Port: uint16(port), Community: community, Version: ver,
		Timeout: timeout, Retries: 0, MaxOids: 2,
	}
	if err := g.Connect(); err != nil {
		return nil, err
	}
	defer g.Conn.Close()

	return verifySystemWrite(g)
}

// VerifyWriteV3 is VerifyWrite for an authenticated SNMPv3 USM credential: it
// GETs sysContact/sysLocation and SETs one writable OctetString back to the
// exact value the agent returned. No configuration value is changed. The
// credential shape (passphrase-derived or raw localized key) mirrors TryV3.
func VerifyWriteV3(host string, port int, c V3Cred, timeout time.Duration) (*WriteVerification, error) {
	if port == 0 {
		port = 161
	}
	if port < 1 || port > 65535 {
		return nil, fmt.Errorf("invalid SNMP port %d", port)
	}
	g, err := v3Client(host, port, c, timeout, 2)
	if err != nil {
		return nil, err
	}
	defer g.Conn.Close()
	return verifySystemWrite(g)
}

// verifySystemWrite performs the idempotent same-value SET write confirmation
// on a connected client (any SNMP version).
func verifySystemWrite(g *gosnmp.GoSNMP) (*WriteVerification, error) {
	resp, err := g.Get([]string{oidSysContact, oidSysLocation})
	if err != nil {
		return nil, err
	}
	pdu, ok := writableSystemPDU(resp)
	if !ok {
		return nil, fmt.Errorf("no writable system-group OctetString returned")
	}
	setResp, err := g.Set([]gosnmp.SnmpPDU{pdu})
	if err != nil {
		return nil, err
	}
	if setResp == nil || setResp.Error != gosnmp.NoError {
		if setResp == nil {
			return nil, fmt.Errorf("empty SNMP SET response")
		}
		return nil, fmt.Errorf("SNMP SET rejected: %s", setResp.Error)
	}
	return &WriteVerification{OID: strings.TrimPrefix(pdu.Name, ".")}, nil
}

func writableSystemPDU(resp *gosnmp.SnmpPacket) (gosnmp.SnmpPDU, bool) {
	if resp == nil || resp.Error != gosnmp.NoError {
		return gosnmp.SnmpPDU{}, false
	}
	for _, variable := range resp.Variables {
		oid := strings.TrimPrefix(variable.Name, ".")
		if (oid == oidSysContact || oid == oidSysLocation) && variable.Type == gosnmp.OctetString {
			return variable, true
		}
	}
	return gosnmp.SnmpPDU{}, false
}

// ProbeV3 performs USM engine discovery: an unauthenticated (noAuthNoPriv)
// request makes a v3 agent return its authoritative engine ID, which both
// confirms SNMPv3 is enabled and discloses the engine ID / boot counter without
// any credential. Returns nil if the host does not speak v3.
func ProbeV3(host string, port int, timeout time.Duration) (*Result, error) {
	if port == 0 {
		port = 161
	}
	if port < 1 || port > 65535 {
		return nil, fmt.Errorf("invalid SNMP port %d", port)
	}
	g := &gosnmp.GoSNMP{
		Target:        host,
		Port:          uint16(port),
		Version:       gosnmp.Version3,
		Timeout:       timeout,
		Retries:       0,
		MaxOids:       1,
		SecurityModel: gosnmp.UserSecurityModel,
		MsgFlags:      gosnmp.NoAuthNoPriv | gosnmp.Reportable,
		SecurityParameters: &gosnmp.UsmSecurityParameters{
			// gosnmp requires a non-empty username; the agent still returns its
			// authoritative engine ID in the usmStats discovery report regardless of
			// which (unknown) user we name.
			UserName:               "oobscan",
			AuthenticationProtocol: gosnmp.NoAuth,
			PrivacyProtocol:        gosnmp.NoPriv,
		},
	}
	if err := g.Connect(); err != nil {
		return nil, err
	}
	defer g.Conn.Close()

	// The first request drives engine discovery; the data GET usually returns a
	// usmStats Report (which surfaces as an error), but the engine ID is captured
	// on the security parameters regardless - that is the signal we want.
	_, _ = g.Get([]string{oidSysDescr})
	usm, ok := g.SecurityParameters.(*gosnmp.UsmSecurityParameters)
	if !ok || usm.AuthoritativeEngineID == "" {
		return nil, fmt.Errorf("no SNMPv3 engine")
	}
	return &Result{
		Host: host, Port: port, Version: 3, V3Supported: true,
		EngineID:    hex.EncodeToString([]byte(usm.AuthoritativeEngineID)),
		EngineBoots: usm.AuthoritativeEngineBoots,
	}, nil
}

// V3Cred is a candidate SNMPv3 USM credential (a known factory default), in one of
// two shapes:
//   - Passphrase-derived: AuthPass/PrivPass hold the documented factory
//     passphrases, which gosnmp localizes against the target's engine ID.
//   - Raw localized key: AuthKeyHex/PrivKeyHex hold a pre-localized USM key used
//     directly as the HMAC/cipher key, bypassing passphrase localization. This is
//     the only way to exercise a vendor that ships a raw localized key. When a key
//     is supplied, AuthProto/PrivProto still select the algorithm.
type V3Cred struct {
	Name       string // label for reporting, e.g. "apc-nmc"
	Vendor     string // identify vendor slug; empty means cross-vendor
	User       string
	AuthProto  string // "SHA" | "SHA256" | "MD5" | "" (noAuth)
	AuthPass   string
	PrivProto  string // "AES" | "AES256" | "DES" | "" (noPriv)
	PrivPass   string
	AuthKeyHex string // raw localized auth key (hex); when set, used directly instead of localizing AuthPass
	PrivKeyHex string // raw localized priv key (hex); when set, used directly instead of localizing PrivPass
}

// hasRawKey reports whether this credential carries a pre-localized key that
// must be used directly rather than derived from a passphrase.
func (c V3Cred) hasRawKey() bool { return c.AuthKeyHex != "" || c.PrivKeyHex != "" }

// TryV3 attempts an authenticated (authNoPriv / authPriv) SNMPv3 GET with a
// candidate credential. A successful GET of sysDescr proves the credential is
// valid (the USM auth/priv keys localized against the engine and the agent
// accepted them). Returns the populated Result on success.
func TryV3(host string, port int, c V3Cred, timeout time.Duration) (*Result, bool) {
	if result, ok := tryV3Level(host, port, c, timeout); ok {
		return result, true
	}
	// Some agents provision the documented auth and privacy phrases but default
	// the user to authNoPriv. Retry the same authenticated identity without
	// privacy rather than treating that posture as an invalid credential.
	if c.AuthProto != "" && c.PrivProto != "" {
		c.PrivProto, c.PrivPass, c.PrivKeyHex = "", "", ""
		return tryV3Level(host, port, c, timeout)
	}
	return nil, false
}

func tryV3Level(host string, port int, c V3Cred, timeout time.Duration) (*Result, bool) {
	g, err := v3Client(host, port, c, timeout, 1)
	if err != nil {
		return nil, false
	}
	defer g.Conn.Close()
	resp, err := g.Get([]string{oidSysDescr})
	if err != nil || resp == nil || len(resp.Variables) == 0 {
		return nil, false
	}
	// A usmStats report comes back as a variable under 1.3.6.1.6.3.15 (auth
	// failure); a real sysDescr means the credential authenticated.
	v := resp.Variables[0]
	if strings.HasPrefix(strings.TrimPrefix(v.Name, "."), "1.3.6.1.6.3.15") {
		return nil, false
	}
	r := &Result{Host: host, Port: port, Version: 3, V3Supported: true, V3User: c.User, V3Level: v3LevelName(c)}
	assignSystemGroup(r, resp.Variables)
	r.VendorGuess = vendorFromOID(r.SysObjectID, &r.EnterpriseID)
	if usm, ok := g.SecurityParameters.(*gosnmp.UsmSecurityParameters); ok {
		r.EngineID = hex.EncodeToString([]byte(usm.AuthoritativeEngineID))
	}
	return r, true
}

// v3LevelName is the human label for the credential's USM security level.
func v3LevelName(c V3Cred) string {
	_, level := v3SecurityLevel(c)
	return level
}

// v3Client dials a connected SNMPv3 USM client for the credential (used by both
// the authenticated read and the write confirmation). maxOids bounds each
// request. An error is returned for a bad port, malformed raw key hex, or a
// failed connect.
func v3Client(host string, port int, c V3Cred, timeout time.Duration, maxOids int) (*gosnmp.GoSNMP, error) {
	if port == 0 {
		port = 161
	}
	if port < 1 || port > 65535 {
		return nil, fmt.Errorf("invalid SNMP port %d", port)
	}
	sp := &gosnmp.UsmSecurityParameters{
		UserName:                 c.User,
		AuthenticationProtocol:   authProto(c.AuthProto),
		AuthenticationPassphrase: c.AuthPass,
		PrivacyProtocol:          privProto(c.PrivProto),
		PrivacyPassphrase:        c.PrivPass,
	}
	// Raw localized keys: setting SecretKey/PrivacyKey makes gosnmp use them
	// directly as the HMAC/cipher key and skip passphrase key-localization. Bad
	// hex is an error rather than a scan-aborting panic.
	if c.AuthKeyHex != "" {
		key, err := hex.DecodeString(c.AuthKeyHex)
		if err != nil || len(key) == 0 {
			return nil, fmt.Errorf("bad localized auth key hex")
		}
		sp.SecretKey = key
	}
	if c.PrivKeyHex != "" {
		key, err := hex.DecodeString(c.PrivKeyHex)
		if err != nil || len(key) == 0 {
			return nil, fmt.Errorf("bad localized priv key hex")
		}
		sp.PrivacyKey = key
	}
	flags, _ := v3SecurityLevel(c)
	g := &gosnmp.GoSNMP{
		Target:             host,
		Port:               uint16(port),
		Version:            gosnmp.Version3,
		Timeout:            timeout,
		Retries:            0,
		MaxOids:            maxOids,
		SecurityModel:      gosnmp.UserSecurityModel,
		MsgFlags:           flags,
		SecurityParameters: sp,
	}
	if err := g.Connect(); err != nil {
		return nil, err
	}
	return g, nil
}

func v3SecurityLevel(cred V3Cred) (gosnmp.SnmpV3MsgFlags, string) {
	switch {
	case cred.AuthProto == "":
		return gosnmp.NoAuthNoPriv | gosnmp.Reportable, "noAuthNoPriv"
	case cred.PrivProto == "":
		return gosnmp.AuthNoPriv | gosnmp.Reportable, "authNoPriv"
	default:
		return gosnmp.AuthPriv | gosnmp.Reportable, "authPriv"
	}
}

// DefaultV3Creds are documented factory SNMPv3 USM credentials for OOB gear
// (APC/Schneider NMC, Server Technology PDUs) - the ones the vulndb references.
var DefaultV3Creds = []V3Cred{
	{Name: "apc-nmc", Vendor: "apc", User: "APC ASI User", AuthProto: "SHA", AuthPass: "APC ASI auth phrase", PrivProto: "AES", PrivPass: "APC ASI crypt phrase"},
	{Name: "apc-nmc-md5", Vendor: "apc", User: "APC ASI User", AuthProto: "MD5", AuthPass: "APC ASI auth phrase", PrivProto: "DES", PrivPass: "APC ASI crypt phrase"},
	{Name: "servertech", Vendor: "servertech", User: "admn", AuthProto: "SHA", AuthPass: "initial1", PrivProto: "AES", PrivPass: "initial1"},
	{Name: "servertech-swcdu", Vendor: "servertech", User: "admn", AuthProto: "SHA", AuthPass: "initial2", PrivProto: "AES", PrivPass: "initial2"},
	{Name: "eaton-pxg", Vendor: "eaton", User: "admin", AuthProto: "SHA", AuthPass: "adminpass", PrivProto: "AES", PrivPass: "adminpass"},
	{Name: "eaton-pxg-md5", Vendor: "eaton", User: "admin", AuthProto: "MD5", AuthPass: "adminpass", PrivProto: "DES", PrivPass: "adminpass"},
	// --- KB gap additions ---
	{Name: "lantronix-snmp", Vendor: "lantronix", User: "snmpuser", AuthProto: "MD5", AuthPass: "SNMPPASS", PrivProto: "DES", PrivPass: "SNMPPASS"},
	{Name: "lantronix-snmp-rw", Vendor: "lantronix", User: "snmprwuser", AuthProto: "MD5", AuthPass: "SNMPPASS", PrivProto: "DES", PrivPass: "SNMPPASS"},
	{Name: "redlion-guest", Vendor: "redlion", User: "guest", AuthProto: "", AuthPass: "", PrivProto: "", PrivPass: ""}, // rwuser guest noauth (noAuthNoPriv)
}

// LocalizedV3Creds are factory SNMPv3 USM credentials shipped as a raw localized
// key (hex) rather than a passphrase, so DefaultV3Creds cannot model them. They are
// tried on any v3-responsive host via DefaultV3CredsWithLocalized, regardless of
// vendor.
//
// The Huawei openUBMC entries reuse one shared 32-byte SHA-256-localized key for
// both auth and privacy; AES-128 privacy takes its leading 16 bytes. Because the
// shipped key is already localized against the shared authoritative engine, it is
// applied directly with no passphrase derivation.
var LocalizedV3Creds = []V3Cred{
	{Name: "huawei-usm-customization", Vendor: "huawei", User: "Administrator", AuthProto: "SHA256", PrivProto: "AES",
		AuthKeyHex: "7df2f29369e3ac3245b2c9d46b67a0ecd055197e41808a34ef325db2f6422581",
		PrivKeyHex: "7df2f29369e3ac3245b2c9d46b67a0ecd055197e41808a34ef325db2f6422581"},
	{Name: "huawei-usm-community", Vendor: "huawei", User: "Administrator", AuthProto: "SHA256", PrivProto: "AES",
		AuthKeyHex: "7a2f5b86f20233ec7b7bef49643fbf34d86d0cbf6f1f8f5c52d4f30d4536938b",
		PrivKeyHex: "7a2f5b86f20233ec7b7bef49643fbf34d86d0cbf6f1f8f5c52d4f30d4536938b"},
}

// DefaultV3CredsFor returns only the passphrase profiles relevant to a known
// vendor. An unknown vendor keeps the full list so SNMP itself can still
// identify devices that had no useful HTTP/IPMI fingerprint.
func DefaultV3CredsFor(vendor string) []V3Cred {
	return defaultV3CredsFor(vendor, false)
}

// DefaultV3CredsWithLocalized is DefaultV3CredsFor plus the raw-localized-key
// credentials (Huawei et al.). The localized creds are appended in full
// regardless of vendor -- they are tried broadly on any v3-responsive host, so
// no vendor fingerprint match is required to reach them.
func DefaultV3CredsWithLocalized(vendor string) []V3Cred {
	return defaultV3CredsFor(vendor, true)
}

func defaultV3CredsFor(vendor string, includeLocalized bool) []V3Cred {
	pick := func(pool []V3Cred) []V3Cred {
		if vendor == "" {
			return append([]V3Cred(nil), pool...)
		}
		var creds []V3Cred
		for _, cred := range pool {
			if cred.Vendor == "" || strings.EqualFold(cred.Vendor, vendor) {
				creds = append(creds, cred)
			}
		}
		return creds
	}
	creds := pick(DefaultV3Creds)
	if includeLocalized {
		// Localized creds are tried broadly (not vendor-filtered) so any
		// v3-responsive host gets them regardless of its identify vendor.
		creds = append(creds, LocalizedV3Creds...)
	}
	return creds
}

// DefaultCommunity is a documented factory SNMP v1/v2c community string beyond
// the generic public/private the snmp check always tries. Access is "ro" or
// "rw" (the documented capability; callers still confirm writes with an
// idempotent SET before reporting read-write access).
type DefaultCommunity struct {
	Vendor    string
	Community string
	Access    string // "ro" | "rw"
	Note      string
}

// DefaultCommunities are shipped/fleet-shared communities that are not the
// generic public/private, keyed by the identify vendor slug so the check only
// tries a vendor's own strings. A Vendor of "*" is tried on every SNMP-confirmed
// host (for firmware-level defaults like AMI MegaRAC that ship across many OEM
// boards, so no single identify vendor covers them).
var DefaultCommunities = []DefaultCommunity{
	{Vendor: "intel", Community: "intel.public", Access: "ro", Note: "M50CYP BMC 2.94 shipped default, SNMP on by default"},
	{Vendor: "intel", Community: "intel.private", Access: "rw", Note: "M50CYP BMC 2.94 shipped default RW -> full-tree write"},
	{Vendor: "tripplite", Community: "tripplite", Access: "rw", Note: "PowerAlert/SNMPWEBCARD loadDefaults community (RW suspected)"},
	{Vendor: "redlion", Community: "MYCOMMUNITY", Access: "rw", Note: "Sixnet SixTRAK/VersaTRAK factory rwcommunity"},
	{Vendor: "advantech", Community: "private", Access: "rw", Note: "EKI shipped RW community, un-removable via UI"},
	// Observed in oob post-auth scan data (2026-07). AMI MegaRAC ships an "AMI"
	// RO community across ASUS/Tyan/Inspur/Celestica/Nedam/Supermicro boards, so
	// it is tried on any SNMP host; the rest are vendor-name-as-community defaults.
	{Vendor: "*", Community: "AMI", Access: "ro", Note: "AMI MegaRAC default RO community; 35 hosts across many OEM boards"},
	{Vendor: "intel", Community: "INTEL", Access: "ro", Note: "bare Intel default community (distinct from intel.public)"},
	{Vendor: "inspur", Community: "Inspur", Access: "ro", Note: "Inspur BMC vendor-name-as-community default"},
	{Vendor: "dell", Community: "Dell Inc.", Access: "ro", Note: "Dell BMC vendor-name-as-community default"},
	{Vendor: "huawei", Community: "TrapAdmin12#$", Access: "ro", Note: "Huawei iBMC trap community observed in scan data (likely site-set, not confirmed factory)"},
}

func authProto(s string) gosnmp.SnmpV3AuthProtocol {
	switch strings.ToUpper(s) {
	case "MD5":
		return gosnmp.MD5
	case "SHA":
		return gosnmp.SHA
	case "SHA256":
		return gosnmp.SHA256
	default:
		return gosnmp.NoAuth
	}
}

func privProto(s string) gosnmp.SnmpV3PrivProtocol {
	switch strings.ToUpper(s) {
	case "DES":
		return gosnmp.DES
	case "AES":
		return gosnmp.AES
	case "AES192":
		return gosnmp.AES192
	case "AES256":
		return gosnmp.AES256
	default:
		return gosnmp.NoPriv
	}
}

// assignSystemGroup copies the system-group varbinds into the Result.
func assignSystemGroup(r *Result, vars []gosnmp.SnmpPDU) {
	for _, v := range vars {
		name := strings.TrimPrefix(v.Name, ".")
		switch name {
		case oidSysDescr:
			r.SysDescr = pduString(v)
		case oidSysObjectID:
			r.SysObjectID = strings.TrimPrefix(pduString(v), ".")
		case oidSysName:
			r.SysName = pduString(v)
		case oidSysLocation:
			r.SysLocation = pduString(v)
		}
	}
}

// pduString renders an SNMP varbind value as a string (OctetString bytes or an
// ObjectIdentifier), ignoring noSuchObject/noSuchInstance/null.
func pduString(v gosnmp.SnmpPDU) string {
	switch val := v.Value.(type) {
	case string:
		return val
	case []byte:
		return string(val)
	case nil:
		return ""
	default:
		return fmt.Sprintf("%v", val)
	}
}

// vendorFromOID extracts the IANA enterprise number from an enterprise
// sysObjectID (under 1.3.6.1.4.1.) and maps it to a vendor slug.
func vendorFromOID(oid string, outEnt *uint32) string {
	const prefix = "1.3.6.1.4.1."
	if !strings.HasPrefix(oid, prefix) {
		return ""
	}
	tail := oid[len(prefix):]
	if dot := strings.IndexByte(tail, '.'); dot >= 0 {
		tail = tail[:dot]
	}
	var ent uint32
	for _, c := range tail {
		if c < '0' || c > '9' {
			return ""
		}
		ent = ent*10 + uint32(c-'0')
	}
	if outEnt != nil {
		*outEnt = ent
	}
	return VendorByEnterpriseID[ent]
}

// VendorBySysDescr returns a vendor slug when sysDescr (device-reported free
// text) carries a distinctive product string. This is a stronger tell than the
// bare enterprise arc (VendorByEnterpriseID), so callers can attribute it at a
// higher confidence -- used for families whose sysObjectID arc is shared or
// unregistered (e.g. Red Lion / Sixnet industrial RTUs). Returns "" on no match.
func VendorBySysDescr(sysDescr string) string {
	low := strings.ToLower(sysDescr)
	switch {
	case strings.Contains(low, "sixtrak"), strings.Contains(low, "versatrak"),
		strings.Contains(low, "sixnet"), strings.Contains(low, "red lion"),
		strings.Contains(low, "r-trak"):
		return "redlion"
	}
	return ""
}
