package snmp

import (
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/gosnmp/gosnmp"
)

const probeRetries = 1

const (
	oidSysDescr    = "1.3.6.1.2.1.1.1.0"
	oidSysObjectID = "1.3.6.1.2.1.1.2.0"
	oidSysContact  = "1.3.6.1.2.1.1.4.0"
	oidSysName     = "1.3.6.1.2.1.1.5.0"
	oidSysLocation = "1.3.6.1.2.1.1.6.0"
)

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

	332:   "digi",
	8691:  "moxa",
	2011:  "huawei",
	37945: "inspur",
	3183:  "inspur",
	1718:  "servertech",
	19046: "lenovo",
	343:   "intel",
}

type Result struct {
	Host         string
	Port         int
	Community    string
	Version      int
	SysDescr     string
	SysObjectID  string
	SysName      string
	SysLocation  string
	EnterpriseID uint32
	VendorGuess  string

	Responded bool

	V3Supported bool
	EngineID    string
	EngineBoots uint32
	V3User      string
	V3Level     string
}

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

type WriteVerification struct {
	OID string
}

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

			UserName:               "oobscan",
			AuthenticationProtocol: gosnmp.NoAuth,
			PrivacyProtocol:        gosnmp.NoPriv,
		},
	}
	if err := g.Connect(); err != nil {
		return nil, err
	}
	defer g.Conn.Close()

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

type V3Cred struct {
	Name       string
	Vendor     string
	User       string
	AuthProto  string
	AuthPass   string
	PrivProto  string
	PrivPass   string
	AuthKeyHex string
	PrivKeyHex string
}

func (c V3Cred) hasRawKey() bool { return c.AuthKeyHex != "" || c.PrivKeyHex != "" }

func TryV3(host string, port int, c V3Cred, timeout time.Duration) (*Result, bool) {
	if result, ok := tryV3Level(host, port, c, timeout); ok {
		return result, true
	}

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

func v3LevelName(c V3Cred) string {
	_, level := v3SecurityLevel(c)
	return level
}

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

var DefaultV3Creds = []V3Cred{
	{Name: "apc-nmc", Vendor: "apc", User: "APC ASI User", AuthProto: "SHA", AuthPass: "APC ASI auth phrase", PrivProto: "AES", PrivPass: "APC ASI crypt phrase"},
	{Name: "apc-nmc-md5", Vendor: "apc", User: "APC ASI User", AuthProto: "MD5", AuthPass: "APC ASI auth phrase", PrivProto: "DES", PrivPass: "APC ASI crypt phrase"},
	{Name: "servertech", Vendor: "servertech", User: "admn", AuthProto: "SHA", AuthPass: "initial1", PrivProto: "AES", PrivPass: "initial1"},
	{Name: "servertech-swcdu", Vendor: "servertech", User: "admn", AuthProto: "SHA", AuthPass: "initial2", PrivProto: "AES", PrivPass: "initial2"},
	{Name: "eaton-pxg", Vendor: "eaton", User: "admin", AuthProto: "SHA", AuthPass: "adminpass", PrivProto: "AES", PrivPass: "adminpass"},
	{Name: "eaton-pxg-md5", Vendor: "eaton", User: "admin", AuthProto: "MD5", AuthPass: "adminpass", PrivProto: "DES", PrivPass: "adminpass"},

	{Name: "lantronix-snmp", Vendor: "lantronix", User: "snmpuser", AuthProto: "MD5", AuthPass: "SNMPPASS", PrivProto: "DES", PrivPass: "SNMPPASS"},
	{Name: "lantronix-snmp-rw", Vendor: "lantronix", User: "snmprwuser", AuthProto: "MD5", AuthPass: "SNMPPASS", PrivProto: "DES", PrivPass: "SNMPPASS"},
	{Name: "redlion-guest", Vendor: "redlion", User: "guest", AuthProto: "", AuthPass: "", PrivProto: "", PrivPass: ""},
}

var LocalizedV3Creds = []V3Cred{
	{Name: "huawei-usm-customization", Vendor: "huawei", User: "Administrator", AuthProto: "SHA256", PrivProto: "AES",
		AuthKeyHex: "7df2f29369e3ac3245b2c9d46b67a0ecd055197e41808a34ef325db2f6422581",
		PrivKeyHex: "7df2f29369e3ac3245b2c9d46b67a0ecd055197e41808a34ef325db2f6422581"},
	{Name: "huawei-usm-community", Vendor: "huawei", User: "Administrator", AuthProto: "SHA256", PrivProto: "AES",
		AuthKeyHex: "7a2f5b86f20233ec7b7bef49643fbf34d86d0cbf6f1f8f5c52d4f30d4536938b",
		PrivKeyHex: "7a2f5b86f20233ec7b7bef49643fbf34d86d0cbf6f1f8f5c52d4f30d4536938b"},
}

func DefaultV3CredsFor(vendor string) []V3Cred {
	return defaultV3CredsFor(vendor, false)
}

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

		creds = append(creds, LocalizedV3Creds...)
	}
	return creds
}

type DefaultCommunity struct {
	Vendor    string
	Community string
	Access    string
	Note      string
}

var DefaultCommunities = []DefaultCommunity{
	{Vendor: "intel", Community: "intel.public", Access: "ro", Note: "M50CYP BMC 2.94 shipped default, SNMP on by default"},
	{Vendor: "intel", Community: "intel.private", Access: "rw", Note: "M50CYP BMC 2.94 shipped default RW -> full-tree write"},
	{Vendor: "tripplite", Community: "tripplite", Access: "rw", Note: "PowerAlert/SNMPWEBCARD loadDefaults community (RW suspected)"},
	{Vendor: "redlion", Community: "MYCOMMUNITY", Access: "rw", Note: "Sixnet SixTRAK/VersaTRAK factory rwcommunity"},
	{Vendor: "advantech", Community: "private", Access: "rw", Note: "EKI shipped RW community, un-removable via UI"},

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
