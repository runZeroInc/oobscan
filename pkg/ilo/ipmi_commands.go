package ilo

const (
	IPMIPort uint16 = 623

	IPMIAltPort uint16 = 49623

	VirtualMediaPort uint16 = 17988

	RemoteConsolePort uint16 = 17990
)

var IPMIScanPorts = []uint16{IPMIPort, IPMIAltPort}

type NetFnClass uint8

const (
	NetFnClassStandard NetFnClass = iota
	NetFnClassDCMI
	NetFnClassHPOEM
)

type NetFnInfo struct {
	NetFn byte

	Name string

	Class NetFnClass

	OEMBucket string
}

var NetFns = []NetFnInfo{
	{NetFn: 0x00, Name: "chassis", Class: NetFnClassStandard},
	{NetFn: 0x02, Name: "bridge", Class: NetFnClassStandard},
	{NetFn: 0x04, Name: "sensor/event", Class: NetFnClassStandard},
	{NetFn: 0x06, Name: "app", Class: NetFnClassStandard},
	{NetFn: 0x08, Name: "fw", Class: NetFnClassStandard},
	{NetFn: 0x0A, Name: "storage", Class: NetFnClassStandard},
	{NetFn: 0x0C, Name: "trans", Class: NetFnClassStandard},
	{NetFn: 0x2C, Name: "dcmi", Class: NetFnClassDCMI},
	{NetFn: 0x30, Name: "oem_030", Class: NetFnClassHPOEM, OEMBucket: "src\\bmc_oem.c"},
	{NetFn: 0x32, Name: "oem_032", Class: NetFnClassHPOEM, OEMBucket: "src\\bmc_oem.c"},
	{NetFn: 0x34, Name: "oem_034", Class: NetFnClassHPOEM, OEMBucket: "src\\bmc_oem2.c"},
	{NetFn: 0x36, Name: "oem_036", Class: NetFnClassHPOEM, OEMBucket: "src\\bmc_oem3.c"},
}

type CmdAccess uint8

const (
	AccessUnknown CmdAccess = iota
	AccessCallback
	AccessUser
	AccessOperator
	AccessAdministrator
	AccessPreAuth
)

type CmdSideEffect uint8

const (
	SideEffectRead CmdSideEffect = iota
	SideEffectWrite
	SideEffectReset
	SideEffectSession
	SideEffectDangerous
)

type Command struct {
	NetFn byte

	Cmd byte

	Name string

	Spec string

	Access CmdAccess

	Side CmdSideEffect

	Preauth bool

	Notes string
}

var StdCommands = []Command{

	{NetFn: 0x00, Cmd: 0x00, Name: "get capabilitieS", Spec: "IPMI-2.0", Access: AccessUser, Side: SideEffectRead, Notes: "lowercase 'S' preserved from firmware"},
	{NetFn: 0x00, Cmd: 0x01, Name: "get status", Spec: "IPMI-2.0", Access: AccessUser, Side: SideEffectRead},
	{NetFn: 0x00, Cmd: 0x02, Name: "control", Spec: "IPMI-2.0", Access: AccessOperator, Side: SideEffectDangerous, Notes: "Chassis power on/off/cycle"},
	{NetFn: 0x00, Cmd: 0x04, Name: "identify", Spec: "IPMI-2.0", Access: AccessOperator, Side: SideEffectWrite, Notes: "Chassis Identify LED"},
	{NetFn: 0x00, Cmd: 0x05, Name: "set front panel enables", Spec: "IPMI-2.0", Access: AccessAdministrator, Side: SideEffectWrite},
	{NetFn: 0x00, Cmd: 0x06, Name: "set power restore policy", Spec: "IPMI-2.0", Access: AccessOperator, Side: SideEffectWrite},
	{NetFn: 0x00, Cmd: 0x0B, Name: "set power cycle interval", Spec: "IPMI-2.0", Access: AccessOperator, Side: SideEffectWrite},
	{NetFn: 0x00, Cmd: 0x07, Name: "get system restart cause", Spec: "IPMI-2.0", Access: AccessUser, Side: SideEffectRead},
	{NetFn: 0x00, Cmd: 0x08, Name: "set system boot options", Spec: "IPMI-2.0", Access: AccessOperator, Side: SideEffectWrite},
	{NetFn: 0x00, Cmd: 0x09, Name: "get system boot options", Spec: "IPMI-2.0", Access: AccessUser, Side: SideEffectRead},
	{NetFn: 0x00, Cmd: 0x0F, Name: "get poh counter", Spec: "IPMI-2.0", Access: AccessUser, Side: SideEffectRead},

	{NetFn: 0x04, Cmd: 0x00, Name: "set event receiver", Spec: "IPMI-2.0", Access: AccessAdministrator, Side: SideEffectWrite},
	{NetFn: 0x04, Cmd: 0x01, Name: "get event receiver", Spec: "IPMI-2.0", Access: AccessUser, Side: SideEffectRead},
	{NetFn: 0x04, Cmd: 0x02, Name: "event message", Spec: "IPMI-2.0", Access: AccessAdministrator, Side: SideEffectWrite},
	{NetFn: 0x04, Cmd: 0x10, Name: "get pef capabilities", Spec: "IPMI-2.0", Access: AccessUser, Side: SideEffectRead},
	{NetFn: 0x04, Cmd: 0x11, Name: "arm pef postpone timer", Spec: "IPMI-2.0", Access: AccessAdministrator, Side: SideEffectWrite},
	{NetFn: 0x04, Cmd: 0x12, Name: "set pef config params", Spec: "IPMI-2.0", Access: AccessAdministrator, Side: SideEffectWrite},
	{NetFn: 0x04, Cmd: 0x13, Name: "get pef config params", Spec: "IPMI-2.0", Access: AccessUser, Side: SideEffectRead},
	{NetFn: 0x04, Cmd: 0x14, Name: "set last processed", Spec: "IPMI-2.0", Access: AccessAdministrator, Side: SideEffectWrite},
	{NetFn: 0x04, Cmd: 0x15, Name: "get last processed", Spec: "IPMI-2.0", Access: AccessUser, Side: SideEffectRead},
	{NetFn: 0x04, Cmd: 0x16, Name: "alert immediate", Spec: "IPMI-2.0", Access: AccessOperator, Side: SideEffectWrite},
	{NetFn: 0x04, Cmd: 0x17, Name: "pet acknowledge", Spec: "IPMI-2.0", Access: AccessOperator, Side: SideEffectWrite},
	{NetFn: 0x04, Cmd: 0x26, Name: "set sensor threshold", Spec: "IPMI-2.0", Access: AccessAdministrator, Side: SideEffectWrite},
	{NetFn: 0x04, Cmd: 0x27, Name: "get sensor threshold", Spec: "IPMI-2.0", Access: AccessUser, Side: SideEffectRead},
	{NetFn: 0x04, Cmd: 0x28, Name: "set sensor event enable", Spec: "IPMI-2.0", Access: AccessAdministrator, Side: SideEffectWrite},
	{NetFn: 0x04, Cmd: 0x29, Name: "get sensor event enable", Spec: "IPMI-2.0", Access: AccessUser, Side: SideEffectRead},
	{NetFn: 0x04, Cmd: 0x2D, Name: "get reading", Spec: "IPMI-2.0", Access: AccessUser, Side: SideEffectRead, Notes: "Get Sensor Reading"},

	{NetFn: 0x06, Cmd: 0x01, Name: "global get device ID", Spec: "IPMI-2.0", Access: AccessPreAuth, Side: SideEffectRead, Preauth: true, Notes: "Fingerprint hook -- iLO returns Mfr ID 11 (0x00000B)"},
	{NetFn: 0x06, Cmd: 0x02, Name: "global cold reset", Spec: "IPMI-2.0", Access: AccessAdministrator, Side: SideEffectReset},
	{NetFn: 0x06, Cmd: 0x03, Name: "global warm reset", Spec: "IPMI-2.0", Access: AccessAdministrator, Side: SideEffectReset},
	{NetFn: 0x06, Cmd: 0x04, Name: "global get self test results", Spec: "IPMI-2.0", Access: AccessUser, Side: SideEffectRead},
	{NetFn: 0x06, Cmd: 0x06, Name: "global get acpi power state", Spec: "IPMI-2.0", Access: AccessUser, Side: SideEffectRead},
	{NetFn: 0x06, Cmd: 0x08, Name: "global get device guid", Spec: "IPMI-2.0", Access: AccessPreAuth, Side: SideEffectRead, Preauth: true},
	{NetFn: 0x06, Cmd: 0x22, Name: "reset watchdog timer", Spec: "IPMI-2.0", Access: AccessOperator, Side: SideEffectWrite},
	{NetFn: 0x06, Cmd: 0x24, Name: "set watchdog timer", Spec: "IPMI-2.0", Access: AccessOperator, Side: SideEffectWrite},
	{NetFn: 0x06, Cmd: 0x25, Name: "get watchdog timer", Spec: "IPMI-2.0", Access: AccessUser, Side: SideEffectRead},
	{NetFn: 0x06, Cmd: 0x2E, Name: "set bmc global enables", Spec: "IPMI-2.0", Access: AccessAdministrator, Side: SideEffectWrite},
	{NetFn: 0x06, Cmd: 0x2F, Name: "get bmc global enables", Spec: "IPMI-2.0", Access: AccessUser, Side: SideEffectRead},
	{NetFn: 0x06, Cmd: 0x30, Name: "clear message flags", Spec: "IPMI-2.0", Access: AccessUser, Side: SideEffectWrite},
	{NetFn: 0x06, Cmd: 0x31, Name: "get message flags", Spec: "IPMI-2.0", Access: AccessUser, Side: SideEffectRead},
	{NetFn: 0x06, Cmd: 0x32, Name: "enable msg chan rcv", Spec: "IPMI-2.0", Access: AccessAdministrator, Side: SideEffectWrite},
	{NetFn: 0x06, Cmd: 0x33, Name: "get message", Spec: "IPMI-2.0", Access: AccessUser, Side: SideEffectRead},
	{NetFn: 0x06, Cmd: 0x34, Name: "send message", Spec: "IPMI-2.0", Access: AccessOperator, Side: SideEffectWrite, Notes: "bridged messages"},
	{NetFn: 0x06, Cmd: 0x37, Name: "system GUID", Spec: "IPMI-2.0", Access: AccessPreAuth, Side: SideEffectRead, Preauth: true, Notes: "Fingerprint hook"},
	{NetFn: 0x06, Cmd: 0x38, Name: "channel authent. capabilities", Spec: "IPMI-2.0", Access: AccessPreAuth, Side: SideEffectRead, Preauth: true, Notes: "Returns auth-type bitmap; CVE-2013-4786 precursor"},
	{NetFn: 0x06, Cmd: 0x39, Name: "session challenge", Spec: "IPMI-1.5", Access: AccessPreAuth, Side: SideEffectSession, Preauth: true, Notes: "IPMI 1.5 MD5 login path -- weak auth"},
	{NetFn: 0x06, Cmd: 0x3A, Name: "activate session", Spec: "IPMI-1.5", Access: AccessPreAuth, Side: SideEffectSession, Preauth: true, Notes: "IPMI 1.5"},
	{NetFn: 0x06, Cmd: 0x3B, Name: "set session priv level", Spec: "IPMI-2.0", Access: AccessUser, Side: SideEffectSession},
	{NetFn: 0x06, Cmd: 0x3C, Name: "close session", Spec: "IPMI-2.0", Access: AccessCallback, Side: SideEffectSession},
	{NetFn: 0x06, Cmd: 0x3D, Name: "get session info", Spec: "IPMI-2.0", Access: AccessUser, Side: SideEffectRead},
	{NetFn: 0x06, Cmd: 0x3F, Name: "get authcode", Spec: "IPMI-1.5", Access: AccessAdministrator, Side: SideEffectRead, Notes: "IPMI 1.5 legacy"},
	{NetFn: 0x06, Cmd: 0x40, Name: "set channel access", Spec: "IPMI-2.0", Access: AccessAdministrator, Side: SideEffectWrite},
	{NetFn: 0x06, Cmd: 0x41, Name: "get channel access", Spec: "IPMI-2.0", Access: AccessUser, Side: SideEffectRead},
	{NetFn: 0x06, Cmd: 0x42, Name: "get channel info", Spec: "IPMI-2.0", Access: AccessUser, Side: SideEffectRead, Preauth: true, Notes: "Some BMCs answer sessionless"},
	{NetFn: 0x06, Cmd: 0x43, Name: "set user access", Spec: "IPMI-2.0", Access: AccessAdministrator, Side: SideEffectWrite},
	{NetFn: 0x06, Cmd: 0x44, Name: "get user access", Spec: "IPMI-2.0", Access: AccessAdministrator, Side: SideEffectRead, Notes: "Enumerates user slots"},
	{NetFn: 0x06, Cmd: 0x45, Name: "set user name", Spec: "IPMI-2.0", Access: AccessAdministrator, Side: SideEffectWrite},
	{NetFn: 0x06, Cmd: 0x46, Name: "get user name", Spec: "IPMI-2.0", Access: AccessAdministrator, Side: SideEffectRead, Notes: "Per-slot username read"},
	{NetFn: 0x06, Cmd: 0x47, Name: "set user password", Spec: "IPMI-2.0", Access: AccessAdministrator, Side: SideEffectDangerous, Notes: "Also used to test/enable user"},
	{NetFn: 0x06, Cmd: 0x48, Name: "activate payload", Spec: "IPMI-2.0", Access: AccessOperator, Side: SideEffectSession},
	{NetFn: 0x06, Cmd: 0x49, Name: "deactivate payload", Spec: "IPMI-2.0", Access: AccessOperator, Side: SideEffectSession},
	{NetFn: 0x06, Cmd: 0x4A, Name: "get payload act stat", Spec: "IPMI-2.0", Access: AccessUser, Side: SideEffectRead},
	{NetFn: 0x06, Cmd: 0x4B, Name: "get payload inst info", Spec: "IPMI-2.0", Access: AccessUser, Side: SideEffectRead},
	{NetFn: 0x06, Cmd: 0x4C, Name: "set user payload access", Spec: "IPMI-2.0", Access: AccessAdministrator, Side: SideEffectWrite},
	{NetFn: 0x06, Cmd: 0x4D, Name: "get user payload access", Spec: "IPMI-2.0", Access: AccessAdministrator, Side: SideEffectRead},
	{NetFn: 0x06, Cmd: 0x4E, Name: "get channel payload sup", Spec: "IPMI-2.0", Access: AccessUser, Side: SideEffectRead},
	{NetFn: 0x06, Cmd: 0x4F, Name: "get channel payload ver", Spec: "IPMI-2.0", Access: AccessUser, Side: SideEffectRead},
	{NetFn: 0x06, Cmd: 0x52, Name: "master write read", Spec: "IPMI-2.0", Access: AccessAdministrator, Side: SideEffectDangerous, Notes: "Arbitrary I2C master -- hardware pivot"},
	{NetFn: 0x06, Cmd: 0x54, Name: "get channel ciphers", Spec: "IPMI-2.0", Access: AccessPreAuth, Side: SideEffectRead, Preauth: true, Notes: "Cipher-suite enumeration -- use for CVE-2013-4786 & cipher-0 checks"},
	{NetFn: 0x06, Cmd: 0x55, Name: "toggle payload encrypt", Spec: "IPMI-2.0", Access: AccessAdministrator, Side: SideEffectWrite},
	{NetFn: 0x06, Cmd: 0x56, Name: "set channel keys", Spec: "IPMI-2.0", Access: AccessAdministrator, Side: SideEffectDangerous, Notes: "Key-exchange -- privileged"},
	{NetFn: 0x06, Cmd: 0x57, Name: "get intf caps", Spec: "IPMI-2.0", Access: AccessUser, Side: SideEffectRead},
	{NetFn: 0x06, Cmd: 0x58, Name: "set system info params", Spec: "IPMI-2.0", Access: AccessAdministrator, Side: SideEffectWrite},
	{NetFn: 0x06, Cmd: 0x59, Name: "get system info params", Spec: "IPMI-2.0", Access: AccessUser, Side: SideEffectRead},

	{NetFn: 0x0A, Cmd: 0x10, Name: "FRU information", Spec: "IPMI-2.0", Access: AccessUser, Side: SideEffectRead},
	{NetFn: 0x0A, Cmd: 0x11, Name: "FRU data read", Spec: "IPMI-2.0", Access: AccessUser, Side: SideEffectRead},
	{NetFn: 0x0A, Cmd: 0x12, Name: "FRU data write", Spec: "IPMI-2.0", Access: AccessOperator, Side: SideEffectWrite},
	{NetFn: 0x0A, Cmd: 0x20, Name: "SDR get repository info", Spec: "IPMI-2.0", Access: AccessUser, Side: SideEffectRead},
	{NetFn: 0x0A, Cmd: 0x21, Name: "SDR get repository alloc info", Spec: "IPMI-2.0", Access: AccessUser, Side: SideEffectRead},
	{NetFn: 0x0A, Cmd: 0x22, Name: "SDR reserve repository", Spec: "IPMI-2.0", Access: AccessUser, Side: SideEffectSession},
	{NetFn: 0x0A, Cmd: 0x23, Name: "SDR get", Spec: "IPMI-2.0", Access: AccessUser, Side: SideEffectRead},
	{NetFn: 0x0A, Cmd: 0x24, Name: "SDR add", Spec: "IPMI-2.0", Access: AccessAdministrator, Side: SideEffectWrite},
	{NetFn: 0x0A, Cmd: 0x26, Name: "SDR delete", Spec: "IPMI-2.0", Access: AccessAdministrator, Side: SideEffectWrite},
	{NetFn: 0x0A, Cmd: 0x27, Name: "SDR clear repository", Spec: "IPMI-2.0", Access: AccessAdministrator, Side: SideEffectDangerous},
	{NetFn: 0x0A, Cmd: 0x28, Name: "SDR get repository time", Spec: "IPMI-2.0", Access: AccessUser, Side: SideEffectRead},
	{NetFn: 0x0A, Cmd: 0x2C, Name: "SDR run init agent", Spec: "IPMI-2.0", Access: AccessAdministrator, Side: SideEffectWrite},
	{NetFn: 0x0A, Cmd: 0x40, Name: "SEL get info", Spec: "IPMI-2.0", Access: AccessUser, Side: SideEffectRead},
	{NetFn: 0x0A, Cmd: 0x42, Name: "SEL reserve", Spec: "IPMI-2.0", Access: AccessUser, Side: SideEffectSession},
	{NetFn: 0x0A, Cmd: 0x43, Name: "SEL get entry", Spec: "IPMI-2.0", Access: AccessUser, Side: SideEffectRead},
	{NetFn: 0x0A, Cmd: 0x44, Name: "SEL add entry", Spec: "IPMI-2.0", Access: AccessOperator, Side: SideEffectWrite},
	{NetFn: 0x0A, Cmd: 0x47, Name: "SEL clear", Spec: "IPMI-2.0", Access: AccessOperator, Side: SideEffectDangerous, Notes: "Destructive -- wipes event log"},
	{NetFn: 0x0A, Cmd: 0x48, Name: "SEL get time", Spec: "IPMI-2.0", Access: AccessUser, Side: SideEffectRead},
	{NetFn: 0x0A, Cmd: 0x49, Name: "SEL set time", Spec: "IPMI-2.0", Access: AccessOperator, Side: SideEffectWrite},

	{NetFn: 0x0A, Cmd: 0x50, Name: "PL get info", Spec: "HP-OEM", Access: AccessUser, Side: SideEffectRead, Notes: "HP iLO platform-log info"},
	{NetFn: 0x0A, Cmd: 0x51, Name: "PL get entry", Spec: "HP-OEM", Access: AccessUser, Side: SideEffectRead},
	{NetFn: 0x0A, Cmd: 0x52, Name: "PL add entry", Spec: "HP-OEM", Access: AccessOperator, Side: SideEffectWrite},
	{NetFn: 0x0A, Cmd: 0x53, Name: "PL clear", Spec: "HP-OEM", Access: AccessAdministrator, Side: SideEffectDangerous},

	{NetFn: 0x0C, Cmd: 0x01, Name: "set LAN config", Spec: "IPMI-2.0", Access: AccessAdministrator, Side: SideEffectWrite},
	{NetFn: 0x0C, Cmd: 0x02, Name: "get LAN config", Spec: "IPMI-2.0", Access: AccessUser, Side: SideEffectRead},
	{NetFn: 0x0C, Cmd: 0x04, Name: "get LAN Stats", Spec: "IPMI-2.0", Access: AccessUser, Side: SideEffectRead, Notes: "Capitalization preserved from firmware"},
	{NetFn: 0x0C, Cmd: 0x20, Name: "SOL activating", Spec: "IPMI-2.0", Access: AccessOperator, Side: SideEffectSession},
	{NetFn: 0x0C, Cmd: 0x21, Name: "set SOL config", Spec: "IPMI-2.0", Access: AccessAdministrator, Side: SideEffectWrite},
	{NetFn: 0x0C, Cmd: 0x22, Name: "get SOL config", Spec: "IPMI-2.0", Access: AccessUser, Side: SideEffectRead},

	{NetFn: 0x2C, Cmd: 0x01, Name: "get caps", Spec: "DCMI-1.5", Access: AccessUser, Side: SideEffectRead, Notes: "DCMI Get Capabilities Info"},
	{NetFn: 0x2C, Cmd: 0x02, Name: "get power reading", Spec: "DCMI-1.5", Access: AccessUser, Side: SideEffectRead},
	{NetFn: 0x2C, Cmd: 0x03, Name: "get power limit", Spec: "DCMI-1.5", Access: AccessUser, Side: SideEffectRead},
	{NetFn: 0x2C, Cmd: 0x04, Name: "set power limit", Spec: "DCMI-1.5", Access: AccessAdministrator, Side: SideEffectWrite},
	{NetFn: 0x2C, Cmd: 0x05, Name: "toggle power limit", Spec: "DCMI-1.5", Access: AccessAdministrator, Side: SideEffectWrite},
	{NetFn: 0x2C, Cmd: 0x06, Name: "Get asset tag", Spec: "DCMI-1.5", Access: AccessUser, Side: SideEffectRead},
	{NetFn: 0x2C, Cmd: 0x07, Name: "get sensor info", Spec: "DCMI-1.5", Access: AccessUser, Side: SideEffectRead, Notes: "DCMI Get DCMI Sensor Info"},
	{NetFn: 0x2C, Cmd: 0x08, Name: "Set asset tag", Spec: "DCMI-1.5", Access: AccessAdministrator, Side: SideEffectWrite},
	{NetFn: 0x2C, Cmd: 0x09, Name: "Get host name", Spec: "DCMI-1.5", Access: AccessUser, Side: SideEffectRead, Notes: "aka Get Management Controller Identifier"},
	{NetFn: 0x2C, Cmd: 0x0A, Name: "Set host name", Spec: "DCMI-1.5", Access: AccessAdministrator, Side: SideEffectWrite},
}

var OEMCommands = []Command{

	{NetFn: 0x30, Name: "OEM Power CMD", Spec: "HP-OEM", Access: AccessOperator, Side: SideEffectDangerous, Notes: "Custom power control"},
	{NetFn: 0x30, Name: "OEM Mgmt Set", Spec: "HP-OEM", Access: AccessAdministrator, Side: SideEffectWrite},
	{NetFn: 0x30, Name: "OEM Mgmt Get", Spec: "HP-OEM", Access: AccessUser, Side: SideEffectRead},
	{NetFn: 0x30, Name: "OEM Mgmt Custom", Spec: "HP-OEM", Access: AccessAdministrator, Side: SideEffectWrite},
	{NetFn: 0x30, Name: "OEM Capabilities Command", Spec: "HP-OEM", Access: AccessUser, Side: SideEffectRead, Notes: "Fingerprint hook -- identifies iLO generation"},
	{NetFn: 0x30, Name: "OEM Mgmt Sensor", Spec: "HP-OEM", Access: AccessUser, Side: SideEffectRead, Notes: "Reveals 'Hidden from IPMI' SDR records"},
	{NetFn: 0x30, Name: "OEM License data Get", Spec: "HP-OEM", Access: AccessUser, Side: SideEffectRead, Notes: "Returns installed iLO license blob"},
	{NetFn: 0x30, Name: "OEM Network Info", Spec: "HP-OEM", Access: AccessUser, Side: SideEffectRead},
	{NetFn: 0x30, Name: "OEM Network Reset", Spec: "HP-OEM", Access: AccessAdministrator, Side: SideEffectReset},
	{NetFn: 0x30, Name: "OEM Network6 Info", Spec: "HP-OEM", Access: AccessUser, Side: SideEffectRead, Notes: "IPv6 stack info"},
	{NetFn: 0x30, Name: "OEM BlackBox", Spec: "HP-OEM", Access: AccessAdministrator, Side: SideEffectRead, Notes: "Read/write Active Health System (AHS) ring buffer"},
	{NetFn: 0x30, Name: "OEM Vsp Feature Enbls", Spec: "HP-OEM", Access: AccessAdministrator, Side: SideEffectWrite, Notes: "Virtual Serial Port feature enables"},
	{NetFn: 0x30, Name: "OEM NVDIMM", Spec: "HP-OEM", Access: AccessOperator, Side: SideEffectWrite},
	{NetFn: 0x30, Name: "OEM web port", Spec: "HP-OEM", Access: AccessAdministrator, Side: SideEffectWrite, Notes: "Changes HTTPS management port"},
	{NetFn: 0x30, Name: "OEM PS slot", Spec: "HP-OEM", Access: AccessUser, Side: SideEffectRead},
	{NetFn: 0x30, Name: "OEM user defined name", Spec: "HP-OEM", Access: AccessAdministrator, Side: SideEffectWrite},
	{NetFn: 0x30, Name: "OEM transition control", Spec: "HP-OEM", Access: AccessAdministrator, Side: SideEffectWrite},
	{NetFn: 0x30, Name: "OEM Get Attached iPDU", Spec: "HP-OEM", Access: AccessUser, Side: SideEffectRead, Notes: "Intelligent PDU topology"},
	{NetFn: 0x30, Name: "OEM Set Regex pattern", Spec: "HP-OEM", Access: AccessAdministrator, Side: SideEffectWrite, Notes: "Custom event pattern matcher"},
	{NetFn: 0x30, Name: "OEM Get Regex pattern", Spec: "HP-OEM", Access: AccessUser, Side: SideEffectRead},

	{NetFn: 0x30, Cmd: 0x24, Name: "Get connected BL IPv4", Spec: "HP-OEM", Access: AccessUser, Side: SideEffectRead, Notes: "Blade enclosure blade IP list (sub-cmd addressed); source: bmc_oem2.c"},

	{NetFn: 0x32, Name: "OEM Activate sys intf sess", Spec: "HP-OEM", Access: AccessAdministrator, Side: SideEffectSession, Notes: "Open IPMI session over system interface -- host-to-BMC"},
	{NetFn: 0x32, Name: "OEM Set sys intf priv level", Spec: "HP-OEM", Access: AccessAdministrator, Side: SideEffectSession, Notes: "Elevate system-interface session privilege"},
	{NetFn: 0x32, Name: "OEM Close sys intf session", Spec: "HP-OEM", Access: AccessUser, Side: SideEffectSession},
	{NetFn: 0x32, Name: "OEM Get sys intf sess info", Spec: "HP-OEM", Access: AccessUser, Side: SideEffectRead},
	{NetFn: 0x32, Name: "OEM Set sys intf config info", Spec: "HP-OEM", Access: AccessAdministrator, Side: SideEffectWrite},
	{NetFn: 0x32, Name: "OEM Get sys intf config info", Spec: "HP-OEM", Access: AccessUser, Side: SideEffectRead},
	{NetFn: 0x32, Name: "OEM Change Chann Assignment", Spec: "HP-OEM", Access: AccessAdministrator, Side: SideEffectWrite, Notes: "Renumber IPMI channels; enforces 'not settable/reserved/in use/not valid'"},
	{NetFn: 0x32, Name: "OEM Set IPMI Config", Spec: "HP-OEM", Access: AccessAdministrator, Side: SideEffectWrite, Notes: "Toggle TELNET/SSH/IPMI_DCMI_OVER_LAN/SERIAL_CLI"},
	{NetFn: 0x32, Name: "OEM Get IPMI Config", Spec: "HP-OEM", Access: AccessUser, Side: SideEffectRead, Notes: "Passive service enablement enumeration"},
	{NetFn: 0x32, Name: "test", Spec: "HP-OEM", Access: AccessAdministrator, Side: SideEffectRead, Notes: "Firmware test hook (name is literally 'test')"},

	{NetFn: 0x34, Name: "OEM LED control", Spec: "HP-OEM", Access: AccessOperator, Side: SideEffectWrite, Notes: "Drive LEDs including health / UID"},
	{NetFn: 0x34, Name: "OEM NVRAM message", Spec: "HP-OEM", Access: AccessAdministrator, Side: SideEffectDangerous, Notes: "Subcommand-dispatched NVRAM read/write"},
	{NetFn: 0x34, Name: "OEM driver loaded", Spec: "HP-OEM", Access: AccessUser, Side: SideEffectRead},
	{NetFn: 0x34, Name: "OEM CPQTAF message", Spec: "HP-OEM", Access: AccessAdministrator, Side: SideEffectWrite, Notes: "Legacy Compaq Technical Assistance Facility"},
	{NetFn: 0x34, Name: "OEM SDREXT message", Spec: "HP-OEM", Access: AccessAdministrator, Side: SideEffectWrite, Notes: "Extended SDR access"},
	{NetFn: 0x34, Name: "OEM SPD command message", Spec: "HP-OEM", Access: AccessAdministrator, Side: SideEffectRead, Notes: "DIMM SPD EEPROM access"},
	{NetFn: 0x34, Name: "OEM Pwr Controller read", Spec: "HP-OEM", Access: AccessAdministrator, Side: SideEffectRead, Notes: "Power-management micro register read"},
	{NetFn: 0x34, Name: "OEM Pwr Controller write", Spec: "HP-OEM", Access: AccessAdministrator, Side: SideEffectDangerous, Notes: "Direct power-micro register write"},
	{NetFn: 0x34, Name: "OEM FRU command message", Spec: "HP-OEM", Access: AccessAdministrator, Side: SideEffectWrite, Notes: "Low-level FRU command bypass"},
	{NetFn: 0x34, Name: "OEM IO read", Spec: "HP-OEM", Access: AccessAdministrator, Side: SideEffectRead, Notes: "Arbitrary BMC I/O space read -- powerful"},
	{NetFn: 0x34, Name: "OEM I2c segment master wr-rd", Spec: "HP-OEM", Access: AccessAdministrator, Side: SideEffectDangerous, Notes: "Arbitrary I2C master on a chosen segment -- hardware pivot"},

	{NetFn: 0x36, Name: "OEM BlackBox descriptor", Spec: "HP-OEM", Access: AccessAdministrator, Side: SideEffectRead, Notes: "bmc_oem3.c 'bb desc' path"},
	{NetFn: 0x36, Name: "OEM BlackBox data", Spec: "HP-OEM", Access: AccessAdministrator, Side: SideEffectRead, Notes: "bmc_oem3.c 'bb data' path; sequence-checked"},
}

func CommandByNetFnCmd(netFn, cmd byte) (Command, bool) {
	for _, c := range StdCommands {
		if c.NetFn == netFn && c.Cmd == cmd {
			return c, true
		}
	}
	for _, c := range OEMCommands {
		if c.NetFn == netFn && c.Cmd != 0 && c.Cmd == cmd {
			return c, true
		}
	}
	return Command{}, false
}

func CommandsByNetFn(netFn byte) []Command {
	var out []Command
	for _, c := range StdCommands {
		if c.NetFn == netFn {
			out = append(out, c)
		}
	}
	for _, c := range OEMCommands {
		if c.NetFn == netFn {
			out = append(out, c)
		}
	}
	return out
}

func PreauthCommands() []Command {
	var out []Command
	for _, c := range StdCommands {
		if c.Preauth {
			out = append(out, c)
		}
	}
	return out
}
