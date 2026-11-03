// Package ipmi provides the RMCP/RMCP+/RAKP primitives used by oobscan: the
// unauthenticated probes and the authenticated session flows the scan engine
// drives to validate exposure and collect post-auth inventory. It has no platform
// dependencies, so oobscan builds as a single static binary.
package ipmi

// Well-known IPMI / RMCP constants.
const (
	DefaultPort = 623

	RMCPVersion   byte = 0x06
	RMCPReserved  byte = 0x00
	RMCPSeqNoAck  byte = 0xFF
	RMCPClassIPMI byte = 0x07
	RMCPClassASF  byte = 0x06

	IPMI15AuthNone byte = 0x00
	IPMI15AuthMD2  byte = 0x01
	IPMI15AuthMD5  byte = 0x02
	IPMI15AuthPass byte = 0x04 // straight password
	IPMI15AuthOEM  byte = 0x05

	IPMI20Format byte = 0x06
)

// PayloadType covers the RMCP+ payload type field.
const (
	PayloadIPMI           byte = 0x00
	PayloadSOL            byte = 0x01
	PayloadOpenSessionReq byte = 0x10
	PayloadOpenSessionRes byte = 0x11
	PayloadRAKP1          byte = 0x12
	PayloadRAKP2          byte = 0x13
	PayloadRAKP3          byte = 0x14
	PayloadRAKP4          byte = 0x15
)

// RAKP auth algorithms.
const (
	RAKPNone       byte = 0x00
	RAKPHMACSHA1   byte = 0x01
	RAKPHMACMD5    byte = 0x02
	RAKPHMACSHA256 byte = 0x03
)

// Integrity algorithms.
const (
	IntegrityNone          byte = 0x00
	IntegrityHMACSHA196    byte = 0x01
	IntegrityHMACMD5128    byte = 0x02
	IntegrityMD5128        byte = 0x03
	IntegrityHMACSHA256128 byte = 0x04
)

// Confidentiality algorithms.
const (
	ConfNone    byte = 0x00
	ConfAESCBC  byte = 0x01
	ConfXRC4128 byte = 0x02
	ConfXRC440  byte = 0x03
)

// NetFn (network functions), bottom 6 bits of the first data byte.
const (
	NetFnChassis   byte = 0x00
	NetFnBridge    byte = 0x02
	NetFnSensor    byte = 0x04
	NetFnApp       byte = 0x06
	NetFnFirmware  byte = 0x08
	NetFnStorage   byte = 0x0A
	NetFnTransport byte = 0x0C
	NetFnGroup     byte = 0x2C // DCMI lives under group extension
	NetFnOEM       byte = 0x2E
)

// App-netfn commands referenced by oobscan checks.
const (
	CmdGetChassisStatus       byte = 0x01
	CmdGetDeviceID            byte = 0x01
	CmdGetLANConfigParams     byte = 0x02
	CmdColdReset              byte = 0x02
	CmdWarmReset              byte = 0x03
	CmdGetSelfTestResults     byte = 0x04
	CmdGetDeviceGUID          byte = 0x08
	CmdGetSystemGUID          byte = 0x37
	CmdGetChannelAuthCaps     byte = 0x38
	CmdGetSessionChallenge    byte = 0x39
	CmdActivateSession        byte = 0x3A
	CmdSetSessionPrivilege    byte = 0x3B
	CmdCloseSession           byte = 0x3C
	CmdGetAuthCode            byte = 0x3F
	CmdSetChannelAccess       byte = 0x40
	CmdGetChannelAccess       byte = 0x41
	CmdGetChannelInfo         byte = 0x42
	CmdSetUserAccess          byte = 0x43
	CmdGetUserAccess          byte = 0x44
	CmdSetUserName            byte = 0x45
	CmdGetUserName            byte = 0x46
	CmdSetUserPassword        byte = 0x47
	CmdActivatePayload        byte = 0x48
	CmdDeactivatePayload      byte = 0x49
	CmdGetPayloadStatus       byte = 0x4A
	CmdGetPayloadInfo         byte = 0x4B
	CmdGetChannelCipherSuites byte = 0x54
	CmdGetFRUInventoryInfo    byte = 0x10
	CmdReadFRUData            byte = 0x11
)

// Get SOL Configuration Parameters (CmdGetSOLConfigParams, on NetFnTransport)
// parameter selectors (IPMI 2.0 Table 26-5). Only the four that describe the SOL
// exposure are read: whether SOL is on, the privilege it demands, and where its
// payload listens. This command can answer at privilege 0 despite being outside
// the documented Privilege::None command set, so it doubles as a privilege-gate
// probe rather than just an inventory read.
const (
	SOLParamEnable         byte = 0x01
	SOLParamAuthentication byte = 0x02
	SOLParamPayloadChannel byte = 0x07
	SOLParamPayloadPort    byte = 0x08
)

// DCMI (Data Center Manageability Interface) rides on the Group Extension
// network function (NetFnGroup, 0x2C). Every DCMI request/response carries the
// DCMI group identifier (0xDC) as its first data byte. Get DCMI Capabilities
// Info is one of the commands a BMC answers pre-session - it sits on the iLO4
// sessionless allow-list gated on the 0xDC group byte - so it is safe to
// enumerate without a session.
const (
	DCMIGroupExtID         byte = 0xDC
	CmdDCMIGetCapabilities byte = 0x01
	DCMIParamSupportedCaps byte = 0x01 // parameter selector: Supported DCMI capabilities
)
