package ipmi

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
	IPMI15AuthPass byte = 0x04
	IPMI15AuthOEM  byte = 0x05

	IPMI20Format byte = 0x06
)

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

const (
	RAKPNone       byte = 0x00
	RAKPHMACSHA1   byte = 0x01
	RAKPHMACMD5    byte = 0x02
	RAKPHMACSHA256 byte = 0x03
)

const (
	IntegrityNone          byte = 0x00
	IntegrityHMACSHA196    byte = 0x01
	IntegrityHMACMD5128    byte = 0x02
	IntegrityMD5128        byte = 0x03
	IntegrityHMACSHA256128 byte = 0x04
)

const (
	ConfNone    byte = 0x00
	ConfAESCBC  byte = 0x01
	ConfXRC4128 byte = 0x02
	ConfXRC440  byte = 0x03
)

const (
	NetFnChassis   byte = 0x00
	NetFnBridge    byte = 0x02
	NetFnSensor    byte = 0x04
	NetFnApp       byte = 0x06
	NetFnFirmware  byte = 0x08
	NetFnStorage   byte = 0x0A
	NetFnTransport byte = 0x0C
	NetFnGroup     byte = 0x2C
	NetFnOEM       byte = 0x2E
)

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

const (
	SOLParamEnable         byte = 0x01
	SOLParamAuthentication byte = 0x02
	SOLParamPayloadChannel byte = 0x07
	SOLParamPayloadPort    byte = 0x08
)

const (
	DCMIGroupExtID         byte = 0xDC
	CmdDCMIGetCapabilities byte = 0x01
	DCMIParamSupportedCaps byte = 0x01
)
