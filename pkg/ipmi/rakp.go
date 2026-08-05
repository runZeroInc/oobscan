package ipmi

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"time"
)

var smcRAKPFixedKey = decodeHexConst("fab979d849be933dd0c41fd2c9d77a30aa8d3f50")

func decodeHexConst(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

type RAKPResult struct {
	Host           string
	Username       string
	AuthAlgo       byte
	IntegrityAlgo  byte
	ConfAlgo       byte
	ClientSID      uint32
	BMCSID         uint32
	ClientRand     []byte
	BMCRand        []byte
	BMCGUID        []byte
	RAKPHash       []byte
	ErrorCode      byte
	OpenSessionRaw []byte
	RAKP2Raw       []byte

	Crack *CrackResult
}

func (r *RAKPResult) Hashcat() string {

	if r.AuthAlgo != RAKPHMACSHA1 || len(r.RAKPHash) != sha1.Size {
		return ""
	}
	return r.SaltHashLine()
}

func (r *RAKPResult) SaltHashLine() string {
	if len(r.RAKPHash) == 0 {
		return ""
	}
	return fmt.Sprintf("%x:%x", r.Salt(), r.RAKPHash)
}

func (r *RAKPResult) Salt() []byte {
	guid := r.BMCGUID
	if len(guid) < 16 {
		guid = append(append([]byte(nil), guid...), make([]byte, 16-len(guid))...)
	} else if len(guid) > 16 {
		guid = guid[:16]
	}
	var salt []byte
	salt = binary.LittleEndian.AppendUint32(salt, r.ClientSID)
	salt = binary.LittleEndian.AppendUint32(salt, r.BMCSID)
	salt = append(salt, r.ClientRand...)
	salt = append(salt, r.BMCRand...)
	salt = append(salt, guid...)
	salt = append(salt, 0x14, byte(len(r.Username)))
	salt = append(salt, r.Username...)
	return salt
}

func DoRAKP12(host string, port int, username string, authAlgo, intAlgo, confAlgo byte, timeout time.Duration) (*RAKPResult, error) {
	c, err := NewClient(host, port, timeout)
	if err != nil {
		return nil, err
	}
	defer c.Close()

	var cSID uint32
	_ = binary.Read(rand.Reader, binary.LittleEndian, &cSID)
	if cSID == 0 {
		cSID = 0xa0a2a3a4
	}
	cRand := make([]byte, 16)
	if _, err := rand.Read(cRand); err != nil {
		return nil, err
	}

	var os bytes.Buffer
	os.WriteByte(0x00)
	os.WriteByte(0x04)
	os.Write([]byte{0x00, 0x00})
	_ = binary.Write(&os, binary.LittleEndian, cSID)

	os.Write([]byte{0x00, 0x00, 0x00, 0x08})
	os.WriteByte(authAlgo)
	os.Write([]byte{0, 0, 0})

	os.Write([]byte{0x01, 0x00, 0x00, 0x08})
	os.WriteByte(intAlgo)
	os.Write([]byte{0, 0, 0})

	os.Write([]byte{0x02, 0x00, 0x00, 0x08})
	os.WriteByte(confAlgo)
	os.Write([]byte{0, 0, 0})

	osPkt := buildRMCPPlus(PayloadOpenSessionReq, 0, 0, os.Bytes())
	osResp, err := c.Send(osPkt)
	if err != nil {
		return nil, fmt.Errorf("open-session: %w", err)
	}

	res := &RAKPResult{
		Host:           host,
		Username:       username,
		AuthAlgo:       authAlgo,
		IntegrityAlgo:  intAlgo,
		ConfAlgo:       confAlgo,
		ClientSID:      cSID,
		ClientRand:     cRand,
		OpenSessionRaw: osResp,
	}

	bmcSID, err := parseOpenSessionResp(osResp)
	if err != nil {
		return res, fmt.Errorf("open-session parse: %w", err)
	}
	res.BMCSID = bmcSID

	var r1 bytes.Buffer
	r1.WriteByte(0x00)
	r1.Write([]byte{0, 0, 0})
	_ = binary.Write(&r1, binary.LittleEndian, bmcSID)
	r1.Write(cRand)
	r1.WriteByte(0x14)
	r1.Write([]byte{0, 0})
	r1.WriteByte(byte(len(username)))
	r1.WriteString(username)

	r1Pkt := buildRMCPPlus(PayloadRAKP1, 0, 0, r1.Bytes())
	r2Resp, err := c.Send(r1Pkt)
	if err != nil {
		return res, fmt.Errorf("rakp1: %w", err)
	}
	res.RAKP2Raw = r2Resp
	if err := parseRAKP2(r2Resp, res); err != nil {
		return res, err
	}
	return res, nil
}

func (r *RAKPResult) VerifyRAKPPassword(password string) bool {
	return r.VerifyRAKPKey([]byte(password))
}

func (r *RAKPResult) VerifyRAKPKey(key []byte) bool {
	var mac hash.Hash

	switch r.AuthAlgo {
	case RAKPHMACSHA1:
		mac = hmac.New(sha1.New, key)
	case RAKPHMACMD5:
		mac = hmac.New(md5.New, key)
	case RAKPHMACSHA256:
		mac = hmac.New(sha256.New, key)
	default:
		return false
	}
	var buf bytes.Buffer
	_ = binary.Write(&buf, binary.LittleEndian, r.ClientSID)
	_ = binary.Write(&buf, binary.LittleEndian, r.BMCSID)
	buf.Write(r.ClientRand)
	buf.Write(r.BMCRand)
	buf.Write(r.BMCGUID)
	buf.WriteByte(0x14)
	buf.WriteByte(byte(len(r.Username)))
	buf.WriteString(r.Username)
	mac.Write(buf.Bytes())
	return hmac.Equal(mac.Sum(nil), r.RAKPHash)
}

func (r *RAKPResult) UsesSMCRAKPFixedKey() bool {
	return r.VerifyRAKPKey(smcRAKPFixedKey)
}

func BuildRMCPPlus(payloadType byte, body []byte) []byte {
	return buildRMCPPlus(payloadType, 0, 0, body)
}

func RmcpPlusPayload(pkt []byte) ([]byte, error) {
	return rmcpPlusPayload(pkt)
}

func BuildRMCPPlusWithSID(payloadType byte, sid uint32, body []byte) []byte {
	return buildRMCPPlusSID(payloadType, sid, 0, body)
}

func buildRMCPPlus(payloadType byte, authType, payloadEnc byte, body []byte) []byte {
	_ = authType
	_ = payloadEnc
	return buildRMCPPlusSID(payloadType, 0, 0, body)
}

func rmcpPlusPayload(pkt []byte) ([]byte, error) {

	if len(pkt) < 16 {
		return nil, errors.New("short RMCP+ packet")
	}
	payloadLen := int(binary.LittleEndian.Uint16(pkt[14:16]))
	if len(pkt) < 16+payloadLen {
		return nil, errors.New("truncated RMCP+ payload")
	}
	return pkt[16 : 16+payloadLen], nil
}

func parseOpenSessionResp(pkt []byte) (uint32, error) {
	bmcSID, _, err := parseOpenSessionRespFull(pkt)
	return bmcSID, err
}

func parseOpenSessionRespFull(pkt []byte) (uint32, byte, error) {
	payload, err := rmcpPlusPayload(pkt)
	if err != nil {
		return 0, 0, fmt.Errorf("open-session parse: %w", err)
	}

	if len(payload) < 2 {
		return 0, 0, errors.New("short open-session payload")
	}
	if status := payload[1]; status != 0 {
		return 0, 0, fmt.Errorf("open-session rejected: status=0x%02x (%s)", status, rakpStatusText(status))
	}
	if len(payload) < 12 {
		return 0, 0, errors.New("short open-session payload")
	}

	bmcSID := binary.LittleEndian.Uint32(payload[8:12])
	return bmcSID, payload[2] & 0x0f, nil
}

func ParseOpenSessionResponse(pkt []byte) (uint32, error) {
	return parseOpenSessionResp(pkt)
}

func parseRAKP2(pkt []byte, r *RAKPResult) error {
	p, err := rmcpPlusPayload(pkt)
	if err != nil {
		return fmt.Errorf("rakp2 parse: %w", err)
	}
	if len(p) < 40 {
		return errors.New("short RAKP2 payload")
	}

	r.ErrorCode = p[1]
	r.BMCRand = append([]byte(nil), p[8:24]...)
	r.BMCGUID = append([]byte(nil), p[24:40]...)
	if len(p) > 40 {
		r.RAKPHash = append([]byte(nil), p[40:]...)
	}
	if r.ErrorCode != 0 {
		return fmt.Errorf("RAKP2 status=0x%02x", r.ErrorCode)
	}
	if len(r.RAKPHash) == 0 {
		return errors.New("RAKP2 did not contain HMAC")
	}
	return nil
}
