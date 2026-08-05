package report

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"hash"

	"github.com/runZeroInc/oobscan/pkg/ipmi"
	"github.com/runZeroInc/oobscan/pkg/output"
)

var smcRAKPFixedKeyBytes = mustHex("fab979d849be933dd0c41fd2c9d77a30aa8d3f50")

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func rakpRecordUsesSMCRAKPFixedKey(r *output.RAKPRecord) bool {
	if r == nil || r.Redacted || r.RAKPHash == "" {
		return false
	}
	cRand, err1 := hex.DecodeString(r.ClientRand)
	bRand, err2 := hex.DecodeString(r.BMCRand)
	guidB, err3 := hex.DecodeString(r.BMCGUID)
	hashB, err4 := hex.DecodeString(r.RAKPHash)
	if err1 != nil || err2 != nil || err3 != nil || err4 != nil || len(hashB) == 0 {
		return false
	}
	var mac hash.Hash
	switch r.AuthAlgo {
	case ipmi.RAKPHMACSHA1:
		mac = hmac.New(sha1.New, smcRAKPFixedKeyBytes)
	case ipmi.RAKPHMACMD5:
		mac = hmac.New(md5.New, smcRAKPFixedKeyBytes)
	case ipmi.RAKPHMACSHA256:
		mac = hmac.New(sha256.New, smcRAKPFixedKeyBytes)
	default:
		return false
	}
	var buf bytes.Buffer
	_ = binary.Write(&buf, binary.LittleEndian, r.ClientSID)
	_ = binary.Write(&buf, binary.LittleEndian, r.BMCSID)
	buf.Write(cRand)
	buf.Write(bRand)
	buf.Write(guidB)
	buf.WriteByte(0x14)
	buf.WriteByte(byte(len(r.Username)))
	buf.WriteString(r.Username)
	mac.Write(buf.Bytes())
	return hmac.Equal(mac.Sum(nil), hashB)
}
