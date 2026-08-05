package ipmi

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"time"
)

var iloNormalAlgoZeroRecord = [8]byte{0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00}

func iloOpenSessionRaw(host string, port int, reqPriv byte, authRec [8]byte, timeout time.Duration) (status byte, bmcSID uint32, err error) {
	c, err := NewClient(host, port, timeout)
	if err != nil {
		return 0, 0, err
	}
	defer c.Close()
	retries := session20HandshakeRetries(timeout)

	var cSID uint32
	_ = binary.Read(rand.Reader, binary.LittleEndian, &cSID)
	if cSID == 0 {
		cSID = 0xa0a2a3a4
	}
	var os bytes.Buffer
	os.WriteByte(0x00)
	os.WriteByte(reqPriv & 0x0f)
	os.Write([]byte{0x00, 0x00})
	_ = binary.Write(&os, binary.LittleEndian, cSID)
	os.Write(authRec[:])
	os.Write([]byte{0x01, 0x00, 0x00, 0x08, 0x01, 0, 0, 0})
	os.Write([]byte{0x02, 0x00, 0x00, 0x08, 0x01, 0, 0, 0})

	resp, err := sendWithTimeoutRetry(c, buildRMCPPlus(PayloadOpenSessionReq, 0, 0, os.Bytes()), retries)
	if err != nil {
		return 0, 0, fmt.Errorf("open-session: %w", err)
	}
	pl, err := rmcpPlusPayload(resp)
	if err != nil {
		return 0, 0, err
	}
	if len(pl) < 2 {
		return 0, 0, errors.New("short open-session response")
	}
	status = pl[1]
	if status == 0 && len(pl) >= 12 {
		bmcSID = binary.LittleEndian.Uint32(pl[8:12])
	}
	return status, bmcSID, nil
}

func ILOAlgoZeroControlAccepted(host string, port int, timeout time.Duration) (accepted bool, status byte, err error) {
	st, _, e := iloOpenSessionRaw(host, port, 0x04, iloNormalAlgoZeroRecord, timeout)
	if e != nil {
		return false, 0, e
	}
	return st == 0x00, st, nil
}
