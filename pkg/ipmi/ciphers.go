package ipmi

import (
	"errors"
	"sort"
	"strconv"
	"time"
)

func EnumCipherSuites15(host string, port int, timeout time.Duration) ([]int, []byte, error) {
	c, err := NewClient(host, port, timeout)
	if err != nil {
		return nil, nil, err
	}
	defer c.Close()

	var raw []byte
	for idx := range 16 {

		req := buildSessionlessMsg(NetFnApp, CmdGetChannelCipherSuites, []byte{0x0e, 0x00, byte(0x80 | idx)})
		reply, err := c.Send(req)
		if err != nil {
			break
		}
		data, cc, ok := extractIPMIData(reply)
		if !ok || cc != 0x00 || len(data) < 1 {
			break
		}
		recs := data[1:]
		raw = append(raw, recs...)

		if len(recs) < 16 {
			break
		}
	}
	if len(raw) == 0 {
		return nil, nil, errors.New("ciphers: no cipher suite data")
	}
	return parseCipherSuiteIDs(raw), raw, nil
}

func parseCipherSuiteIDs(raw []byte) []int {
	seen := map[int]bool{}
	var out []int
	for i := 0; i < len(raw); {
		if raw[i] == 0xC0 || raw[i] == 0xC1 {
			if i+1 < len(raw) {
				id := int(raw[i+1])

				if (id <= 19 || id >= 128) && !seen[id] {
					seen[id] = true
					out = append(out, id)
				}
			}
			i += 2
			for i < len(raw) && raw[i] != 0xC0 && raw[i] != 0xC1 {
				i++
			}
			continue
		}
		i++
	}
	sort.Ints(out)
	return out
}

func CipherSuiteName(id int) string {
	switch id {
	case 0:
		return "none/none/none (cipher-0 auth bypass, CVE-2013-4782)"
	case 1:
		return "HMAC-SHA1/none/none (no integrity, no encryption)"
	case 2:
		return "HMAC-SHA1/HMAC-SHA1-96/none (no encryption)"
	case 3:
		return "HMAC-SHA1/HMAC-SHA1-96/AES-CBC-128"
	case 4:
		return "HMAC-SHA1/HMAC-SHA1-96/xRC4-128"
	case 5:
		return "HMAC-SHA1/HMAC-SHA1-96/xRC4-40"
	case 6:
		return "HMAC-MD5/none/none"
	case 7:
		return "HMAC-MD5/HMAC-MD5-128/none"
	case 8:
		return "HMAC-MD5/HMAC-MD5-128/AES-CBC-128"
	case 9:
		return "HMAC-MD5/HMAC-MD5-128/xRC4-128"
	case 10:
		return "HMAC-MD5/HMAC-MD5-128/xRC4-40"
	case 11:
		return "HMAC-MD5/MD5-128/none"
	case 12:
		return "HMAC-MD5/MD5-128/AES-CBC-128"
	case 13:
		return "HMAC-MD5/MD5-128/xRC4-128"
	case 14:
		return "HMAC-MD5/MD5-128/xRC4-40"
	case 15:
		return "HMAC-SHA256/none/none"
	case 16:
		return "HMAC-SHA256/HMAC-SHA256-128/none"
	case 17:
		return "HMAC-SHA256/HMAC-SHA256-128/AES-CBC-128 (recommended)"
	case 18:
		return "HMAC-SHA256/HMAC-SHA256-128/xRC4-128"
	case 19:
		return "HMAC-SHA256/HMAC-SHA256-128/xRC4-40"
	default:
		return "cipher suite " + strconv.Itoa(id)
	}
}

func AuthAlgosForCiphers(ids []int) []byte {
	has := func(lo, hi int) bool {
		for _, id := range ids {
			if id >= lo && id <= hi {
				return true
			}
		}
		return false
	}
	var out []byte
	if has(1, 5) {
		out = append(out, RAKPHMACSHA1)
	}
	if has(15, 19) {
		out = append(out, RAKPHMACSHA256)
	}
	if has(6, 14) {
		out = append(out, RAKPHMACMD5)
	}
	return out
}

type CipherAlgos struct {
	Suite     int  `json:"suite"`
	Auth      byte `json:"auth"`
	Integrity byte `json:"integrity"`
	Conf      byte `json:"conf"`
}

func CipherAlgosFor(id int) (CipherAlgos, bool) {
	switch id {
	case 1:
		return CipherAlgos{1, RAKPHMACSHA1, IntegrityNone, ConfNone}, true
	case 2:
		return CipherAlgos{2, RAKPHMACSHA1, IntegrityHMACSHA196, ConfNone}, true
	case 3:
		return CipherAlgos{3, RAKPHMACSHA1, IntegrityHMACSHA196, ConfAESCBC}, true
	case 4:
		return CipherAlgos{4, RAKPHMACSHA1, IntegrityHMACSHA196, ConfXRC4128}, true
	case 5:
		return CipherAlgos{5, RAKPHMACSHA1, IntegrityHMACSHA196, ConfXRC440}, true
	case 6:
		return CipherAlgos{6, RAKPHMACMD5, IntegrityNone, ConfNone}, true
	case 7:
		return CipherAlgos{7, RAKPHMACMD5, IntegrityHMACMD5128, ConfNone}, true
	case 8:
		return CipherAlgos{8, RAKPHMACMD5, IntegrityHMACMD5128, ConfAESCBC}, true
	case 9:
		return CipherAlgos{9, RAKPHMACMD5, IntegrityHMACMD5128, ConfXRC4128}, true
	case 10:
		return CipherAlgos{10, RAKPHMACMD5, IntegrityHMACMD5128, ConfXRC440}, true
	case 11:
		return CipherAlgos{11, RAKPHMACMD5, IntegrityMD5128, ConfNone}, true
	case 12:
		return CipherAlgos{12, RAKPHMACMD5, IntegrityMD5128, ConfAESCBC}, true
	case 13:
		return CipherAlgos{13, RAKPHMACMD5, IntegrityMD5128, ConfXRC4128}, true
	case 14:
		return CipherAlgos{14, RAKPHMACMD5, IntegrityMD5128, ConfXRC440}, true
	case 15:
		return CipherAlgos{15, RAKPHMACSHA256, IntegrityNone, ConfNone}, true
	case 16:
		return CipherAlgos{16, RAKPHMACSHA256, IntegrityHMACSHA256128, ConfNone}, true
	case 17:
		return CipherAlgos{17, RAKPHMACSHA256, IntegrityHMACSHA256128, ConfAESCBC}, true
	case 18:
		return CipherAlgos{18, RAKPHMACSHA256, IntegrityHMACSHA256128, ConfXRC4128}, true
	case 19:
		return CipherAlgos{19, RAKPHMACSHA256, IntegrityHMACSHA256128, ConfXRC440}, true
	}
	return CipherAlgos{}, false
}

func CipherTriples(ids []int) []CipherAlgos {
	order := ids
	if len(order) == 0 {
		order = []int{17, 3, 16, 2, 1, 8, 7, 6, 12, 11, 15, 9, 10, 13, 14, 4, 5, 18, 19}
	}

	full := map[int]bool{3: true, 4: true, 5: true, 8: true, 9: true, 10: true, 12: true, 13: true, 14: true, 16: true, 17: true, 18: true, 19: true}
	var head, tail []CipherAlgos
	seen := map[int]bool{}
	for _, id := range order {
		if seen[id] {
			continue
		}
		seen[id] = true
		if ca, ok := CipherAlgosFor(id); ok {
			if full[id] {
				head = append(head, ca)
			} else {
				tail = append(tail, ca)
			}
		}
	}
	return append(head, tail...)
}

func CipherSuiteWeak(id int) bool {
	switch id {
	case 3, 8, 17:
		return false
	default:
		return true
	}
}

func extractIPMIData(reply []byte) (data []byte, cc byte, ok bool) {
	for i := 0; i+7 < len(reply); i++ {
		if (reply[i] == 0x81 || reply[i] == 0x8c) && i+3 < len(reply) && reply[i+3] == 0x20 {
			end := len(reply) - 1
			if end > i+7 {
				return reply[i+7 : end], reply[i+6], true
			}
			return nil, reply[i+6], true
		}
	}
	return nil, 0, false
}
