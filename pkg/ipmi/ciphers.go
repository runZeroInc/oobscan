package ipmi

import (
	"errors"
	"sort"
	"strconv"
	"time"
)

// EnumCipherSuites15 enumerates the cipher suites a BMC advertises via the paged
// Get Channel Cipher Suites command (NetFn App / Cmd 0x54). This is a pre-session
// command (a client needs it before Open Session), so it is answered sessionless
// over LAN. Returns the sorted, de-duplicated cipher suite IDs and the raw record bytes.
func EnumCipherSuites15(host string, port int, timeout time.Duration) ([]int, []byte, error) {
	c, err := NewClient(host, port, timeout)
	if err != nil {
		return nil, nil, err
	}
	defer c.Close()

	var raw []byte
	for idx := range 16 {
		// data = [channel=0x0e][payload type=0x00 (IPMI)][0x80|list-index]
		req := buildSessionlessMsg(NetFnApp, CmdGetChannelCipherSuites, []byte{0x0e, 0x00, byte(0x80 | idx)})
		reply, err := c.Send(req)
		if err != nil {
			break
		}
		data, cc, ok := extractIPMIData(reply)
		if !ok || cc != 0x00 || len(data) < 1 {
			break
		}
		recs := data[1:] // first byte is the channel number
		raw = append(raw, recs...)
		// A full page carries 16 record bytes; a short page is the last one.
		if len(recs) < 16 {
			break
		}
	}
	if len(raw) == 0 {
		return nil, nil, errors.New("ciphers: no cipher suite data")
	}
	return parseCipherSuiteIDs(raw), raw, nil
}

// parseCipherSuiteIDs walks the Cipher Suite Record list. Each record begins with
// a 0xC0 (standard) or 0xC1 (OEM) start-of-record tag followed by the cipher
// suite ID; the algorithm bytes that follow are tagged 0x00/0x40/0x80 and never
// collide with 0xC0/0xC1.
func parseCipherSuiteIDs(raw []byte) []int {
	seen := map[int]bool{}
	var out []int
	for i := 0; i < len(raw); {
		if raw[i] == 0xC0 || raw[i] == 0xC1 {
			if i+1 < len(raw) {
				id := int(raw[i+1])
				// Standard cipher suite IDs are 0-19; OEM suites are >=128.
				// Anything in between is a misread boundary/padding byte.
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

// CipherSuiteName returns a short algorithm description for the standard cipher
// suite IDs (IPMI 2.0 Table 22-19), used to flag weak/unencrypted suites.
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

// AuthAlgosForCiphers maps advertised cipher suite IDs to the distinct RAKP
// auth algorithms they use, so RAKP probing can negotiate an algorithm the BMC
// actually accepts. Standard suites: 1-5 = HMAC-SHA1, 6-14 = HMAC-MD5,
// 15-19 = HMAC-SHA256. Order prefers SHA1 (hashcat -m 7300), then SHA256, then
// MD5. Returns nil when ids carries no standard suite (caller falls back).
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

// CipherAlgos is the (auth, integrity, confidentiality) algorithm triple a
// cipher suite negotiates in the RMCP+ Open Session request.
type CipherAlgos struct {
	Suite     int  `json:"suite"`
	Auth      byte `json:"auth"`
	Integrity byte `json:"integrity"`
	Conf      byte `json:"conf"`
}

// CipherAlgosFor returns the algorithm triple for a standard cipher suite ID.
// Hardened BMCs (e.g. OpenBMC advertising only suite 17) reject an Open Session
// that offers integrity/confidentiality None, so RAKP probing must offer the
// suite's real integrity+conf algorithms to get a RAKP-2 back.
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

// CipherTriples returns the cipher-algo triples to try for RAKP, ordered by the
// advertised suite IDs (full-crypto suites first for hardened BMCs). When ids is
// empty it falls back to a broad default set covering SHA1/SHA256/MD5.
func CipherTriples(ids []int) []CipherAlgos {
	order := ids
	if len(order) == 0 {
		order = []int{17, 3, 16, 2, 1, 8, 7, 6, 12, 11, 15, 9, 10, 13, 14, 4, 5, 18, 19}
	}
	// Prefer full-crypto suites (they double as the ones hardened BMCs accept).
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

// CipherSuiteWeak reports whether a cipher suite offers no confidentiality or no
// integrity (or is cipher 0). Suites 3 and 17 provide full crypto.
func CipherSuiteWeak(id int) bool {
	switch id {
	case 3, 8, 17:
		return false
	default:
		return true
	}
}

// extractIPMIData returns the data after the completion code, plus the completion
// code, from an IPMB response envelope (rqAddr netfn|lun csum rsAddr rqSeq cmd cc
// data csum2), anchoring on the response header (rsAddr=0x81 followed by
// rqAddr=0x20). The trailing csum2 is stripped, as extractV15Payload does for 1.5
// sessions; keeping it over-reads every response by one byte and corrupts the tail
// of any raw field taken from the reply.
func extractIPMIData(reply []byte) (data []byte, cc byte, ok bool) {
	for i := 0; i+7 < len(reply); i++ {
		if (reply[i] == 0x81 || reply[i] == 0x8c) && i+3 < len(reply) && reply[i+3] == 0x20 {
			end := len(reply) - 1 // strip csum2 (trailing IPMB response checksum)
			if end > i+7 {
				return reply[i+7 : end], reply[i+6], true
			}
			return nil, reply[i+6], true
		}
	}
	return nil, 0, false
}
