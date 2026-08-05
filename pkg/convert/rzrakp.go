package convert

import (
	"encoding/binary"
	"encoding/hex"
	"strings"

	"github.com/runZeroInc/oobscan/pkg/ipmi"
	"github.com/runZeroInc/oobscan/pkg/output"
)

type rakpEntry struct {
	Username string
	Cipher   string
	Algo     string
	Salt     string
	MAC      string
	Redacted bool
}

func (e *rakpEntry) authAlgo() byte {
	switch e.Algo {
	case "sha1":
		return ipmi.RAKPHMACSHA1
	case "md5":
		return ipmi.RAKPHMACMD5
	case "sha256":
		return ipmi.RAKPHMACSHA256
	}
	return 0
}

func (e *rakpEntry) result() *ipmi.RAKPResult {
	if e.Redacted {
		return nil
	}
	salt, err := hex.DecodeString(e.Salt)
	if err != nil {
		return nil
	}
	mac, err := hex.DecodeString(e.MAC)
	if err != nil || len(mac) == 0 {
		return nil
	}

	const fixed = 58
	if len(salt) < fixed || salt[56] != 0x14 || int(salt[57]) != len(salt)-fixed {
		return nil
	}
	return &ipmi.RAKPResult{
		Username:   string(salt[fixed:]),
		AuthAlgo:   e.authAlgo(),
		ClientSID:  binary.LittleEndian.Uint32(salt[0:4]),
		BMCSID:     binary.LittleEndian.Uint32(salt[4:8]),
		ClientRand: salt[8:24],
		BMCRand:    salt[24:40],
		BMCGUID:    salt[40:56],
		RAKPHash:   mac,
	}
}

func (h *rzHost) rakpRecords() []output.RAKPRecord {
	var out []output.RAKPRecord
	for i := range h.services {
		s := &h.services[i]
		raw := s.get("ipmi.rakp.hashes")
		if raw == "" {
			continue
		}
		cracked := parseUserMap(s.get("ipmi.rakp.cracked"))
		passwords := parseUserMap(s.get("ipmi.rakp.passwords"))
		for _, e := range parseRAKPHashes(raw) {
			user := displayUser(e.Username)
			rec := output.RAKPRecord{
				Username: user,
				AuthAlgo: e.authAlgo(),
				Redacted: e.Redacted,
			}
			if rr := e.result(); rr != nil {
				rec.ClientSID = rr.ClientSID
				rec.BMCSID = rr.BMCSID
				rec.ClientRand = hex.EncodeToString(rr.ClientRand)
				rec.BMCRand = hex.EncodeToString(rr.BMCRand)
				rec.BMCGUID = hex.EncodeToString(rr.BMCGUID)
				rec.RAKPHash = hex.EncodeToString(rr.RAKPHash)
				rec.Hashcat = rr.Hashcat()
			} else if !e.Redacted {

				rec.RAKPHash = e.MAC
			}

			if pw, ok := passwords[e.Username]; ok && pw != "" && !strings.Contains(pw, "redacted") {
				rec.Cracked = pw
			} else if kind, ok := cracked[e.Username]; ok {
				if kind == "" {
					kind = "yes"
				}
				rec.Cracked = kind
			}
			out = append(out, rec)
		}
	}
	return out
}

func parseRAKPHashes(val string) []rakpEntry {
	var out []rakpEntry
	for _, entry := range tabValues(val) {
		if e, ok := parseRAKPEntry(entry); ok {
			out = append(out, e)
		}
	}
	return out
}

func parseRAKPEntry(entry string) (rakpEntry, bool) {
	if before, after, ok := strings.Cut(entry, "$"); ok {
		left, right := before, after
		user, cipher := "", ""
		if c := strings.LastIndexByte(left, ':'); c >= 0 {
			user, cipher = left[:c], left[c+1:]
		} else {
			cipher = left
		}
		if strings.Contains(right, "redacted") {
			return rakpEntry{Username: user, Cipher: cipher, Algo: algoForCipher(cipher), Redacted: true}, true
		}
		salt, mac, ok := splitSaltMAC(right)
		if !ok {
			return rakpEntry{}, false
		}
		algo := algoForMAC(mac)
		if algo == "" {
			return rakpEntry{}, false
		}
		return rakpEntry{Username: user, Cipher: cipher, Algo: algo, Salt: salt, MAC: mac}, true
	}

	c2 := strings.LastIndexByte(entry, ':')
	if c2 < 0 {
		return rakpEntry{}, false
	}
	rest, mac := entry[:c2], entry[c2+1:]
	c1 := strings.LastIndexByte(rest, ':')
	if c1 < 0 {
		return rakpEntry{}, false
	}
	user, salt := rest[:c1], rest[c1+1:]
	if !isHex(salt) || !isHex(mac) {
		return rakpEntry{}, false
	}
	algo := algoForMAC(mac)
	if algo == "" {
		return rakpEntry{}, false
	}
	return rakpEntry{Username: user, Algo: algo, Salt: salt, MAC: mac}, true
}

func splitSaltMAC(body string) (salt, mac string, ok bool) {
	c := strings.LastIndexByte(body, ':')
	if c < 0 {
		return "", "", false
	}
	salt, mac = body[:c], body[c+1:]
	if !isHex(salt) || !isHex(mac) {
		return "", "", false
	}
	return salt, mac, true
}

func algoForMAC(machex string) string {
	switch len(machex) {
	case 40:
		return "sha1"
	case 32:
		return "md5"
	case 64:
		return "sha256"
	}
	return ""
}

func algoForCipher(cipher string) string {
	switch strings.TrimSpace(cipher) {
	case "1":
		return "sha1"
	case "2":
		return "md5"
	case "3":
		return "sha256"
	}
	return ""
}

func isHex(s string) bool {
	if s == "" || len(s)%2 != 0 {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}

func parseUserMap(val string) map[string]string {
	out := map[string]string{}
	for _, entry := range tabValues(val) {

		c := strings.LastIndexByte(entry, ':')
		if c < 0 {
			out[entry] = ""
			continue
		}
		out[entry[:c]] = entry[c+1:]
	}
	return out
}

func displayUser(u string) string {
	if u == "<empty>" {
		return ""
	}
	return u
}
