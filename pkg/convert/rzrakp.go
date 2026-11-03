package convert

import (
	"encoding/binary"
	"encoding/hex"
	"strings"

	"github.com/runZeroInc/oobscan/pkg/ipmi"
	"github.com/runZeroInc/oobscan/pkg/output"
)

// runZero stores a captured RAKP-2 exchange collapsed into one string per account
// (HMAC input plus HMAC); the native schema stores it decomposed into the two
// session ids, the two nonces, the BMC GUID and the username.
//
// The decomposition is recoverable because the salt is exactly the concatenation
// SIDc(LE) | SIDm(LE) | Rc | Rm | GUIDm | 0x14 | ulen | username (see
// ipmi.RAKPResult.Salt, the single source of truth for the layout), so a converted
// record carries real RAKP rows rather than an opaque blob.
//
// Exports frequently ship "<redacted>" in place of the salt and HMAC. Those rows
// are still emitted, flagged Redacted, so the fact that the BMC leaked a hash
// survives even when the hash does not.

// rakpEntry is one parsed entry of an ipmi.rakp.hashes attribute.
type rakpEntry struct {
	Username string
	Cipher   string // RAKP auth cipher id as reported (may be empty on legacy rows)
	Algo     string // sha1 / md5 / sha256, derived from the HMAC length
	Salt     string // hex
	MAC      string // hex
	Redacted bool   // the source withheld the salt and HMAC
}

// authAlgo maps the parsed algorithm name onto the IPMI RAKP auth algorithm id.
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

// result reconstructs the oobscan RAKPResult behind this entry, or nil when the
// salt is absent or does not have the canonical RAKP-2 layout.
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
	// 4+4 session ids, 16+16 nonces, 16 GUID, the 0x14 role byte and the username
	// length byte: 58 fixed bytes ahead of the username.
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

// usesSMCFixedKey reports whether this RAKP-2 HMAC was computed with the known
// Supermicro/ATEN fixed key rather than the account password, which makes the
// leaked hash forgeable. Verification is delegated to oobscan's own check.
func (e *rakpEntry) usesSMCFixedKey() bool {
	rr := e.result()
	return rr != nil && rr.UsesSMCRAKPFixedKey()
}

// rakpRecords projects every captured RAKP-2 exchange on the host onto oobscan
// RAKP rows.
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
				// The salt did not decompose: keep the HMAC so the row still says
				// which account leaked, even though it is not re-crackable here.
				rec.RAKPHash = e.MAC
			}
			// oobscan's `cracked` holds the recovered password. runZero exports the
			// password separately from a classification ("default", "common", ...)
			// and redacts the password by default, so fall back to the class marker
			// rather than dropping the fact that the account was recovered.
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

// parseRAKPHashes parses an ipmi.rakp.hashes attribute (tab joined) into its
// entries. Each entry looks like:
//
//	displayUser:cipher$salthex:machex     (current format)
//	displayUser:cipher$<redacted>         (secrets withheld at export)
//	displayUser:salthex:machex            (legacy, no cipher)
//
// A username may itself contain ':', so the salt and HMAC are peeled from the
// right and the cipher from the position just before '$'.
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
	if dollar := strings.IndexByte(entry, '$'); dollar >= 0 {
		left, right := entry[:dollar], entry[dollar+1:]
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

	// Legacy "user:salt:mac": peel the HMAC and salt from the right.
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

// splitSaltMAC splits a "salthex:machex" body, validating both halves as hex.
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

// algoForMAC maps an HMAC hex length to its RAKP authentication algorithm.
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

// algoForCipher maps the reported RAKP auth cipher id to its algorithm. It is
// the only signal left when the HMAC itself was withheld.
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

// isHex reports whether s is a non-empty even-length hex string.
func isHex(s string) bool {
	if s == "" || len(s)%2 != 0 {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}

// parseUserMap parses a tab-separated "user:value" attribute into a map.
func parseUserMap(val string) map[string]string {
	out := map[string]string{}
	for _, entry := range tabValues(val) {
		// Split on the last colon, not the first: an IPMI username may contain a
		// colon, and the value never does.
		c := strings.LastIndexByte(entry, ':')
		if c < 0 {
			out[entry] = ""
			continue
		}
		out[entry[:c]] = entry[c+1:]
	}
	return out
}

// displayUser normalizes runZero's "<empty>" placeholder to an empty string,
// which is how oobscan spells the IPMI null user.
func displayUser(u string) string {
	if u == "<empty>" {
		return ""
	}
	return u
}
