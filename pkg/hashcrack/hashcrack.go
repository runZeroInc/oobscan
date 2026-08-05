package hashcrack

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/runZeroInc/oobscan/pkg/ipmi"
)

const (
	AlgoSHA1   byte = 1
	AlgoMD5    byte = 2
	AlgoSHA256 byte = 3
)

func AlgoName(a byte) string {
	switch a {
	case AlgoSHA1:
		return "sha1"
	case AlgoMD5:
		return "md5"
	case AlgoSHA256:
		return "sha256"
	}
	return "?"
}

func AlgoFromName(s string) (byte, bool) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "sha1", "1", "7300":
		return AlgoSHA1, true
	case "md5", "2":
		return AlgoMD5, true
	case "sha256", "3":
		return AlgoSHA256, true
	}
	return 0, false
}

var AllAlgos = []byte{AlgoMD5, AlgoSHA1, AlgoSHA256}

var smcRAKPFixedKey = mustHex("fab979d849be933dd0c41fd2c9d77a30aa8d3f50") //nolint:gosec // this is a secret, but not OUR secret

const SMCRAKPOEMKeyLabel = "(SMC-RAKP-OEM-KEY)"

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func MatchSMCRAKPFixedKey(h *Hash) bool {
	if h == nil || len(h.MAC) == 0 {
		return false
	}
	ctor := hashCtor(h.Algo)
	if ctor == nil {
		return false
	}
	mac := hmac.New(ctor, smcRAKPFixedKey)
	mac.Write(h.Salt)
	return hmac.Equal(mac.Sum(nil), h.MAC)
}

func labelSMCRAKPFixedKey(h *Hash) {
	if MatchSMCRAKPFixedKey(h) {

		h.SMCFixedKey = true
	}
}

func ParseCiphers(tokens []string) (want map[byte]bool, unknown []string) {
	want = map[byte]bool{}
	for _, t := range tokens {
		if t = strings.TrimSpace(t); t == "" {
			continue
		}
		if b, ok := AlgoFromName(t); ok {
			want[b] = true
		} else {
			unknown = append(unknown, t)
		}
	}
	if len(want) == 0 {
		return nil, unknown
	}
	return want, unknown
}

func hashCtor(a byte) func() hash.Hash {
	switch a {
	case AlgoSHA1:
		return sha1.New
	case AlgoMD5:
		return md5.New
	case AlgoSHA256:
		return sha256.New
	}
	return nil
}

func macLen(a byte) int {
	switch a {
	case AlgoSHA1:
		return sha1.Size
	case AlgoMD5:
		return md5.Size
	case AlgoSHA256:
		return sha256.Size
	}
	return 0
}

func algoCrackCost(a byte) int {

	switch a {
	case AlgoMD5:
		return 1
	case AlgoSHA1:
		return 2
	case AlgoSHA256:
		return 3
	default:
		return 99
	}
}

type Hash struct {
	GID      int
	IP       string
	Vendor   string
	Product  string
	Version  string
	Services string
	Source   string
	Username string
	Algo     byte
	Salt     []byte
	MAC      []byte

	SMCFixedKey bool
}

func (h *Hash) SaltHashLine() string { return fmt.Sprintf("%x:%x", h.Salt, h.MAC) }

func (h *Hash) JohnLine() string { return fmt.Sprintf("$rakp$%x$%x", h.Salt, h.MAC) }

type Tally map[byte]int

func (t Tally) Total() int { return t[AlgoSHA1] + t[AlgoMD5] + t[AlgoSHA256] }

type scanRec struct {
	Host     string `json:"host"`
	Identity struct {
		Vendor     string         `json:"vendor"`
		Product    string         `json:"product"`
		Generation string         `json:"generation"`
		Attributes map[string]any `json:"attributes"`
	} `json:"identity"`
	Findings []map[string]any `json:"findings"`
	RAKP     []scanRAKPEntry  `json:"rakp"`
}

type scanRAKPEntry struct {
	Username   string
	AuthAlgo   int
	ClientSID  int64
	BMCSID     int64
	ClientRand string
	BMCRand    string
	BMCGUID    string
	RAKPHash   string
}

func (e *scanRAKPEntry) UnmarshalJSON(b []byte) error {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}
	e.Username = rawString(raw, "username")
	e.AuthAlgo = rawInt(raw, "authAlgo", "auth_algo")
	e.ClientSID = rawInt64(raw, "clientSid", "client_sid")
	e.BMCSID = rawInt64(raw, "bmcSid", "bmc_sid")
	e.ClientRand = rawString(raw, "clientRand", "client_rand")
	e.BMCRand = rawString(raw, "bmcRand", "bmc_rand")
	e.BMCGUID = rawString(raw, "bmcGuid", "bmc_guid")
	e.RAKPHash = rawString(raw, "rakpHash", "rakp_hash")
	return nil
}

func rawString(raw map[string]json.RawMessage, keys ...string) string {
	for _, key := range keys {
		if v, ok := raw[key]; ok {
			var s string
			if json.Unmarshal(v, &s) == nil {
				return s
			}
		}
	}
	return ""
}

func rawInt(raw map[string]json.RawMessage, keys ...string) int {
	return int(rawInt64(raw, keys...))
}

func rawInt64(raw map[string]json.RawMessage, keys ...string) int64 {
	for _, key := range keys {
		if v, ok := raw[key]; ok {
			var n int64
			if json.Unmarshal(v, &n) == nil {
				return n
			}
		}
	}
	return 0
}

func attrStr(m map[string]any, key string) string {
	if m == nil {
		return ""
	}
	if v, ok := m[key]; ok && v != nil {
		return fmt.Sprint(v)
	}
	return ""
}

func firstAttrStr(m map[string]any, keys ...string) string {
	for _, key := range keys {
		if v := attrStr(m, key); v != "" {
			return v
		}
	}
	return ""
}

func findingID(f map[string]any) string {
	if v, ok := f["check"]; ok {
		return fmt.Sprint(v)
	}
	if v, ok := f["id"]; ok {
		return fmt.Sprint(v)
	}
	return ""
}

func deriveVersion(r *scanRec) string {
	for _, k := range []string{"ipmiFirmwareVersion", "iloFirmwareVersion", "redfishFirmwareVersion", "idracFirmwareVersion", "firmwareVersion", "ipmi.fw", "ilo.fw", "redfish.fw", "idrac.fw", "fw", "version"} {
		if v := attrStr(r.Identity.Attributes, k); v != "" {
			return v
		}
	}
	if r.Identity.Generation != "" {
		return r.Identity.Generation
	}
	for _, f := range r.Findings {
		if findingID(f) == "id" {
			if fl, ok := f["fields"].(map[string]any); ok {
				for _, k := range []string{"version", "fw", "generation", "firmware"} {
					if v, ok := fl[k]; ok && v != nil && fmt.Sprint(v) != "" {
						return fmt.Sprint(v)
					}
				}
			}
		}
	}
	return ""
}

func deriveServices(r *scanRec) string {
	set := map[string]struct{}{}
	for _, f := range r.Findings {
		proto, _ := f["protocol"].(string)
		port := ""
		if p, ok := f["port"]; ok && p != nil {
			port = fmt.Sprint(p)
		}
		switch {
		case proto != "" && port != "":
			set[proto+"/"+port] = struct{}{}
		case proto != "":
			set[proto] = struct{}{}
		}
	}
	if s := firstAttrStr(r.Identity.Attributes, "webScheme", "web.scheme"); s != "" {
		if p := firstAttrStr(r.Identity.Attributes, "webPort", "web.port"); p != "" {
			set[s+"/"+p] = struct{}{}
		} else {
			set[s] = struct{}{}
		}
	}
	if v := firstAttrStr(r.Identity.Attributes, "sshVersion", "ssh.version"); v != "" {
		set["ssh"] = struct{}{}
	}
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	if len(out) > 10 {
		out = out[:10]
	}
	return strings.Join(out, ",")
}

func LoadScans(paths []string, wantAlgo map[byte]bool, dedupHostUser bool) ([]*Hash, Tally, error) {
	var out []*Hash
	seenExact := map[string]struct{}{}
	bestByHostUser := map[string]*Hash{}
	tally := Tally{}
	gid := 0

	processLine := func(line []byte, base string) {
		var r scanRec
		if json.Unmarshal(line, &r) != nil {
			return
		}
		var ver, svc string
		verDone := false
		for i := range r.RAKP {
			e := &r.RAKP[i]
			a := byte(e.AuthAlgo)
			if a != AlgoSHA1 && a != AlgoMD5 && a != AlgoSHA256 {
				continue
			}
			if wantAlgo != nil && !wantAlgo[a] {
				continue
			}
			mac, err1 := hex.DecodeString(e.RAKPHash)
			cr, err2 := hex.DecodeString(e.ClientRand)
			br, err3 := hex.DecodeString(e.BMCRand)
			guid, err4 := hex.DecodeString(e.BMCGUID)
			if err1 != nil || err2 != nil || err3 != nil || err4 != nil {
				continue
			}

			if want := macLen(a); want == 0 || len(mac) != want {
				continue
			}

			rr := &ipmi.RAKPResult{
				Username:   e.Username,
				AuthAlgo:   a,
				ClientSID:  uint32(e.ClientSID),
				BMCSID:     uint32(e.BMCSID),
				ClientRand: cr,
				BMCRand:    br,
				BMCGUID:    guid,
				RAKPHash:   mac,
			}
			salt := rr.Salt()
			h := &Hash{
				GID: gid, IP: r.Host, Vendor: r.Identity.Vendor, Product: r.Identity.Product,
				Version: ver, Services: svc, Source: base, Username: e.Username,
				Algo: a, Salt: salt, MAC: mac,
			}
			labelSMCRAKPFixedKey(h)
			if dedupHostUser {
				key := r.Host + "|" + h.Username
				if prev, ok := bestByHostUser[key]; ok {

					if algoCrackCost(a) >= algoCrackCost(prev.Algo) {
						continue
					}
				}
				if !verDone {
					ver, svc, verDone = deriveVersion(&r), deriveServices(&r), true
				}
				h.Version, h.Services = ver, svc
				bestByHostUser[key] = h
				gid++
				continue
			}
			key := string(rune(a)) + string(salt) + "\x00" + string(mac)
			if _, dup := seenExact[key]; dup {
				continue
			}
			seenExact[key] = struct{}{}
			if !verDone {
				ver, svc, verDone = deriveVersion(&r), deriveServices(&r), true
			}
			h.Version, h.Services = ver, svc
			out = append(out, h)
			tally[a]++
			gid++
		}
	}
	for _, path := range paths {
		f, err := os.Open(path)
		if err != nil {
			return nil, nil, err
		}
		base := filepath.Base(path)

		var src io.Reader = f
		var gz *gzip.Reader
		if strings.HasSuffix(strings.ToLower(path), ".gz") {
			gz, err = gzip.NewReader(f)
			if err != nil {
				f.Close()
				return nil, nil, fmt.Errorf("%s: gzip: %w", path, err)
			}
			src = gz
		}

		rdr := bufio.NewReaderSize(src, 1<<20)
		var readErr error
		for {
			line, rerr := rdr.ReadBytes('\n')
			if trimmed := bytes.TrimRight(line, "\r\n"); len(trimmed) > 0 {
				processLine(trimmed, base)
			}
			if rerr != nil {
				if rerr != io.EOF {
					readErr = rerr
				}
				break
			}
		}
		if gz != nil {
			gz.Close()
		}
		f.Close()
		if readErr != nil {
			return nil, nil, fmt.Errorf("%s: %w", path, readErr)
		}
	}
	if dedupHostUser {
		for _, h := range bestByHostUser {
			out = append(out, h)
			tally[h.Algo]++
		}
		sort.Slice(out, func(i, j int) bool {
			if out[i].IP != out[j].IP {
				return out[i].IP < out[j].IP
			}
			if out[i].Username != out[j].Username {
				return out[i].Username < out[j].Username
			}
			return out[i].Algo < out[j].Algo
		})
		for i := range out {
			out[i].GID = i
		}
	}
	return out, tally, nil
}

var credFieldKeys = []string{
	"password", "pass", "cracked", "credential",
	"username", "user", "usernames",
}

func HarvestSeeds(paths []string) ([]string, error) {
	seen := map[string]struct{}{}
	var out []string
	add := func(v string) {
		v = strings.TrimSpace(v)
		if v == "" {
			return
		}

		if v == SMCRAKPOEMKeyLabel || strings.HasPrefix(v, "<") || strings.HasPrefix(v, "(") {
			return
		}
		if _, dup := seen[v]; dup {
			return
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}

	processLine := func(line []byte) {
		var r scanRec
		if json.Unmarshal(line, &r) != nil {
			return
		}
		for i := range r.RAKP {
			add(r.RAKP[i].Username)
		}
		for _, f := range r.Findings {
			fl, ok := f["fields"].(map[string]any)
			if !ok {
				continue
			}
			for _, key := range credFieldKeys {
				v, ok := fl[key]
				if !ok || v == nil {
					continue
				}
				s := fmt.Sprint(v)

				if key == "usernames" && strings.Contains(s, ",") {
					for part := range strings.SplitSeq(s, ",") {
						add(part)
					}
					continue
				}
				add(s)
			}
		}
	}

	for _, path := range paths {
		f, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		var src io.Reader = f
		var gz *gzip.Reader
		if strings.HasSuffix(strings.ToLower(path), ".gz") {
			gz, err = gzip.NewReader(f)
			if err != nil {
				f.Close()
				return nil, fmt.Errorf("%s: gzip: %w", path, err)
			}
			src = gz
		}
		rdr := bufio.NewReaderSize(src, 1<<20)
		var readErr error
		for {
			line, rerr := rdr.ReadBytes('\n')
			if trimmed := bytes.TrimRight(line, "\r\n"); len(trimmed) > 0 {
				processLine(trimmed)
			}
			if rerr != nil {
				if rerr != io.EOF {
					readErr = rerr
				}
				break
			}
		}
		if gz != nil {
			gz.Close()
		}
		f.Close()
		if readErr != nil {
			return nil, fmt.Errorf("%s: %w", path, readErr)
		}
	}
	return out, nil
}
