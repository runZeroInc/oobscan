package ipmi

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/md5"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"hash/crc32"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/runZeroInc/oobscan/pkg/guid"
)

const (
	NetFnSMCOEM            byte = 0x30
	CmdSMCFileTransactions byte = 0xA0

	smcSubPrepDownload     byte = 0x05
	smcSubPrepDownloadDone byte = 0x06
	smcSubFileDownload     byte = 0x07
	smcSubFileDownloadDone byte = 0x08

	SMCFileTypeConfig byte = 0x01

	smcMaxDownloadChunk = 1500
	smcMaxUploadChunk   = 1470

	smcDefDownloadChunk = 1400
	smcDefUploadChunk   = 1400

	smcArchivePrefix = "./preserve_config/"
)

type SMCConfigCipher string

const (
	SMCCipherAES128CBC SMCConfigCipher = "aes-128-cbc"
	SMCCipher3DESCBC   SMCConfigCipher = "3des-ede3-cbc"
)

var SMCObfuscationIV = []byte{
	0x2e, 0x7b, 0x4c, 0x71, 0xd0, 0x45, 0x2a, 0x6b,
	0x89, 0xb8, 0x9a, 0xf9, 0x6a, 0xb3, 0xc6, 0xca,
}

type SMCCryptoProfile struct {
	Cipher SMCConfigCipher
	Key    []byte
	IV     []byte
}

var smcCryptoProfiles = map[string]SMCCryptoProfile{

	"X11": {SMCCipherAES128CBC, mustDecodeHex("a22874547aba7a32cf8ac49c1896722f"), SMCObfuscationIV},

	"X10": {SMCCipher3DESCBC, mustDecodeHex("f1da33a298120612060792ffaa998811998877445588aabb"), make([]byte, 8)},

	"H13": {SMCCipherAES128CBC, mustDecodeHex("ba8cc4a492d2c24aafa2143c48de8a2f"), SMCObfuscationIV},
}

func mustDecodeHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic("smcbackup: bad built-in hex: " + err.Error())
	}
	return b
}

func SMCCryptoProfileForGeneration(gen string) (SMCCryptoProfile, bool) {
	p, ok := smcCryptoProfiles[strings.ToUpper(strings.TrimSpace(gen))]
	if !ok {
		return SMCCryptoProfile{}, false
	}
	return SMCCryptoProfile{
		Cipher: p.Cipher,
		Key:    append([]byte(nil), p.Key...),
		IV:     append([]byte(nil), p.IV...),
	}, true
}

func smcNewBlock(cipher SMCConfigCipher, key []byte) (cipherBlock, error) {
	switch cipher {
	case SMCCipher3DESCBC:
		return des.NewTripleDESCipher(key)
	case SMCCipherAES128CBC, "":
		return aes.NewCipher(key)
	default:
		return nil, fmt.Errorf("unsupported config cipher %q", cipher)
	}
}

type cipherBlock = interface {
	BlockSize() int
	Encrypt(dst, src []byte)
	Decrypt(dst, src []byte)
}

type SMCGenerationResult struct {
	Generation  string `json:"generation"`
	ModelPrefix string `json:"modelPrefix"`
	GUIDHex     string `json:"guidHex"`
}

func (s *CmdSess) SMCGeneration(ctx context.Context) (*SMCGenerationResult, error) {
	if s == nil || s.runner == nil {
		return nil, fmt.Errorf("session closed")
	}
	cc, data, err := s.runner.Exec(NetFnApp, CmdGetSystemGUID, nil)
	if err != nil {
		return nil, err
	}
	if cc != 0x00 {
		return nil, fmt.Errorf("get system guid cc=0x%02x", cc)
	}
	if len(data) < 16 {
		return nil, fmt.Errorf("get system guid short reply (%d bytes)", len(data))
	}
	g := guid.Decode(data[:16])
	res := &SMCGenerationResult{GUIDHex: g.Hex}
	if g.Fields != nil {
		res.ModelPrefix = g.Fields["model_prefix"]
	}
	res.Generation = guid.SMCGenerationFromModelPrefix(res.ModelPrefix)
	return res, nil
}

type SMCConfigXfer struct {
	sess          *CmdSess
	UploadChunk   int
	DownloadChunk int
	PollInterval  time.Duration
	PollDeadline  time.Duration
}

func NewSMCConfigXfer(sess *CmdSess) *SMCConfigXfer {
	return &SMCConfigXfer{
		sess:          sess,
		UploadChunk:   smcDefUploadChunk,
		DownloadChunk: smcDefDownloadChunk,
		PollInterval:  time.Second,
		PollDeadline:  3 * time.Minute,
	}
}

func (x *SMCConfigXfer) sub(data []byte) (byte, []byte, error) {
	if x == nil || x.sess == nil {
		return 0xff, nil, fmt.Errorf("session closed")
	}
	return x.sess.ExecRaw(NetFnSMCOEM, CmdSMCFileTransactions, data)
}

func (x *SMCConfigXfer) Export(ctx context.Context, ftype byte) ([]byte, error) {
	chunk := x.DownloadChunk
	if chunk <= 0 || chunk > smcMaxDownloadChunk {
		chunk = smcDefDownloadChunk
	}

	cc, out, err := x.sub([]byte{smcSubPrepDownload, ftype})
	if err != nil {
		return nil, fmt.Errorf("PrepareFileDownload: %w", err)
	}
	if cc != 0x00 {
		return nil, fmt.Errorf("PrepareFileDownload cc=0x%02x (%s)", cc, smcCCName(cc))
	}
	if len(out) < 2 {
		return nil, fmt.Errorf("PrepareFileDownload short reply (%d bytes)", len(out))
	}
	rid := binary.LittleEndian.Uint16(out[:2])
	ridLo, ridHi := byte(rid), byte(rid>>8)
	reportCommandProgress(ctx, "smcbackup: reservation 0x%04x (type 0x%02x->0x%02x)", rid, ftype, ftype|0x80)

	var size uint32
	interval := x.PollInterval
	if interval <= 0 {
		interval = time.Second
	}
	deadline := time.Now().Add(x.PollDeadline)
	for {
		cc, out, err = x.sub([]byte{smcSubPrepDownloadDone, ridLo, ridHi})
		if err != nil {
			return nil, fmt.Errorf("PrepareFileDownloadDone: %w", err)
		}
		if cc != 0x00 {
			return nil, fmt.Errorf("PrepareFileDownloadDone cc=0x%02x (%s)", cc, smcCCName(cc))
		}
		if len(out) < 5 {
			return nil, fmt.Errorf("PrepareFileDownloadDone short reply (%d bytes)", len(out))
		}
		if out[0] == 0 {
			size = binary.LittleEndian.Uint32(out[1:5])
			break
		}
		reportCommandProgress(ctx, "smcbackup: still generating")
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("export never became ready within %s", x.PollDeadline)
		}
		if err := sleepCtx(ctx, interval); err != nil {
			return nil, err
		}
	}
	reportCommandProgress(ctx, "smcbackup: ready, %d bytes", size)
	if size == 0 {
		return nil, fmt.Errorf("BMC reported a zero-byte export")
	}

	buf := make([]byte, 0, size)
	for uint32(len(buf)) < size {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		off := uint32(len(buf))
		want := min(size-off, uint32(chunk))
		req := []byte{smcSubFileDownload, ridLo, ridHi}
		req = appendLE32(req, off)
		req = appendLE16(req, uint16(want))
		cc, out, err = x.sub(req)
		if err != nil {
			return nil, fmt.Errorf("FileDownload off=%d: %w", off, err)
		}
		if cc != 0x00 {
			return nil, fmt.Errorf("FileDownload off=%d cc=0x%02x (%s)", off, cc, smcCCName(cc))
		}
		if len(out) == 0 {
			return nil, fmt.Errorf("FileDownload off=%d returned 0 bytes", off)
		}

		n := min(uint32(len(out)), want)
		buf = append(buf, out[:n]...)
		reportCommandProgress(ctx, "smcbackup: %d/%d bytes", len(buf), size)
	}

	if cc, _, err := x.sub([]byte{smcSubFileDownloadDone, ridLo, ridHi}); err == nil && cc != 0x00 {
		reportCommandProgress(ctx, "smcbackup: FileDownloadDone cc=0x%02x (BMC /tmp file may linger)", cc)
	}
	if uint32(len(buf)) != size {
		return nil, fmt.Errorf("size mismatch: got %d expected %d", len(buf), size)
	}
	return buf, nil
}

func SMCContainerWrap(pt, key, iv []byte, cipherKind SMCConfigCipher) ([]byte, error) {
	block, err := smcNewBlock(cipherKind, key)
	if err != nil {
		return nil, err
	}
	if len(iv) != block.BlockSize() {
		return nil, fmt.Errorf("iv must be %d bytes for %s", block.BlockSize(), cipherKind)
	}
	body := make([]byte, 4+len(pt))
	binary.LittleEndian.PutUint32(body[:4], crc32.ChecksumIEEE(pt))
	copy(body[4:], pt)
	body = pkcs7Pad(body, block.BlockSize())
	out := make([]byte, len(body))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(out, body)
	return out, nil
}

func SMCContainerUnwrap(ct, key, iv []byte, cipherKind SMCConfigCipher) ([]byte, bool, error) {
	block, err := smcNewBlock(cipherKind, key)
	if err != nil {
		return nil, false, err
	}
	if len(iv) != block.BlockSize() {
		return nil, false, fmt.Errorf("iv must be %d bytes for %s", block.BlockSize(), cipherKind)
	}
	if len(ct) == 0 || len(ct)%block.BlockSize() != 0 {
		return nil, false, fmt.Errorf("ciphertext is not a whole number of %d-byte blocks", block.BlockSize())
	}
	raw := make([]byte, len(ct))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(raw, ct)
	raw = pkcs7Unpad(raw, block.BlockSize())
	if len(raw) < 4 {
		return nil, false, fmt.Errorf("decrypted output too short (wrong key?)")
	}
	want := binary.LittleEndian.Uint32(raw[:4])
	pt := raw[4:]
	ok := crc32.ChecksumIEEE(pt) == want
	return pt, ok, nil
}

func SMCLooksGzip(b []byte) bool {
	return len(b) >= 2 && b[0] == 0x1f && b[1] == 0x8b
}

func SMCLooksOpenSSLSalted(b []byte) bool {
	return len(b) >= 16 && string(b[:8]) == "Salted__"
}

var smcOpenSSLMagic = []byte("Salted__")

var SMCConfigInnerPassword = []byte("CKSAM1SUCKSAM1SUASMUCIKSASMUCIKS")

var smcATENInnerMagic = []byte("ATEN\x01\x00")

func evpBytesToKeyMD5(pass, salt []byte, keyLen, ivLen int) (key, iv []byte) {
	var out, prev []byte
	for len(out) < keyLen+ivLen {
		h := md5.New()
		h.Write(prev)
		h.Write(pass)
		h.Write(salt)
		prev = h.Sum(nil)
		out = append(out, prev...)
	}
	return out[:keyLen], out[keyLen : keyLen+ivLen]
}

func SMCOpenSSLSaltedUnwrap(blob, password []byte) (pt []byte, looksGzip bool, err error) {
	if !SMCLooksOpenSSLSalted(blob) {
		return nil, false, fmt.Errorf("not an openssl Salted__ blob")
	}
	salt := blob[8:16]
	ct := blob[16:]
	if len(ct) == 0 || len(ct)%aes.BlockSize != 0 {
		return nil, false, fmt.Errorf("ciphertext is not a whole number of %d-byte blocks", aes.BlockSize)
	}
	key, iv := evpBytesToKeyMD5(password, salt, 32, aes.BlockSize)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, false, err
	}
	raw := make([]byte, len(ct))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(raw, ct)
	raw = pkcs7Unpad(raw, aes.BlockSize)

	raw = bytes.TrimPrefix(raw, smcATENInnerMagic)
	return raw, SMCLooksGzip(raw), nil
}

func SMCOpenSSLSaltedWrap(pt, password []byte) ([]byte, error) {
	salt := make([]byte, 8)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	key, iv := evpBytesToKeyMD5(password, salt, 32, aes.BlockSize)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	inner := pt
	if !bytes.HasPrefix(inner, smcATENInnerMagic) {
		inner = append(append([]byte{}, smcATENInnerMagic...), pt...)
	}
	padded := pkcs7Pad(inner, aes.BlockSize)
	ct := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ct, padded)
	out := append(append([]byte{}, smcOpenSSLMagic...), salt...)
	return append(out, ct...), nil
}

func pkcs7Pad(b []byte, block int) []byte {
	n := block - (len(b) % block)
	if n == 0 {
		n = block
	}
	return append(b, bytes.Repeat([]byte{byte(n)}, n)...)
}

func pkcs7Unpad(b []byte, block int) []byte {
	if len(b) == 0 || len(b)%block != 0 {
		return b
	}
	n := int(b[len(b)-1])
	if n < 1 || n > block || n > len(b) {
		return b
	}
	for _, c := range b[len(b)-n:] {
		if int(c) != n {
			return b
		}
	}
	return b[:len(b)-n]
}

func smcMemberKey(name string) string {
	n := strings.TrimPrefix(name, smcArchivePrefix)
	n = strings.TrimPrefix(n, "preserve_config/")
	return strings.TrimPrefix(n, "/")
}

type smcMember struct {
	hdr  *tar.Header
	data []byte
}

func smcReadArchive(gz []byte) ([]smcMember, error) {
	zr, err := gzip.NewReader(bytes.NewReader(gz))
	if err != nil {
		return nil, fmt.Errorf("gzip: %w (wrong key, or not a decrypted backup?)", err)
	}
	defer zr.Close()
	tr := tar.NewReader(zr)
	var out []smcMember
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("tar: %w", err)
		}
		var data []byte
		if hdr.Typeflag == tar.TypeReg {
			data, err = io.ReadAll(tr)
			if err != nil {
				return nil, fmt.Errorf("tar read %s: %w", hdr.Name, err)
			}
		}
		h := *hdr
		out = append(out, smcMember{hdr: &h, data: data})
	}
	return out, nil
}

func SMCArchiveMemberNames(gz []byte) ([]string, error) {
	members, err := smcReadArchive(gz)
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(members))
	for _, m := range members {
		names = append(names, m.hdr.Name)
	}
	sort.Strings(names)
	return names, nil
}

func SMCArchiveMember(gz []byte, key string) ([]byte, bool, error) {
	members, err := smcReadArchive(gz)
	if err != nil {
		return nil, false, err
	}
	for _, m := range members {
		if smcMemberKey(m.hdr.Name) == key {
			return m.data, true, nil
		}
	}
	return nil, false, nil
}

func smcCCName(cc byte) string {
	switch cc {
	case 0x00:
		return "ok"
	case 0x80:
		return "priv-level-not-available"
	case 0xC0:
		return "node-busy"
	case 0xC5:
		return "reservation-cancelled/stale-id"
	case 0xC7:
		return "req-data-length-invalid"
	case 0xCC:
		return "invalid-data-field/offset-out-of-range"
	case 0xD4:
		return "insufficient-privilege/lockdown"
	case 0xD5:
		return "not-supported-in-present-state"
	default:
		return "unknown"
	}
}

func appendLE16(b []byte, v uint16) []byte {
	return append(b, byte(v), byte(v>>8))
}

func appendLE32(b []byte, v uint32) []byte {
	return append(b, byte(v), byte(v>>8), byte(v>>16), byte(v>>24))
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}
