package ipmi

import (
	"context"
	"testing"
)

// fruWalkRunner answers FRU device 0 with a tiny valid FRU and reports every other
// device id as unsupported, counting how many device ids the walk touched.
type fruWalkRunner struct {
	probed  map[byte]int
	touched int
}

func (r *fruWalkRunner) Close() {}

func (r *fruWalkRunner) Exec(netfn, cmd byte, data []byte) (byte, []byte, error) {
	if netfn != NetFnStorage || len(data) == 0 {
		return 0xc1, nil, nil
	}
	dev := data[0]
	switch cmd {
	case CmdGetFRUInventoryInfo:
		if r.probed == nil {
			r.probed = map[byte]int{}
		}
		r.probed[dev]++
		r.touched++
		if dev != 0 {
			return 0xcb, nil, nil // unsupported device
		}
		// Device 0: 16 bytes, byte-addressed.
		return 0x00, []byte{16, 0, 0x00}, nil
	case CmdReadFRUData:
		if dev != 0 {
			return 0xcb, nil, nil
		}
		// A common-header-only FRU with no areas parses to zero fields: the shape that
		// makes an unbounded walk run all 256 ids.
		return 0x00, append([]byte{16}, make([]byte, 16)...), nil
	}
	return 0xc1, nil, nil
}

// Looping deviceID 0..255 and stopping only on maxFields blind-probes all 256 ids when
// device 0 yields few fields, each costing a round trip and, on a non-answering BMC, a
// full op timeout -- enough to exhaust the post-auth budget before FRU lands.
func TestCollectFRUBoundsTheDeviceWalk(t *testing.T) {
	r := &fruWalkRunner{}
	if _, err := collectFRU(context.Background(), r, 64); err != nil {
		t.Fatalf("collectFRU: %v", err)
	}
	// Device 0 plus at most the miss run: nowhere near 256.
	if r.touched > 1+fruMaxConsecutiveMisses {
		t.Errorf("walk touched %d device ids, want <= %d (device 0 + %d misses)",
			r.touched, 1+fruMaxConsecutiveMisses, fruMaxConsecutiveMisses)
	}
	if r.probed[0] == 0 {
		t.Error("device 0 was never probed; the baseboard FRU must always be read")
	}
	if r.touched >= 256 {
		t.Error("the walk still runs the full 0..255 device space")
	}
}

// fruManyDevicesRunner answers every device with a tiny valid FRU, so the walk is
// bounded by the device-id cap rather than by a run of misses.
type fruManyDevicesRunner struct{ touched int }

func (r *fruManyDevicesRunner) Close() {}

func (r *fruManyDevicesRunner) Exec(netfn, cmd byte, data []byte) (byte, []byte, error) {
	if netfn != NetFnStorage || len(data) == 0 {
		return 0xc1, nil, nil
	}
	switch cmd {
	case CmdGetFRUInventoryInfo:
		r.touched++
		return 0x00, []byte{16, 0, 0x00}, nil
	case CmdReadFRUData:
		return 0x00, append([]byte{16}, make([]byte, 16)...), nil
	}
	return 0xc1, nil, nil
}

// Even when every device answers, the walk stops at the device-id cap instead of
// running to 255.
func TestCollectFRUCapsDeviceIDEvenWhenAllAnswer(t *testing.T) {
	r := &fruManyDevicesRunner{}
	if _, err := collectFRU(context.Background(), r, 64); err != nil {
		t.Fatalf("collectFRU: %v", err)
	}
	if r.touched > fruMaxDeviceID+1 {
		t.Errorf("walk touched %d device ids, want <= %d", r.touched, fruMaxDeviceID+1)
	}
}

// fruDeviceZeroErrRunner answers device 0 with a hard completion code (0xd4,
// insufficient privilege) rather than the 0xcb/0xcc that mean "no such device".
type fruDeviceZeroErrRunner struct{}

func (fruDeviceZeroErrRunner) Close() {}

func (fruDeviceZeroErrRunner) Exec(netfn, cmd byte, data []byte) (byte, []byte, error) {
	if netfn == NetFnStorage && cmd == CmdGetFRUInventoryInfo {
		return 0xd4, nil, nil
	}
	return 0xc1, nil, nil
}

// A failure on device 0 is still fatal: no baseboard FRU means no FRU at all, and
// bounding the walk must not turn a real error into a silent empty result.
func TestCollectFRUDeviceZeroErrorIsFatal(t *testing.T) {
	if _, err := collectFRU(context.Background(), fruDeviceZeroErrRunner{}, 64); err == nil {
		t.Error("a device-0 failure must be returned, not swallowed")
	}
}
