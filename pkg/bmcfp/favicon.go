package bmcfp

import (
	"encoding/base64"
	"strconv"
)

func FaviconHash(icon []byte) int32 { return murmur3x86_32(mimeBase64(icon)) }

func FaviconHashString(icon []byte) string { return strconv.Itoa(int(FaviconHash(icon))) }

func mimeBase64(raw []byte) []byte {
	enc := base64.StdEncoding.EncodeToString(raw)
	if enc == "" {
		return nil
	}
	out := make([]byte, 0, len(enc)+len(enc)/76+1)
	for i := 0; i < len(enc); i += 76 {
		end := min(i+76, len(enc))
		out = append(out, enc[i:end]...)
		out = append(out, '\n')
	}
	return out
}

func murmur3x86_32(data []byte) int32 {
	const (
		c1 uint32 = 0xcc9e2d51
		c2 uint32 = 0x1b873593
	)
	var h1 uint32
	n := len(data)
	blocks := n / 4
	for i := range blocks {
		j := i * 4
		k1 := uint32(data[j]) | uint32(data[j+1])<<8 | uint32(data[j+2])<<16 | uint32(data[j+3])<<24
		k1 *= c1
		k1 = (k1 << 15) | (k1 >> 17)
		k1 *= c2
		h1 ^= k1
		h1 = (h1 << 13) | (h1 >> 19)
		h1 = h1*5 + 0xe6546b64
	}
	var k1 uint32
	switch tail := data[blocks*4:]; len(tail) {
	case 3:
		k1 ^= uint32(tail[2]) << 16
		fallthrough
	case 2:
		k1 ^= uint32(tail[1]) << 8
		fallthrough
	case 1:
		k1 ^= uint32(tail[0])
		k1 *= c1
		k1 = (k1 << 15) | (k1 >> 17)
		k1 *= c2
		h1 ^= k1
	}
	h1 ^= uint32(n)
	h1 ^= h1 >> 16
	h1 *= 0x85ebca6b
	h1 ^= h1 >> 13
	h1 *= 0xc2b2ae35
	h1 ^= h1 >> 16
	return int32(h1)
}
