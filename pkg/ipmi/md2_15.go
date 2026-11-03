package ipmi

// Self-contained MD2 (RFC 1319 section 3) for the IPMI v1.5 auth-type MD2 (0x01)
// code: the Go standard library ships no MD2, yet legacy BMCs advertise it in Get
// Channel Auth Caps (bit1) and some offer nothing else. Used solely to compute the
// 16-byte AuthCode, never for security.
//
// Same construction as the MD5 AuthCode, only the digest differs:
// MD2( pw16 || sessionID(4 LE) || msgData || sessionSeq(4 LE) || pw16 ).

// md2PiSubst is the digits of pi permutation table from RFC 1319, Appendix.
var md2PiSubst = [256]byte{
	41, 46, 67, 201, 162, 216, 124, 1, 61, 54, 84, 161, 236, 240, 6,
	19, 98, 167, 5, 243, 192, 199, 115, 140, 152, 147, 43, 217, 188,
	76, 130, 202, 30, 155, 87, 60, 253, 212, 224, 22, 103, 66, 111, 24,
	138, 23, 229, 18, 190, 78, 196, 214, 218, 158, 222, 73, 160, 251,
	245, 142, 187, 47, 238, 122, 169, 104, 121, 145, 21, 178, 7, 63,
	148, 194, 16, 137, 11, 34, 95, 33, 128, 127, 93, 154, 90, 144, 50,
	39, 53, 62, 204, 231, 191, 247, 151, 3, 255, 25, 48, 179, 72, 165,
	181, 209, 215, 94, 146, 42, 172, 86, 170, 198, 79, 184, 56, 210,
	150, 164, 125, 182, 118, 252, 107, 226, 156, 116, 4, 241, 69, 157,
	112, 89, 100, 113, 135, 32, 134, 91, 207, 101, 230, 45, 168, 2, 27,
	96, 37, 173, 174, 176, 185, 246, 28, 70, 97, 105, 52, 64, 126, 15,
	85, 71, 163, 35, 221, 81, 175, 58, 195, 92, 249, 206, 186, 197,
	234, 38, 44, 83, 13, 110, 133, 40, 132, 9, 211, 223, 205, 244, 65,
	129, 77, 82, 106, 220, 55, 200, 108, 193, 171, 250, 36, 225, 123,
	8, 12, 189, 177, 74, 120, 136, 149, 139, 227, 99, 232, 109, 233,
	203, 213, 254, 59, 0, 29, 57, 242, 239, 183, 14, 102, 88, 208, 228,
	166, 119, 114, 248, 235, 117, 75, 10, 49, 68, 80, 180, 143, 237,
	31, 26, 219, 153, 141, 51, 159, 17, 131, 20,
}

// md2Sum returns the 16-byte MD2 digest of data (RFC 1319).
func md2Sum(data []byte) []byte {
	// 1. Append padding so length == 0 mod 16. Pad value = number of pad bytes.
	msg := append([]byte(nil), data...)
	pad := 16 - (len(msg) % 16)
	for range pad {
		msg = append(msg, byte(pad))
	}

	// 2. Append the 16-byte checksum.
	var checksum [16]byte
	var l byte
	for i := 0; i < len(msg)/16; i++ {
		for j := range 16 {
			c := msg[i*16+j]
			checksum[j] ^= md2PiSubst[c^l]
			l = checksum[j]
		}
	}
	msg = append(msg, checksum[:]...)

	// 3. Process each 16-byte block through the 48-byte state buffer.
	var x [48]byte
	for i := 0; i < len(msg)/16; i++ {
		for j := range 16 {
			x[16+j] = msg[i*16+j]
			x[32+j] = x[16+j] ^ x[j]
		}
		var t byte
		for round := range 18 {
			for k := range 48 {
				x[k] ^= md2PiSubst[t]
				t = x[k]
			}
			t += byte(round)
		}
	}
	return append([]byte(nil), x[:16]...)
}
