package ipmi

import (
	"bytes"
	"testing"
)

func TestAuthAlgosForCiphers(t *testing.T) {
	cases := []struct {
		name string
		ids  []int
		want []byte
	}{
		{"sha1+aes", []int{3}, []byte{RAKPHMACSHA1}},
		{"sha256 only (modern BMC)", []int{15, 16, 17}, []byte{RAKPHMACSHA256}},
		{"mixed sha1+sha256", []int{3, 17}, []byte{RAKPHMACSHA1, RAKPHMACSHA256}},
		{"md5 present", []int{8}, []byte{RAKPHMACMD5}},
		{"all", []int{1, 8, 17}, []byte{RAKPHMACSHA1, RAKPHMACSHA256, RAKPHMACMD5}},
		{"none standard", []int{0, 128}, nil},
		{"empty", nil, nil},
	}
	for _, c := range cases {
		got := AuthAlgosForCiphers(c.ids)
		if !bytes.Equal(got, c.want) {
			t.Errorf("%s: AuthAlgosForCiphers(%v) = %v, want %v", c.name, c.ids, got, c.want)
		}
	}
}
