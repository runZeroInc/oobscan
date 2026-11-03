package slp

import (
	"bytes"
	"encoding/binary"
	"reflect"
	"testing"
)

func TestParseSrvRplySkipsAuthenticationBlocks(t *testing.T) {
	var packet bytes.Buffer
	packet.Write([]byte{2, FuncSrvRply, 0, 0, 0, 0, 0, 0, 0, 0, 0x12, 0x34})
	_ = binary.Write(&packet, binary.BigEndian, uint16(2))
	packet.WriteString("en")
	_ = binary.Write(&packet, binary.BigEndian, uint16(0))
	_ = binary.Write(&packet, binary.BigEndian, uint16(2))
	writeURL := func(rawURL string, withAuth bool) {
		packet.WriteByte(0)
		_ = binary.Write(&packet, binary.BigEndian, uint16(300))
		_ = binary.Write(&packet, binary.BigEndian, uint16(len(rawURL)))
		packet.WriteString(rawURL)
		if !withAuth {
			packet.WriteByte(0)
			return
		}
		packet.WriteByte(1)
		packet.Write([]byte{0, 1, 0, 10, 0, 0, 0, 0, 0, 0})
	}
	writeURL("service:wbem:https://bmc/wsman", true)
	writeURL("service:redfish-rest:https://bmc/redfish/v1", false)

	raw := packet.Bytes()
	length := len(raw)
	raw[2], raw[3], raw[4] = byte(length>>16), byte(length>>8), byte(length)
	reply, err := parseSrvRply(raw)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"service:wbem:https://bmc/wsman", "service:redfish-rest:https://bmc/redfish/v1"}
	if !reflect.DeepEqual(reply.URLs, want) {
		t.Fatalf("URLs = %q, want %q", reply.URLs, want)
	}
}

func TestParseSrvRplyRejectsTruncatedURL(t *testing.T) {
	packet := []byte{
		2, FuncSrvRply, 0, 0, 22, 0, 0, 0, 0, 0, 0x12, 0x34,
		0, 2, 'e', 'n',
		0, 0, 0, 1,
		0, 0,
	}
	if _, err := parseSrvRply(packet); err == nil {
		t.Fatal("truncated URL entry was accepted")
	}
}
