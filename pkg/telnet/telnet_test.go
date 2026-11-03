package telnet

import (
	"net"
	"strings"
	"testing"
	"time"
)

func TestParseIAC_AnnotatesOptionsAndPreservesVisible(t *testing.T) {
	// IAC DO ECHO (fd 01), IAC WILL SGA (fb 03), then a diag prompt.
	in := []byte{IAC, DO, 0x01, IAC, WILL, 0x03, 'd', 'i', 'a', 'g', '>', ' '}
	ir := ParseIAC(in)
	if string(ir.Visible) != "diag> " {
		t.Fatalf("visible = %q, want %q", string(ir.Visible), "diag> ")
	}
	if !ir.HasIAC {
		t.Fatal("expected HasIAC=true")
	}
	if !strings.Contains(ir.Annotated, "<DO Echo>") {
		t.Errorf("annotated missing <DO Echo>: %q", ir.Annotated)
	}
	if !strings.Contains(ir.Annotated, "<WILL Suppress Go Ahead>") {
		t.Errorf("annotated missing <WILL Suppress Go Ahead>: %q", ir.Annotated)
	}
	if !strings.Contains(ir.Annotated, "diag> ") {
		t.Errorf("annotated missing visible tail: %q", ir.Annotated)
	}
	// Reject responses: DO Echo -> WONT Echo, WILL SGA -> DONT SGA.
	want := []byte{IAC, WONT, 0x01, IAC, DONT, 0x03}
	if string(ir.Responses) != string(want) {
		t.Errorf("responses = % x, want % x", ir.Responses, want)
	}
}

func TestParseIAC_PlainBannerPassthrough(t *testing.T) {
	ir := ParseIAC([]byte("IOLAN diag"))
	if string(ir.Visible) != "IOLAN diag" {
		t.Fatalf("visible = %q", string(ir.Visible))
	}
	if ir.Annotated != "IOLAN diag" {
		t.Errorf("annotated = %q, want %q", ir.Annotated, "IOLAN diag")
	}
	if ir.HasIAC {
		t.Error("HasIAC should be false on plain text")
	}
	if len(ir.Responses) != 0 {
		t.Errorf("responses should be empty, got % x", ir.Responses)
	}
}

func TestParseIAC_EscapedFF(t *testing.T) {
	// IAC IAC represents a literal 0xff byte in the data stream.
	in := []byte{'A', IAC, IAC, 'B'}
	ir := ParseIAC(in)
	if string(ir.Visible) != string([]byte{'A', 0xff, 'B'}) {
		t.Fatalf("visible = % x", ir.Visible)
	}
}

func TestParseIAC_TruncatedTail(t *testing.T) {
	// A bare IAC at the end of the buffer must not panic.
	ir := ParseIAC([]byte{'X', IAC})
	if string(ir.Visible) != "X" {
		t.Errorf("visible = %q", string(ir.Visible))
	}
}

// TestReadBannerWithNegotiate_IACAnnotated exercises the happy path where
// the peer offers options and then emits a login prompt; we should record
// the annotated banner and write reject responses back.
func TestReadBannerWithNegotiate_IACAnnotated(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	gotResp := make(chan []byte, 1)
	go func() {
		c, e := ln.Accept()
		if e != nil {
			return
		}
		defer c.Close()
		_, _ = c.Write([]byte{IAC, DO, 0x01})
		_, _ = c.Write([]byte("Perle IOLAN diag>"))
		buf := make([]byte, 64)
		_ = c.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		n, _ := c.Read(buf)
		gotResp <- append([]byte(nil), buf[:n]...)
	}()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	res := ReadBannerWithNegotiate(conn, 2*time.Second)
	if !res.HasIAC {
		t.Error("expected HasIAC=true")
	}
	if !strings.Contains(res.Annotated, "<DO Echo>") {
		t.Errorf("annotated missing <DO Echo>: %q", res.Annotated)
	}
	if !strings.Contains(res.Annotated, "Perle IOLAN diag>") {
		t.Errorf("annotated missing visible banner: %q", res.Annotated)
	}
	if string(res.Visible) != "Perle IOLAN diag>" {
		t.Errorf("visible = %q, want Perle IOLAN diag>", string(res.Visible))
	}
	// The client must have written back a WONT Echo reject.
	select {
	case resp := <-gotResp:
		if len(resp) < 3 || resp[0] != IAC || resp[1] != WONT || resp[2] != 0x01 {
			t.Errorf("server got response % x, want IAC WONT ECHO", resp)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for negotiation response")
	}
}

// TestReadBannerWithNegotiate_EmptyRetriesWithEnter verifies the "peer stays
// silent until pressed enter" behaviour: connect -> read nothing -> write
// "\r\n" -> wait 100ms -> read the prompt.
func TestReadBannerWithNegotiate_EmptyRetriesWithEnter(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	go func() {
		c, e := ln.Accept()
		if e != nil {
			return
		}
		defer c.Close()
		// Wait for the client's "\r\n" wake-up, then emit a prompt.
		buf := make([]byte, 16)
		_ = c.SetReadDeadline(time.Now().Add(4 * time.Second))
		n, _ := c.Read(buf)
		if n > 0 && (buf[0] == '\r' || buf[0] == '\n') {
			_, _ = c.Write([]byte("SLC login: "))
			// Keep the connection open long enough for the client to read.
			time.Sleep(300 * time.Millisecond)
		}
	}()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	res := ReadBannerWithNegotiate(conn, 3*time.Second)
	if !res.SentEnter {
		t.Error("expected SentEnter=true after empty first read")
	}
	if string(res.Visible) != "SLC login: " {
		t.Errorf("visible = %q, want %q", string(res.Visible), "SLC login: ")
	}
}
