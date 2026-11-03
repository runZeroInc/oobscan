package cmd

import (
	"bytes"
	"testing"
)

func TestParseSMCShellPort(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		want    int
		wantErr bool
	}{
		{name: "host only defaults", args: []string{"10.0.0.10"}, want: smcShellDefaultPort},
		{name: "explicit port", args: []string{"10.0.0.10", "2223"}, want: 2223},
		{name: "blank port defaults", args: []string{"10.0.0.10", " "}, want: smcShellDefaultPort},
		{name: "non-numeric port", args: []string{"10.0.0.10", "https"}, wantErr: true},
		{name: "zero port", args: []string{"10.0.0.10", "0"}, wantErr: true},
		{name: "port out of range", args: []string{"10.0.0.10", "65536"}, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseSMCShellPort(tt.args)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("parseSMCShellPort(%v) = %d, want error", tt.args, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseSMCShellPort(%v) error: %v", tt.args, err)
			}
			if got != tt.want {
				t.Fatalf("parseSMCShellPort(%v) = %d, want %d", tt.args, got, tt.want)
			}
		})
	}
}

func TestCRLFWriter(t *testing.T) {
	tests := []struct {
		name  string
		chunk []byte
		want  string
	}{
		{name: "bare LF becomes CRLF", chunk: []byte("uname -a\n"), want: "uname -a\r\n"},
		{name: "existing CRLF untouched", chunk: []byte("ok\r\n"), want: "ok\r\n"},
		{name: "no newline", chunk: []byte("prompt# "), want: "prompt# "},
		{name: "CR alone untouched", chunk: []byte("a\rb"), want: "a\rb"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			w := &crlfWriter{w: &buf}
			if n, err := w.Write(tt.chunk); err != nil || n != len(tt.chunk) {
				t.Fatalf("Write(%q) = %d, %v; want %d, nil", tt.chunk, n, err, len(tt.chunk))
			}
			if got := buf.String(); got != tt.want {
				t.Fatalf("Write(%q) output = %q, want %q", tt.chunk, got, tt.want)
			}
		})
	}

	// A CRLF split across two Write calls must not be doubled.
	t.Run("CRLF split across writes", func(t *testing.T) {
		var buf bytes.Buffer
		w := &crlfWriter{w: &buf}
		_, _ = w.Write([]byte("ok\r"))
		_, _ = w.Write([]byte("\nnext\n"))
		if got, want := buf.String(), "ok\r\nnext\r\n"; got != want {
			t.Fatalf("split CRLF output = %q, want %q", got, want)
		}
	})
}
