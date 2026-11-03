package cmd

import (
	"net/http"
	"reflect"
	"testing"
)

func TestPprofServerUsesPrivateBoundedMux(t *testing.T) {
	server := newPprofServer()
	if server.Handler == http.DefaultServeMux {
		t.Fatal("pprof server uses the process-wide default mux")
	}
	if server.ReadHeaderTimeout <= 0 {
		t.Fatal("pprof server has no read-header timeout")
	}
}

func TestDefaultScanArgs(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want []string
	}{
		{
			name: "bare target",
			args: []string{"192.0.2.0/24"},
			want: []string{"scan", "192.0.2.0/24"},
		},
		{
			name: "scan flag before target",
			args: []string{"--output", "results.jsonl", "192.0.2.0/24"},
			want: []string{"scan", "--output", "results.jsonl", "192.0.2.0/24"},
		},
		{
			name: "root flag before target",
			args: []string{"--verbose", "192.0.2.0/24"},
			want: []string{"scan", "--verbose", "192.0.2.0/24"},
		},
		{
			name: "root flag before command",
			args: []string{"--verbose", "coverage"},
			want: []string{"--verbose", "coverage"},
		},
		{
			name: "root flag with value before command",
			args: []string{"--pprof", "6060", "version"},
			want: []string{"--pprof", "6060", "version"},
		},
		{
			name: "explicit scan command",
			args: []string{"scan", "192.0.2.0/24"},
			want: []string{"scan", "192.0.2.0/24"},
		},
		{
			name: "root help",
			args: []string{"--help"},
			want: []string{"--help"},
		},
		{
			name: "no args",
			args: nil,
			want: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := defaultScanArgs(tt.args)
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("defaultScanArgs(%v) = %v, want %v", tt.args, got, tt.want)
			}
		})
	}
}
