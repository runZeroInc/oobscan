package cmd

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func TestExplainGuideIncludesOperationalContext(t *testing.T) {
	oldMatch, oldOut := explainMatch, explainOut
	t.Cleanup(func() { explainMatch, explainOut = oldMatch, oldOut })
	explainMatch, explainOut = nil, ""
	input := filepath.Join(t.TempDir(), "scan.jsonl")
	data := `{"host":"192.0.2.10","findings":[{"check":"example.first","risk":"high"},{"check":"example.second","risk":"medium"}]}`
	if err := os.WriteFile(input, []byte(data+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	command := &cobra.Command{}
	command.SetOut(&output)
	if err := runExplain(command, []string{input}); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"# OOBscan validation guide", "authorized to assess", "failure counters", "sensitive evidence", "potential impact", "example.first", "example.second"} {
		if !strings.Contains(output.String(), want) {
			t.Errorf("guide missing %q", want)
		}
	}
	if got := strings.Count(output.String(), "# OOBscan validation guide"); got != 1 {
		t.Errorf("guide preface count = %d, want 1", got)
	}
	output.Reset()
	explainMatch = []string{"unmatched-finding"}
	if err := runExplain(command, []string{input}); err == nil {
		t.Fatal("expected an error when no finding matches")
	}
	if output.Len() != 0 {
		t.Error("an empty guide must not contain a standalone preface")
	}
}
