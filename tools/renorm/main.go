// Command renorm rewrites NDJSON through the current output.Result encoder.
//
// Usage: renorm <in.jsonl> <out.jsonl>
package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"os"

	"github.com/runZeroInc/oobscan/pkg/output"
)

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: renorm <in.jsonl> <out.jsonl>")
		os.Exit(2)
	}
	in, err := os.Open(os.Args[1])
	must(err)
	defer in.Close()
	out, err := os.Create(os.Args[2])
	must(err)
	defer out.Close()

	bw := bufio.NewWriterSize(out, 1<<20)
	sc := bufio.NewScanner(in)
	sc.Buffer(make([]byte, 1<<20), 64<<20)

	var lines, changed, failed int
	for sc.Scan() {
		raw := bytes.TrimRight(sc.Bytes(), " \t\r")
		if len(raw) == 0 {
			continue
		}
		lines++
		var rec output.Result
		if err := json.Unmarshal(raw, &rec); err != nil {
			failed++
			must(writeLine(bw, raw))
			continue
		}
		// json.Marshal uses the same default HTML-escaping + compact form as the
		// scanner's json.NewEncoder, so an unchanged record re-encodes identically.
		b, err := json.Marshal(&rec)
		if err != nil {
			failed++
			must(writeLine(bw, raw))
			continue
		}
		if !bytes.Equal(raw, b) {
			changed++
		}
		must(writeLine(bw, b))
	}
	must(sc.Err())
	must(bw.Flush())
	fmt.Printf("renorm: %d records, %d re-encoded differently (fields canonicalized), %d unparseable(passed through) -> %s\n",
		lines, changed, failed, os.Args[2])
}

func writeLine(w *bufio.Writer, b []byte) error {
	if _, err := w.Write(b); err != nil {
		return err
	}
	return w.WriteByte('\n')
}

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "renorm:", err)
		os.Exit(1)
	}
}
