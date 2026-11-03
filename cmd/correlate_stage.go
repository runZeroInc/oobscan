package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/runZeroInc/oobscan/pkg/correlate"
	"github.com/runZeroInc/oobscan/pkg/scanfile"
)

// The correlation stage runs once, after the sweep, over the file the scan just
// wrote. It is a second pass rather than per-target work because the useful joins
// are cross-host: a MAC one BMC publishes for its server is located by a neighbour
// table a different BMC gave up, and neither host knows about the other while it is
// being probed.
//
// What it produces goes onto the device's own record, under `managedHost`, and not
// into a file of its own. A sidecar of managed-device rows duplicated the identity of
// every device it described in order to say which record it belonged to, and left a
// consumer to join two files to answer one question. Pass two therefore rewrites the
// scan output: it is written to a sibling temporary file and renamed over the
// original, so the visible file is never a partial one, and every line it does not
// annotate is copied through byte for byte.

// managedKey is the record key the correlation pass fills in.
const managedKey = `"managedHost":`

// correlateTempPath is the sibling the annotated copy is built in before it replaces
// the input. It keeps a .gz suffix so the writer compresses to match the input, and it
// is truncated on open, so a temporary left behind by a killed run is reused rather
// than accumulating.
func correlateTempPath(scanPath string) string {
	if strings.HasSuffix(strings.ToLower(scanPath), ".gz") {
		return scanPath + ".correlating.gz"
	}
	return scanPath + ".correlating"
}

// runCorrelateStage correlates a finished scan file and annotates it in place,
// returning the summary plus the path written. A correlation failure is never fatal:
// the scan itself succeeded and its output is already on disk.
func runCorrelateStage(scanPath string) (correlate.Summary, string, error) {
	return runCorrelateStageTo(scanPath, "")
}

// runCorrelateStageTo is runCorrelateStage with an explicit destination; an empty
// outPath annotates the input itself.
func runCorrelateStageTo(scanPath, outPath string) (correlate.Summary, string, error) {
	var sum correlate.Summary
	if strings.TrimSpace(scanPath) == "" {
		return sum, "", nil
	}
	hosts, sum, err := correlateScanFile(scanPath)
	if err != nil {
		return sum, "", err
	}

	blobs := make(map[string][]byte, len(hosts))
	for _, m := range hosts {
		e := m.Embedded()
		if e == nil {
			continue // nothing to say about the server this device manages
		}
		b, merr := marshalManaged(e)
		if merr != nil {
			return sum, "", merr
		}
		blobs[m.BMC] = b
	}

	n, path, err := annotateScanFile(scanPath, outPath, blobs)
	sum.Annotated = n
	return sum, path, err
}

// correlateScanFile is pass one: read every record, extract what each out-of-band
// device said about its server, and resolve those claims against the whole sweep.
func correlateScanFile(scanPath string) ([]*correlate.ManagedHost, correlate.Summary, error) {
	var sum correlate.Summary
	rd, err := scanfile.Open(scanPath)
	if err != nil {
		return nil, sum, err
	}
	defer func() { _ = rd.Close() }()

	ix := correlate.NewIndex()
	var hosts []*correlate.ManagedHost
	oobTotal := 0
	for rd.Next() {
		rec := rd.Record()
		if isOOBRecord(rec) {
			oobTotal++
		}
		// Every scanned address is a potential answer, not just the OOB ones: the
		// managed server is usually in the sweep too, and whatever it leaked about
		// itself is what turns a published MAC into an address.
		observeHostSide(ix, rec)
		if m := correlate.Extract(rec); m != nil {
			hosts = append(hosts, m)
			ix.Observe(m)
		}
	}
	if err := rd.Err(); err != nil {
		return nil, sum, err
	}
	for _, m := range hosts {
		ix.Resolve(m)
	}
	correlate.SortHosts(hosts)
	return hosts, correlate.Summarize(hosts, oobTotal), nil
}

// marshalManaged encodes one embedded managed-host object as a single line fragment,
// with the same HTML-literal escaping the scan writer uses so a server name that
// contains a `<` reads the same in an annotated file as it did in the original.
func marshalManaged(m *correlate.ManagedHost) ([]byte, error) {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(m); err != nil {
		return nil, err
	}
	return bytes.TrimRight(b.Bytes(), "\n"), nil
}

// annotateScanFile is pass two: copy the scan file, adding the `managedHost` key to
// the records that have one. It returns the number of records annotated and the path
// written. An empty outPath replaces the input by rename.
func annotateScanFile(scanPath, outPath string, blobs map[string][]byte) (int, string, error) {
	inPlace := strings.TrimSpace(outPath) == ""
	dst := outPath
	if inPlace {
		dst = correlateTempPath(scanPath)
	}

	rd, err := scanfile.OpenLines(scanPath)
	if err != nil {
		return 0, "", err
	}
	defer func() { _ = rd.Close() }()
	w, err := scanfile.Create(dst)
	if err != nil {
		return 0, "", err
	}

	n := 0
	for rd.Next() {
		line := rd.Line()
		if out, ok := annotateLine(line, blobs); ok {
			line = out
			n++
		}
		if werr := w.WriteLine(line); werr != nil {
			_ = w.Close()
			return 0, "", werr
		}
	}
	if err := rd.Err(); err != nil {
		_ = w.Close()
		return 0, "", err
	}
	if err := w.Close(); err != nil {
		return 0, "", err
	}
	if !inPlace {
		return n, dst, nil
	}
	// Keep the mode of the file being replaced: a scan written into a directory with a
	// restrictive umask must not come back world-readable.
	if fi, serr := os.Stat(scanPath); serr == nil {
		_ = os.Chmod(dst, fi.Mode().Perm())
	}
	if err := os.Rename(dst, scanPath); err != nil {
		return 0, "", err
	}
	return n, scanPath, nil
}

// annotateLine adds the managed-host object to one NDJSON line, reporting whether it
// changed anything. Every other byte of the line is left alone rather than re-encoded
// from a decoded record: a rewrite that round-trips through the schema types silently
// drops whatever this build does not model, and the file being rewritten is the only
// copy of the scan.
//
// The result is validated before it is accepted. Nothing here can prove that an edit
// derived from string positions is sound on a line this build did not write, so a line
// that does not come out as valid JSON is passed through unmodified instead.
func annotateLine(line []byte, blobs map[string][]byte) ([]byte, bool) {
	body, nl := splitNewline(line)
	var head struct {
		Host string `json:"host"`
	}
	if err := json.Unmarshal(body, &head); err != nil || head.Host == "" {
		return nil, false
	}
	blob, ok := blobs[head.Host]
	if !ok {
		return nil, false
	}
	// Re-running correlation over an already annotated file must replace the key, not
	// append a second one. The pass only ever writes it last, so the previous value is
	// the tail of the object.
	if i := bytes.LastIndex(body, []byte(managedKey)); i >= 0 {
		cut := bytes.LastIndexByte(body[:i], ',')
		if cut < 0 {
			return nil, false
		}
		body = append(append([]byte(nil), body[:cut]...), '}')
	}
	end := bytes.LastIndexByte(body, '}')
	if end < 0 {
		return nil, false
	}
	out := make([]byte, 0, len(body)+len(blob)+len(managedKey)+2+len(nl))
	out = append(out, body[:end]...)
	if !endsOpen(body[:end]) {
		out = append(out, ',')
	}
	out = append(out, managedKey...)
	out = append(out, blob...)
	out = append(out, '}')
	if !json.Valid(out) {
		return nil, false
	}
	return append(out, nl...), true
}

// splitNewline separates a line from its terminator. The last line of a scan that was
// interrupted has none, and re-adding one would change the file.
func splitNewline(line []byte) (body, nl []byte) {
	body = bytes.TrimRight(line, "\r\n")
	return body, line[len(body):]
}

// endsOpen reports whether the record has no fields yet, so the key being appended is
// the first one and must not be preceded by a comma.
func endsOpen(b []byte) bool {
	t := bytes.TrimRight(b, " \t")
	return len(t) > 0 && t[len(t)-1] == '{'
}

func isOOBRecord(rec *scanfile.Record) bool {
	if rec == nil || rec.Final == nil {
		return false
	}
	switch string(rec.Final.Class) {
	case "bmc", "serial", "serialConsole", "pdu", "kvm", "amt":
		return true
	}
	return false
}

// observeHostSide records what a scanned address said about itself: the MACs it
// claims and the names it answers to. This is the half of the join the BMC cannot
// provide, and it is why correlation runs over the whole sweep rather than over the
// OOB subset.
func observeHostSide(ix *correlate.Index, rec *scanfile.Record) {
	if rec == nil {
		return
	}
	for i := range rec.Findings {
		f := &rec.Findings[i]
		for _, fld := range f.Fields {
			switch fld.Key {
			case "mac":
				// ssh.weakCrypto writes the SSH MAC *algorithm list* into a field
				// called "mac"; only hardware-address-shaped values are taken, and
				// correlate.ObserveHostMAC drops anything that is not one.
				ix.ObserveHostMAC(rec.Host, fld.Val)
			case "hostname", "serverName", "netbiosName", "sysName":
				ix.ObserveName(rec.Host, fld.Val)
			}
		}
	}
	if rec.Attributes != nil {
		ix.ObserveHostMAC(rec.Host, rec.Attributes["mac"])
		ix.ObserveName(rec.Host, rec.Attributes["hostname"])
	}
}

// correlateSummaryLine is the single line a finished scan prints. It reports located
// separately from described on purpose: a BMC naming its server is inventory, a BMC
// whose server has an address is a mapping, and conflating the two overstates the
// result by roughly an order of magnitude.
func correlateSummaryLine(sum correlate.Summary, path string) string {
	return fmt.Sprintf("Correlation: %s; %d neighbour entries. Annotated %d records in %s",
		sum.String(), sum.Neighbours, sum.Annotated, path)
}
