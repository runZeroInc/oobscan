package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/runZeroInc/oobscan/pkg/correlate"
	"github.com/runZeroInc/oobscan/pkg/scanfile"
)

func correlateOutputPath(scanPath string) string {
	ext := filepath.Ext(scanPath)
	if ext == ".gz" {
		trimmed := strings.TrimSuffix(scanPath, ext)
		return strings.TrimSuffix(trimmed, filepath.Ext(trimmed)) + ".managed.jsonl"
	}
	return strings.TrimSuffix(scanPath, ext) + ".managed.jsonl"
}

func runCorrelateStage(scanPath string) (correlate.Summary, string, error) {
	return runCorrelateStageTo(scanPath, "")
}

func runCorrelateStageTo(scanPath, outPath string) (correlate.Summary, string, error) {
	var sum correlate.Summary
	if strings.TrimSpace(scanPath) == "" {
		return sum, "", nil
	}
	rd, err := scanfile.Open(scanPath)
	if err != nil {
		return sum, "", err
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

		observeHostSide(ix, rec)
		if m := correlate.Extract(rec); m != nil {
			hosts = append(hosts, m)
			ix.Observe(m)
		}
	}
	if err := rd.Err(); err != nil {
		return sum, "", err
	}
	for _, m := range hosts {
		ix.Resolve(m)
	}
	correlate.SortHosts(hosts)
	sum = correlate.Summarize(hosts, oobTotal)

	if strings.TrimSpace(outPath) == "" {
		outPath = correlateOutputPath(scanPath)
	}
	f, err := os.Create(outPath)
	if err != nil {
		return sum, "", err
	}
	enc := json.NewEncoder(f)
	for _, m := range hosts {
		if m.Empty() && len(m.Neighbours) == 0 {
			continue
		}
		if err := enc.Encode(m); err != nil {
			_ = f.Close()
			return sum, outPath, err
		}
	}
	if err := f.Close(); err != nil {
		return sum, outPath, err
	}
	return sum, outPath, nil
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

func observeHostSide(ix *correlate.Index, rec *scanfile.Record) {
	if rec == nil {
		return
	}
	for i := range rec.Findings {
		f := &rec.Findings[i]
		for _, fld := range f.Fields {
			switch fld.Key {
			case "mac":

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

func correlateSummaryLine(sum correlate.Summary, path string) string {
	return fmt.Sprintf("Correlation: %s; %d neighbour entries. Written to %s",
		sum.String(), sum.Neighbours, path)
}
