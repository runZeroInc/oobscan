package check

import (
	"context"
	"testing"

	"github.com/runZeroInc/oobscan/pkg/httpx"
)

// TestWebLoginTranscriptStashed confirms the default web-login check captures the
// full request/response transcript on the target evidence so the raw exchange is
// available in the scan record for field debugging (false positives / wrong
// system).
func TestWebLoginTranscriptStashed(t *testing.T) {
	srv := basicAuthServer(t, "Allegro-Software-RomPager-Digi/3.12", "PortServer",
		map[string]string{"root": "dbps"}, "<title>PortServer TS 1 Configuration and Management</title>", nil)
	host, port := splitHostPort(t, srv.URL)
	tgt := mkTargetWithIdentity(t, host, port, "digi", "PortServer TS", map[string]string{"web.port": port, "web.scheme": "http"})

	got := runWebBasicDefaultCreds(context.Background(), tgt)
	if hasFinding(got, "http.digi.defaultCreds") == nil {
		t.Fatalf("expected a login finding to accompany the transcript")
	}

	v, ok := tgt.Evidenced("web.login.transcript")
	if !ok {
		t.Fatalf("no web.login.transcript evidence stashed")
	}
	tr, ok := v.(*httpx.Transcript)
	if !ok || tr == nil {
		t.Fatalf("evidence is not *httpx.Transcript: %T", v)
	}
	if tr.Vendor != "digi" || tr.Result != "success" || tr.Username != "root" {
		t.Errorf("transcript = %+v, want vendor=digi result=success user=root", tr)
	}
	if tr.Mechanism != "httpBasic" {
		t.Errorf("mechanism = %q, want http.basic", tr.Mechanism)
	}
	if len(tr.Exchanges) == 0 {
		t.Fatalf("transcript has no exchanges")
	}
	// The winning exchange must carry the real server response the success
	// heuristic keyed on: a 200 with the authenticated page body.
	var sawAuthed bool
	for _, e := range tr.Exchanges {
		if e.Status == 200 && e.RequestHeaders["Authorization"] != "" {
			sawAuthed = true
		}
	}
	if !sawAuthed {
		t.Errorf("no authenticated 200 exchange captured; exchanges=%+v", tr.Exchanges)
	}
}

// TestWebLoginTranscriptOnRejection confirms a transcript is still captured when
// the default is rejected (result=no-match) -- needed to debug false negatives /
// wrong-system reports where nothing fired.
func TestWebLoginTranscriptOnRejection(t *testing.T) {
	srv := basicAuthServer(t, "Allegro-Software-RomPager-Digi/3.12", "PortServer",
		map[string]string{"root": "rotated"}, "ok", nil)
	host, port := splitHostPort(t, srv.URL)
	tgt := mkTargetWithIdentity(t, host, port, "digi", "PortServer TS", map[string]string{"web.port": port, "web.scheme": "http"})

	if got := runWebBasicDefaultCreds(context.Background(), tgt); len(got) != 0 {
		t.Fatalf("default should be rejected, got %+v", got)
	}
	v, ok := tgt.Evidenced("web.login.transcript")
	if !ok {
		t.Fatalf("transcript must be captured even on rejection")
	}
	tr := v.(*httpx.Transcript)
	if tr.Result != "no-match" {
		t.Errorf("result = %q, want no-match", tr.Result)
	}
}
