package check

import (
	"slices"
	"testing"

	"github.com/runZeroInc/oobscan/pkg/engine"
	"github.com/runZeroInc/oobscan/pkg/httpscan"
)

// TestExposureConfirmed pins the proof rule for http.exposure: only a 2xx body
// carrying a data-bearing tag is an exposure. Route reachability is not proof.
func TestExposureConfirmed(t *testing.T) {
	tags := []string{"handlerReachable", "upload-surface"}
	readable := []string{"preAuthReadable"}
	for _, tc := range []struct {
		name    string
		rr      httpscan.RequestResult
		tags    []string
		wantHit bool
	}{
		{
			name:    "401 auth-gated upload CGI (has error-page body) is NOT an exposure",
			rr:      httpscan.RequestResult{Status: 401, Snippet: "<html>401 Authorization Required</html>"},
			tags:    tags,
			wantHit: false,
		},
		{
			name:    "empty-body HEAD 200 is NOT a preAuthReadable exposure",
			rr:      httpscan.RequestResult{Status: 200, Snippet: ""},
			tags:    readable,
			wantHit: false,
		},
		{
			name:    "404 with a body is NOT an exposure",
			rr:      httpscan.RequestResult{Status: 404, Snippet: "not found"},
			tags:    readable,
			wantHit: false,
		},
		{
			name:    "302 redirect is NOT an exposure",
			rr:      httpscan.RequestResult{Status: 302, Snippet: "moved"},
			tags:    readable,
			wantHit: false,
		},
		{
			name:    "200 with concrete readable data IS a confirmed exposure",
			rr:      httpscan.RequestResult{Status: 200, Snippet: `{"password":"leaked"}`},
			tags:    readable,
			wantHit: true,
		},
		{
			name:    "200 upload route with a redirect page is NOT proof of upload",
			rr:      httpscan.RequestResult{Status: 200, Snippet: `<html><meta http-equiv="refresh" content="0;URL=/"></html>`},
			tags:    []string{"post-accepted", "upload-surface"},
			wantHit: false,
		},
		{
			name:    "reachable KVM launcher without a token is NOT an exposure",
			rr:      httpscan.RequestResult{Status: 200, Snippet: `<html><title>Remote Console</title></html>`},
			tags:    []string{"kvm.launchExposed", "post-accepted"},
			wantHit: false,
		},
		{
			name:    "200 with a body but NO interest tag is not an exposure (it is an INFO endpoint)",
			rr:      httpscan.RequestResult{Status: 200, Snippet: "hello"},
			tags:    nil,
			wantHit: false,
		},
	} {
		if got := exposureConfirmed(tc.rr, tc.tags); got != tc.wantHit {
			t.Errorf("%s: exposureConfirmed = %v, want %v", tc.name, got, tc.wantHit)
		}
	}
}

func TestHTTPSurfaceVendorScope(t *testing.T) {
	dell := &engine.Target{Identity: &engine.Identity{Vendor: "dell"}}
	if got := httpSurfaceVendorScope(dell); len(got) != 1 || got[0] != "dell" {
		t.Fatalf("Dell scope = %v", got)
	}
	ami := &engine.Target{Identity: &engine.Identity{Vendor: "ami"}}
	if got := httpSurfaceVendorScope(ami); got != nil {
		t.Fatalf("mixed-lineage AMI scope = %v, want full corpus", got)
	}
}

// TestNormalizeHTTPSurfaceInteresting pins that static spec documents (Redfish
// service root, OData $metadata) and logout stubs shed their leak-implying tags
// so they can only ever be informational -- the possibleDataLeak substring fires
// on schema property names ("SerialNumber", ...) and the "session" word in a
// logout page, neither of which is a real disclosure. A genuine data endpoint is
// left untouched.
func TestNormalizeHTTPSurfaceInteresting(t *testing.T) {
	for _, tc := range []struct {
		name string
		url  string
		in   []string
		want []string
	}{
		{
			name: "OData $metadata drops leak tags (was MEDIUM, now INFO)",
			url:  "https://10.0.0.1/redfish/v1/$metadata",
			in:   []string{"possibleDataLeak", "post-accepted", "preAuthReadable"},
			want: []string{"post-accepted"},
		},
		{
			name: "bare /$metadata drops leak tags too",
			url:  "https://10.0.0.1/$metadata",
			in:   []string{"possibleDataLeak", "preAuthReadable", "staticDisclosure"},
			want: []string{},
		},
		{
			name: "logout stub drops possibleDataLeak (was MEDIUM, now INFO)",
			url:  "https://10.0.0.1/cgi/logout.cgi",
			in:   []string{"possibleDataLeak"},
			want: []string{},
		},
		{
			name: "redfish service root still normalized (regression)",
			url:  "https://10.0.0.1/redfish/v1/",
			in:   []string{"possibleDataLeak", "preAuthReadable"},
			want: []string{},
		},
		{
			name: "redfish discovery root is informational",
			url:  "https://10.0.0.1/redfish/",
			in:   []string{"preAuthReadable", "prefixLive"},
			want: []string{"prefixLive"},
		},
		{
			name: "genuine data endpoint keeps its tags",
			url:  "https://10.0.0.1/rpc/getsysinfo.asp",
			in:   []string{"possibleDataLeak", "preAuthReadable"},
			want: []string{"possibleDataLeak", "preAuthReadable"},
		},
	} {
		got := normalizeHTTPSurfaceInteresting(tc.url, tc.in)
		if !slices.Equal(got, tc.want) {
			t.Errorf("%s: normalizeHTTPSurfaceInteresting = %#v, want %#v", tc.name, got, tc.want)
		}
		// The normalized tag set must never leave these at medium or high risk.
		if r := httpRisk(got); tc.name != "genuine data endpoint keeps its tags" && (r == "medium" || r == "high") {
			t.Errorf("%s: httpRisk(%#v) = %q, want info/low", tc.name, got, r)
		}
	}
}

func TestHTTPRiskDoesNotTreatRouteReachabilityAsWriteProof(t *testing.T) {
	if got := httpRisk([]string{"post-accepted", "upload-surface"}); got != "info" {
		t.Fatalf("httpRisk(route-only upload) = %q, want info", got)
	}
}
