package redfish

import (
	"strings"
	"testing"
)

func TestIsUnauthLeak(t *testing.T) {
	cases := []struct {
		name string
		body []byte
		want bool
	}{
		{"real redfish resource", []byte(`{"@odata.id":"/redfish/v1/AccountService","Accounts":{}}`), true},
		{"members collection", []byte(`{"Members":[{"@odata.id":"/redfish/v1/SessionService/Sessions/1"}]}`), true},
		{"html login page", []byte(`<!DOCTYPE html><html><body>login</body></html>`), false},
		{"json login stub", []byte(`{"redirect":"/login"}`), false},
		{"empty", []byte(``), false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := isUnauthLeak(c.body); got != c.want {
				t.Errorf("isUnauthLeak(%q) = %v, want %v", c.body, got, c.want)
			}
		})
	}
}

func TestIsHighRiskDoesNotPromoteLoginPage(t *testing.T) {
	// A sensitive path (contains "accounts") that returns 200 but whose body was
	// a login page (so SampleData stays empty) must not be high-risk.
	loginEP := &OEMEndpoint{
		Path:       "/redfish/v1/AccountService/Accounts",
		Status:     200,
		SampleData: "", // login page never sets this
	}
	if isHighRisk(loginEP) {
		t.Error("a 200 login page on a sensitive path must not be flagged high-risk")
	}

	// Same path, but with a genuine Redfish body captured -> high-risk leak.
	leakEP := &OEMEndpoint{
		Path:       "/redfish/v1/AccountService/Accounts",
		Status:     200,
		SampleData: `{"@odata.id":"/redfish/v1/AccountService/Accounts","Members":[]}`,
	}
	if !isHighRisk(leakEP) {
		t.Error("a 200 with a genuine Redfish body on a sensitive path must be high-risk")
	}
}

func TestIsHighRiskUnauthWriteStillFires(t *testing.T) {
	ep := &OEMEndpoint{
		Path:         "/redfish/v1/UpdateService/Actions/UpdateService.SimpleUpdate",
		Status:       405,
		AuthRequired: false,
		HasPOST:      true,
	}
	if !isHighRisk(ep) {
		t.Error("unauthenticated write on a firmware-update path must be high-risk")
	}
}

func TestEnqueueRedfishLinkBoundsQueue(t *testing.T) {
	queue := []qitem{{path: "/redfish/v1/", depth: 0}}
	visited := map[string]bool{}
	queued := map[string]bool{"/redfish/v1/": true}

	// maxQueued reached: new links should be ignored.
	queue = enqueueRedfishLink(queue, queued, visited, "/redfish/v1/Systems/1", 1, 1)
	if len(queue) != 1 {
		t.Fatalf("queue length changed past cap: %d", len(queue))
	}

	// Raise cap and enqueue should now succeed.
	queue = enqueueRedfishLink(queue, queued, visited, "/redfish/v1/Systems/1", 1, 4)
	if len(queue) != 2 {
		t.Fatalf("queue length = %d, want 2", len(queue))
	}

	// Duplicate and non-redfish paths should be ignored.
	queue = enqueueRedfishLink(queue, queued, visited, "/redfish/v1/Systems/1", 2, 4)
	queue = enqueueRedfishLink(queue, queued, visited, "/api/other", 2, 4)
	if len(queue) != 2 {
		t.Fatalf("queue should ignore duplicate/non-redfish links; got %d", len(queue))
	}

	// Already-visited links should be ignored.
	visited["/redfish/v1/Managers/1"] = true
	queue = enqueueRedfishLink(queue, queued, visited, "/redfish/v1/Managers/1", 2, 4)
	if len(queue) != 2 {
		t.Fatalf("queue should ignore visited links; got %d", len(queue))
	}
}

func TestExtractLinksBoundsNestingDepth(t *testing.T) {
	body := strings.Repeat(`{"nested":`, maxLinkWalkDepth+2) +
		`{"@odata.id":"/redfish/v1/too-deep"}` +
		strings.Repeat("}", maxLinkWalkDepth+2)
	if links := extractLinks([]byte(body), "/redfish/v1/"); len(links) != 0 {
		t.Fatalf("deep JSON produced links: %q", links)
	}
	if links := extractLinks([]byte(`{"Members":[{"@odata.id":"/redfish/v1/Systems/1"}]}`), "/redfish/v1/"); len(links) != 1 {
		t.Fatalf("shallow JSON links = %q, want one", links)
	}
}
