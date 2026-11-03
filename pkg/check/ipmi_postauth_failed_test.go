package check

import (
	"errors"
	"testing"

	"github.com/runZeroInc/oobscan/pkg/ipmi"
)

// A post-auth attempt that authenticates but collects nothing before its budget
// expires must still be recorded, so it is not indistinguishable from a host that
// was never eligible for post-auth.
func TestPostAuthAttemptFailedFindingIsEmitted(t *testing.T) {
	flow := ipmi.AuthFlow{
		Version:  "2.0",
		Mode:     "cred",
		Username: "ADMIN",
		Source:   "ipmi.auth.defaultCreds",
	}
	f := postAuthAttemptFailedFinding(flow, nil, errors.New("before mcInfo: context deadline exceeded"))

	if f.Check != "ipmi.postAuthEnum" {
		t.Errorf("check = %q, want ipmi.postAuthEnum", f.Check)
	}
	if f.Category != "creds" {
		t.Errorf("category = %q, want creds", f.Category)
	}
	fields := map[string]string{}
	for _, kv := range f.Fields {
		fields[kv.Key] = kv.Val
	}
	// access=failed is the discriminator a report uses to separate "not
	// vulnerable" from "not measured"; without it the host is uncountable.
	if fields["access"] != "failed" {
		t.Errorf("access = %q, want failed", fields["access"])
	}
	if fields["error"] == "" {
		t.Error("error field is empty; the failure reason must be recorded")
	}
	if fields["flow"] != "2.0/cred" {
		t.Errorf("flow = %q, want 2.0/cred", fields["flow"])
	}
	if fields["user"] != "ADMIN" {
		t.Errorf("user = %q, want ADMIN", fields["user"])
	}
	if fields["source"] != "ipmi.auth.defaultCreds" {
		t.Errorf("source = %q, want ipmi.auth.defaultCreds", fields["source"])
	}
}

// With no error but a nil inventory, the reason must still be populated rather
// than emitting an empty error field.
func TestPostAuthAttemptFailedFindingWithoutError(t *testing.T) {
	f := postAuthAttemptFailedFinding(ipmi.AuthFlow{Version: "1.5", Mode: "authNone"}, nil, nil)
	fields := map[string]string{}
	for _, kv := range f.Fields {
		fields[kv.Key] = kv.Val
	}
	if fields["error"] == "" {
		t.Error("error field must describe why nothing was collected")
	}
	if fields["access"] != "failed" {
		t.Errorf("access = %q, want failed", fields["access"])
	}
}

// An inventory-carrying partial failure reports what it did collect, so a
// partial result is not mistaken for a total loss.
func TestPostAuthAttemptFailedFindingReportsPartialCollection(t *testing.T) {
	inv := &ipmi.PostAuthCollection{Completed: []string{"mcInfo"}}
	f := postAuthAttemptFailedFinding(
		ipmi.AuthFlow{Version: "2.0", Mode: "cipherZero"}, inv, errors.New("chassis: timeout"))
	fields := map[string]string{}
	for _, kv := range f.Fields {
		fields[kv.Key] = kv.Val
	}
	if fields["collected"] == "" {
		t.Error("collected field must summarise the partial inventory")
	}
}
