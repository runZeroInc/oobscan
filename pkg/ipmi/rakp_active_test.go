package ipmi

import (
	"reflect"
	"testing"
)

func TestPreferredUsernamesPrioritizesProvidedAndAppendsCommon(t *testing.T) {
	got := preferredUsernames([]string{"runZero", "ADMIN"}, []string{"ADMIN", "root", "operator"})
	want := []string{"runZero", "ADMIN", "root", "operator"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("preferredUsernames() = %v, want %v", got, want)
	}
}

// The empty/null username must be preserved: on BMCs with an enabled anonymous
// account it yields a distinct, often crackable RAKP-2 hash, so stripping it loses
// most of the offline-crack yield.
func TestPreferredUsernamesKeepsNullUser(t *testing.T) {
	got := preferredUsernames(nil, []string{"ADMIN", "", "root", ""})
	want := []string{"ADMIN", "", "root"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("preferredUsernames() = %v, want %v", got, want)
	}
}

func TestPreferredUsernamesFallsBackToCommon(t *testing.T) {
	got := preferredUsernames(nil, []string{"ADMIN", "root"})
	want := []string{"ADMIN", "root"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("preferredUsernames() = %v, want %v", got, want)
	}
}

func TestPreferredUsernamesDedupesCaseInsensitive(t *testing.T) {
	got := preferredUsernames([]string{"ADMIN"}, []string{"admin", "root"})
	want := []string{"ADMIN", "root"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("preferredUsernames() = %v, want %v", got, want)
	}
}

func TestSMCRAKPOnlineUserCandidatesDedupesCaseInsensitive(t *testing.T) {
	cracked := []CrackResult{{Username: "ADMIN", PasswordType: "smcrakp-fixed-key"}}
	got := smcrakpOnlineUserCandidates(cracked, []string{"admin", "ADMIN", "root"}, 8)
	want := []string{"ADMIN", "root"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("smcrakpOnlineUserCandidates() = %v, want %v", got, want)
	}
}
