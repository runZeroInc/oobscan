package httpx

import (
	"net/http"
	"net/url"
	"testing"
)

func mustURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse url %q: %v", raw, err)
	}
	return u
}

func TestSameHostRedirectPolicyAllowsInPlaceRedirect(t *testing.T) {
	policy := SameHostRedirectPolicy(4)
	req := &http.Request{URL: mustURL(t, "https://10.0.0.5/login")}
	via := []*http.Request{{URL: mustURL(t, "https://10.0.0.5/")}}
	if err := policy(req, via); err != nil {
		t.Fatalf("same-host redirect should be allowed, got %v", err)
	}
}

func TestSameHostRedirectPolicyBlocksCrossHostRedirect(t *testing.T) {
	policy := SameHostRedirectPolicy(4)
	req := &http.Request{URL: mustURL(t, "https://169.254.169.254/latest/meta-data/")}
	via := []*http.Request{{URL: mustURL(t, "https://10.0.0.5/")}}
	if err := policy(req, via); err != http.ErrUseLastResponse {
		t.Fatalf("cross-host redirect should be blocked, got %v", err)
	}
}

func TestSameHostRedirectPolicyAllowsCrossPortRedirect(t *testing.T) {
	policy := SameHostRedirectPolicy(4)
	req := &http.Request{URL: mustURL(t, "https://10.0.0.5:8443/")}
	via := []*http.Request{{URL: mustURL(t, "https://10.0.0.5/")}}
	if err := policy(req, via); err != nil {
		t.Fatalf("same-host cross-port redirect should be allowed, got %v", err)
	}
}

func TestNewClientBlocksCrossHostRedirectByDefault(t *testing.T) {
	client := NewClient(ClientOptions{})
	req := &http.Request{URL: mustURL(t, "https://169.254.169.254/latest/meta-data/")}
	via := []*http.Request{{URL: mustURL(t, "https://10.0.0.5/")}}
	if err := client.CheckRedirect(req, via); err != http.ErrUseLastResponse {
		t.Fatalf("default client allowed cross-host redirect: %v", err)
	}
}

func TestSameHostRedirectPolicyHonorsMaxHops(t *testing.T) {
	policy := SameHostRedirectPolicy(2)
	req := &http.Request{URL: mustURL(t, "https://10.0.0.5/final")}
	via := []*http.Request{
		{URL: mustURL(t, "https://10.0.0.5/")},
		{URL: mustURL(t, "https://10.0.0.5/step")},
	}
	if err := policy(req, via); err != http.ErrUseLastResponse {
		t.Fatalf("redirect beyond max hops should be blocked, got %v", err)
	}
}
