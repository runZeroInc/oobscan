package redfish

import (
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"
)

func hostPort(t *testing.T, rawURL string) (string, int) {
	t.Helper()
	// rawURL is like https://127.0.0.1:54321
	h, p, err := net.SplitHostPort(rawURL[len("https://"):])
	if err != nil {
		t.Fatalf("split %q: %v", rawURL, err)
	}
	port, _ := strconv.Atoi(p)
	return h, port
}

func TestFetchEventService_AdvertisesAction(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/redfish/v1/EventService" {
			w.WriteHeader(200)
			_, _ = w.Write([]byte(`{"Id":"EventService","Actions":{"#EventService.SubmitTestEvent":{"target":"/redfish/v1/EventService/Actions/EventService.SubmitTestEvent"}}}`))
			return
		}
		w.WriteHeader(404)
	}))
	defer srv.Close()
	h, p := hostPort(t, srv.URL)

	info := FetchEventService(h, p, 3*time.Second)
	if !info.Reachable {
		t.Fatal("expected EventService reachable")
	}
	if !info.HasSubmitTestEvent {
		t.Error("expected SubmitTestEvent action to be detected")
	}
}

func TestFetchEventService_AuthGated(t *testing.T) {
	// A 401 still proves the resource exists (auth-gated) -> Reachable, but the
	// action set is not readable so HasSubmitTestEvent stays false.
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(401)
	}))
	defer srv.Close()
	h, p := hostPort(t, srv.URL)

	info := FetchEventService(h, p, 3*time.Second)
	if !info.Reachable {
		t.Error("a 401 EventService should still be Reachable (exists, auth-gated)")
	}
	if info.HasSubmitTestEvent {
		t.Error("must not claim SubmitTestEvent from a 401 body")
	}
}
