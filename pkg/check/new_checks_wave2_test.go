package check

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/runZeroInc/oobscan/pkg/engine"
	"github.com/runZeroInc/oobscan/pkg/ssdp"
)

func TestSSDPRedfishFields(t *testing.T) {
	f, ok := ssdpRedfishFields(&ssdp.Result{ST: "urn:dmtf-org:service:redfish-rest:1", Location: "http://1.2.3.4/desc.xml", Server: "UPnP/1.0", USN: "uuid:abc"})
	if !ok || len(f) == 0 {
		t.Fatal("expected redfish SSDP fields to parse")
	}
	if _, ok := ssdpRedfishFields(&ssdp.Result{ST: "upnp:rootdevice", Location: "http://x"}); ok {
		t.Fatal("non-redfish ST should not match")
	}
}

func TestRunAMIUPnPDescriptor(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/redfishSCPD.xml" {
			w.Header().Set("Content-Type", "text/xml")
			_, _ = w.Write([]byte(`<serviceType>urn:dmtf-org:service:redfish-rest:1</serviceType><manufacturer>American Megatrends, Inc.</manufacturer>`))
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()
	host, portStr, _ := net.SplitHostPort(strings.TrimPrefix(srv.URL, "http://"))
	tg := &engine.Target{Host: host, Timeout: 2 * time.Second, Identity: &engine.Identity{Vendor: "tyan", Class: engine.ClassBMC, Attributes: map[string]string{"web.port": portStr, "web.scheme": "http"}}}
	got := runAMIUPnPDescriptor(context.Background(), tg)
	if hasFinding(got, "http.ami.upnpDescriptor") == nil {
		t.Fatalf("expected ami upnp descriptor finding, got %+v", got)
	}
}

func TestRunOpenBMCConsole2200(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		c, e := ln.Accept()
		if e != nil {
			return
		}
		defer c.Close()
		_, _ = c.Write([]byte("SSH-2.0-dropbear_2022.82\r\n"))
	}()
	_, ps, _ := net.SplitHostPort(ln.Addr().String())
	port := 0
	_, _ = fmt.Sscanf(ps, "%d", &port)
	// Directly test banner reader helper to keep this unit deterministic.
	b, ok := readTCPBanner(context.Background(), "127.0.0.1", port, 2*time.Second)
	if !ok || !strings.HasPrefix(b, "SSH-2.0-") {
		t.Fatalf("expected ssh banner, got %q", b)
	}
}
