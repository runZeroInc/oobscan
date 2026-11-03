package check

import (
	"context"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/runZeroInc/oobscan/pkg/engine"
)

// TestWebLoginAgainstLiveSim drives every web-login adapter (and the generic
// Basic path) against the lab/web-sim emulators over real TCP sockets, proving
// the oobscan client and the independently written device emulator agree on
// the wire. Skipped unless WEBSIM_BASE is set, so CI stays hermetic:
//
//	(cd lab/web-sim && go build -o /tmp/websim . && /tmp/websim &)
//	WEBSIM_BASE=127.0.0.1 go test ./pkg/check/ -run TestWebLoginAgainstLiveSim -v
func TestWebLoginAgainstLiveSim(t *testing.T) {
	base := os.Getenv("WEBSIM_BASE")
	if base == "" {
		t.Skip("set WEBSIM_BASE=127.0.0.1 (with lab/web-sim running) to run the live sim test")
	}
	// The emulators listen on container ports 8080-8092; under docker compose they
	// are mapped to host 9080-9092, so set WEBSIM_PORT_OFFSET=1000 for that path.
	offset := 0
	if v := os.Getenv("WEBSIM_PORT_OFFSET"); v != "" {
		offset, _ = strconv.Atoi(v)
	}
	cases := []struct {
		vendor string
		port   int
		class  engine.DeviceClass
		user   string
		pass   string // "(blank)" is rendered for an empty password
	}{
		{"moxa", 8080, engine.ClassSerialConsole, "admin", "moxa"},
		{"opengear", 8081, engine.ClassSerialConsole, "root", "default"},
		{"raritan", 8082, engine.ClassPDU, "admin", "raritan"},
		{"servertech", 8083, engine.ClassPDU, "admn", "(blank)"},
		{"digi", 8084, engine.ClassSerialConsole, "root", "dbps"},
		{"pikvm", 8085, engine.ClassKVM, "admin", "admin"},
		{"lantronix", 8086, engine.ClassSerialConsole, "sysadmin", "PASS"},
		{"perle", 8087, engine.ClassSerialConsole, "admin", "superuser"},
		{"cyberpower", 8088, engine.ClassPDU, "cyber", "cyber"},
		{"eaton", 8089, engine.ClassPDU, "admin", "admin"},
		{"advantech", 8090, engine.ClassSerialConsole, "admin", "(blank)"},
		{"nanokvm", 8091, engine.ClassKVM, "admin", "admin"},
		{"tripplite", 8092, engine.ClassPDU, "localadmin", "localadmin"},
	}
	for _, c := range cases {
		t.Run(c.vendor, func(t *testing.T) {
			port := strconv.Itoa(c.port + offset)
			tgt := &engine.Target{
				Host:    base,
				Timeout: 4 * time.Second,
				Identity: &engine.Identity{
					Vendor: c.vendor, Class: c.class,
					Attributes: map[string]string{"web.port": port, "web.scheme": "http"},
				},
			}
			f := hasFinding(runWebBasicDefaultCreds(context.Background(), tgt), "http."+c.vendor+".defaultCreds")
			if f == nil {
				t.Fatalf("%s: no http.web.defaultCreds finding against live emulator :%d", c.vendor, c.port)
			}
			if u, p := fieldVal(f.Fields, "username"), fieldVal(f.Fields, "password"); u != c.user || p != c.pass {
				t.Errorf("%s: recovered %q/%q, want %q/%q", c.vendor, u, p, c.user, c.pass)
			}
			t.Logf("%-11s OK  %s/%s  via=%s  proof=%s", c.vendor,
				fieldVal(f.Fields, "username"), fieldVal(f.Fields, "password"),
				fieldVal(f.Fields, "loginVia"), fieldVal(f.Fields, "proof"))
		})
	}
}
