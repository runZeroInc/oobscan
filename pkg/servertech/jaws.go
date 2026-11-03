// Package servertech implements a probe for the Server Technology (Sentry
// PDU/CDU) JAWS "manager" handshake, the proprietary XML entry to the
// management/manager protocol parsed by the JAWS dispatch in app.bin before
// the credential exchange completes. The handshake document is a fixed
// vendor-constant XML init block and the session id is carried in the
// single-character "C=" cookie, so the XML parser is a pre-auth-reachable
// surface.
//
// The related ST-Eye discovery protocol (identified by the com.servertech.scp
// string) provides LAN device discovery, but its wire format, transport, and
// port were not recovered in the firmware review, so no active ST-Eye probe is
// issued; reversing it is a live-hardware follow-up.
package servertech

import (
	"strconv"
	"strings"
	"time"

	"github.com/runZeroInc/oobscan/pkg/wire"
)

// ManagerPort is the management/web port that carries the JAWS dispatch.
const ManagerPort = 80

// handshake is the fixed manager-role init document. The <company> value is a
// Server Technology vendor constant and doubles as a fingerprint.
const handshake = `<init><version>2</version><type>manager</type><company>Server Technology</company></init>`

// Response records the JAWS handshake result.
type Response struct {
	From           string
	Open           bool
	ServerTechSeen bool
	Reply          []byte
}

// Query sends the manager handshake and captures the reply. Read-only: the
// init block selects the manager role but presents no credential.
func Query(host string, timeout time.Duration) *Response {
	open, reply, err := wire.TCPQuery(host, ManagerPort, []byte(handshake+"\r\n"), timeout)
	if err != nil || !open {
		return nil
	}
	r := &Response{From: host, Open: true, Reply: reply}
	r.ServerTechSeen = strings.Contains(strings.ToLower(string(reply)), "server technology") ||
		strings.Contains(string(reply), "Sentry")
	return r
}

// Fields renders the decoded response as engine field key/value pairs.
func (r *Response) Fields() []string {
	f := []string{
		"protocol", "jaws-manager",
		"port", strconv.Itoa(ManagerPort),
		"serverTechFingerprint", strconv.FormatBool(r.ServerTechSeen),
	}
	if len(r.Reply) > 0 {
		f = append(f, "replyStrings", wire.Join(wire.Printable(r.Reply)))
	}
	return f
}
