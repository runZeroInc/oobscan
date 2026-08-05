package servertech

import (
	"strconv"
	"strings"
	"time"

	"github.com/runZeroInc/oobscan/pkg/wire"
)

const ManagerPort = 80

const handshake = `<init><version>2</version><type>manager</type><company>Server Technology</company></init>`

type Response struct {
	From           string
	Open           bool
	ServerTechSeen bool
	Reply          []byte
}

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
