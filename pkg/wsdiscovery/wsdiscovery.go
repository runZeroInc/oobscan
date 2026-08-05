package wsdiscovery

import (
	"regexp"
	"strings"
	"time"

	"github.com/runZeroInc/oobscan/pkg/wire"
)

const Port = 3702

const probeEnvelope = `<?xml version="1.0" encoding="utf-8"?>` +
	`<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" ` +
	`xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing" ` +
	`xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery">` +
	`<s:Header>` +
	`<a:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</a:To>` +
	`<a:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</a:Action>` +
	`<a:MessageID>urn:uuid:0a6dc791-2be6-4991-9af1-454778a1917a</a:MessageID>` +
	`</s:Header><s:Body><d:Probe/></s:Body></s:Envelope>`

type Result struct {
	From   string
	Types  []string
	XAddrs []string
}

var (
	reTypes  = regexp.MustCompile(`(?is)<[a-z0-9]*:?Types[^>]*>(.*?)</[a-z0-9]*:?Types>`)
	reXAddrs = regexp.MustCompile(`(?is)<[a-z0-9]*:?XAddrs[^>]*>(.*?)</[a-z0-9]*:?XAddrs>`)
)

func Probe(host string, timeout time.Duration) *Result {
	raw, err := wire.UDPQuery(host, Port, []byte(probeEnvelope), timeout)
	if err != nil || len(raw) == 0 {
		return nil
	}
	return parse(host, string(raw))
}

func parse(host, s string) *Result {

	if !strings.Contains(s, "ProbeMatch") && !strings.Contains(s, "discovery") {
		return nil
	}
	r := &Result{From: host}
	if m := reTypes.FindStringSubmatch(s); len(m) == 2 {
		r.Types = strings.Fields(strings.TrimSpace(m[1]))
	}
	if m := reXAddrs.FindStringSubmatch(s); len(m) == 2 {
		r.XAddrs = strings.Fields(strings.TrimSpace(m[1]))
	}
	return r
}
