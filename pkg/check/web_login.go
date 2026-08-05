package check

import (
	"context"
	"errors"
	"net/http"
	"strings"
)

var errNotThisDevice = errors.New("weblogin: vendor login flow not present")

type webLoginAdapter interface {
	mechanism() string

	login(ctx context.Context, client *http.Client, base, user, pass string) (ok bool, proof string, err error)
}

var webLoginAdapters = map[string]webLoginAdapter{}

func registerWebLoginAdapter(vendor string, a webLoginAdapter) {
	if _, dup := webLoginAdapters[vendor]; dup {
		panic("duplicate web-login adapter for vendor " + vendor)
	}
	webLoginAdapters[vendor] = a
}

type webVendorFP struct {
	server  []string
	title   []string
	exclude []string
}

var webVendorFPs = map[string]webVendorFP{
	"moxa":       {server: []string{"moxahttp"}, title: []string{"nport"}, exclude: []string{"d-link", "dlink"}},
	"opengear":   {server: []string{"cherokee"}, title: []string{"opengear"}},
	"digi":       {server: []string{"rompager"}, title: []string{"portserver", "digi", "connect", "web service"}},
	"servertech": {server: []string{"servertech"}, title: []string{"protected object", "sentry", "switched cdu"}},

	"lantronix": {server: []string{"mini_httpd", "goahead"}, title: []string{"spider", "lantronix", "securelinx", "serial server", "slc"}, exclude: []string{"cradlepoint", "texecom", "d-link", "dlink"}},
	"perle":     {server: []string{"mini_httpd"}, title: []string{"iolan"}},

	"eaton":     {server: []string{"tntnet"}, title: []string{"network-m", "power xpert", "eaton"}, exclude: []string{"cradlepoint"}},
	"tripplite": {title: []string{"poweralert", "tripp"}},

	"cyberpower": {server: []string{"httpsrv"}, title: []string{"powerpanel", "rmcard", "cyberpower"}},
	"advantech":  {server: []string{"boa"}, title: []string{"advantech", "eki"}},

	"pikvm":   {title: []string{"pikvm"}},
	"redlion": {title: []string{"red lion", "sixnet"}},
}

func confirmVendorWeb(server, title, vendor string) bool {
	fp, ok := webVendorFPs[vendor]
	if !ok {
		return true
	}
	s, ti := strings.ToLower(server), strings.ToLower(title)
	for _, x := range fp.exclude {
		if strings.Contains(s, x) || strings.Contains(ti, x) {
			return false
		}
	}
	for _, m := range fp.server {
		if strings.Contains(s, m) {
			return true
		}
	}
	for _, m := range fp.title {
		if strings.Contains(ti, m) {
			return true
		}
	}
	return false
}
