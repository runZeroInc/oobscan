package httpscan

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/runZeroInc/oobscan/pkg/bmcfp"
	"github.com/runZeroInc/oobscan/pkg/httpx"
	"github.com/runZeroInc/oobscan/pkg/netaddr"
	"github.com/runZeroInc/oobscan/pkg/sanitize"
)

var defaultMethods = []string{http.MethodGet, http.MethodHead, http.MethodPost}

type RequestResult struct {
	Method      string `json:"method"`
	URL         string `json:"url"`
	Status      int    `json:"status,omitempty"`
	Server      string `json:"server,omitempty"`
	ContentType string `json:"contentType,omitempty"`
	Location    string `json:"location,omitempty"`
	BodyBytes   int    `json:"bodyBytes,omitempty"`
	Snippet     string `json:"snippet,omitempty"`

	Body     string   `json:"body,omitempty"`
	Interest []string `json:"interest,omitempty"`
	Error    string   `json:"error,omitempty"`

	Fingerprint Fingerprint `json:"fingerprint"`
}

type EndpointResult struct {
	Path        string          `json:"path"`
	Match       MatchType       `json:"match"`
	Vendors     []string        `json:"vendors,omitempty"`
	Tags        []string        `json:"tags,omitempty"`
	Interesting []string        `json:"interesting,omitempty"`
	Requests    []RequestResult `json:"requests,omitempty"`
}

type Summary struct {
	EndpointsTested   int `json:"endpointsTested"`
	RequestsAttempted int `json:"requestsAttempted"`
	InterestingHits   int `json:"interestingHits"`
	PreAuthReadable   int `json:"preAuthReadable"`
	HandlerReachable  int `json:"handlerReachable"`
	UploadSurface     int `json:"uploadSurface"`

	RequestsFailed int `json:"requestsFailed"`
}

type Report struct {
	IP           string           `json:"ip"`
	Port         int              `json:"port"`
	Scheme       string           `json:"scheme"`
	HWVendor     string           `json:"hwVendor,omitempty"`
	HWProduct    string           `json:"hwProduct,omitempty"`
	HTTPVendors  []string         `json:"httpVendors,omitempty"`
	HTTPFindings []EndpointResult `json:"httpFindings,omitempty"`
	HTTPSummary  Summary          `json:"httpSummary"`
	Errors       []string         `json:"errors,omitempty"`
}

const DefaultGlobalSweepConcurrency = 2048

var sweepGate = make(chan struct{}, DefaultGlobalSweepConcurrency)

func SetGlobalSweepConcurrency(n int) {
	if n <= 0 {
		return
	}
	sweepGate = make(chan struct{}, n)
}

func acquireSweepSlot() { sweepGate <- struct{}{} }
func releaseSweepSlot() { <-sweepGate }

func ProbeHost(host string, port int, timeout time.Duration) (*Report, error) {
	return ProbeHostCtx(context.Background(), host, port, timeout)
}

func ProbeHostCtx(ctx context.Context, host string, port int, timeout time.Duration) (*Report, error) {
	return probeHostTargets(ctx, host, port, "", timeout, AggregatedTargets())
}

func ProbeHostCtxForVendors(ctx context.Context, host string, port int, timeout time.Duration, vendors ...string) (*Report, error) {
	return ProbeHostCtxForVendorsScheme(ctx, host, port, "", timeout, vendors...)
}

func ProbeHostCtxForVendorsScheme(ctx context.Context, host string, port int, scheme string, timeout time.Duration, vendors ...string) (*Report, error) {
	targets := AggregatedTargets()
	if len(vendors) > 0 {
		targets = targetsForVendors(targets, vendors)
	}
	return probeHostTargets(ctx, host, port, scheme, timeout, targets)
}

func targetsForVendors(targets []AggregatedTarget, vendors []string) []AggregatedTarget {
	wanted := make(map[string]struct{}, len(vendors))
	for _, vendor := range vendors {
		if vendor = strings.ToLower(strings.TrimSpace(vendor)); vendor != "" {
			wanted[vendor] = struct{}{}
		}
	}
	if len(wanted) == 0 {
		return targets
	}
	out := make([]AggregatedTarget, 0, len(targets))
	for _, target := range targets {
		for _, vendor := range target.Vendors {
			if _, ok := wanted[strings.ToLower(vendor)]; ok {
				out = append(out, target)
				break
			}
		}
	}
	return out
}

func probeHostTargets(ctx context.Context, host string, port int, scheme string, timeout time.Duration, targets []AggregatedTarget) (*Report, error) {
	if scheme != "http" && scheme != "https" {
		scheme = defaultScheme(port)
	}
	base := fmt.Sprintf("%s://%s", scheme, hostPort(host, port, scheme))
	client := httpx.Client(timeout)

	report := &Report{IP: host, Port: port, Scheme: scheme}
	vendorScore := map[string]int{}
	report.HTTPSummary.EndpointsTested = len(targets)

	var serverHeader, htmlTitle string

	type targetOutcome struct {
		er           EndpointResult
		hasFindings  bool
		requests     int
		failed       int
		serverHeader string
		htmlTitle    string
		vendorHits   []string
		panicErr     string
	}
	outcomes := make([]targetOutcome, len(targets))
	const maxWorkers = 16
	sem := make(chan struct{}, maxWorkers)
	var wg sync.WaitGroup
	for i := range targets {
		wg.Add(1)
		sem <- struct{}{}

		acquireSweepSlot()
		go func(i int) {
			defer wg.Done()
			defer releaseSweepSlot()
			defer func() { <-sem }()
			target := targets[i]
			o := targetOutcome{}
			defer func() {
				if recovered := recover(); recovered != nil {
					o.panicErr = fmt.Sprintf("%s: panic: %v", target.Path, recovered)
					outcomes[i] = o
				}
			}()
			if ctx.Err() != nil {
				return
			}
			er := EndpointResult{Path: target.Path, Match: target.Match, Vendors: target.Vendors, Tags: target.Tags}
			interesting := map[string]struct{}{}
			for _, method := range defaultMethods {
				if ctx.Err() != nil {
					break
				}
				o.requests++
				rr := doRequest(ctx, client, method, base+target.Path, timeout, target.Path, target.Tags)
				if rr.Status == 0 && rr.Error != "" {
					o.failed++
					continue
				}
				if o.serverHeader == "" && rr.Server != "" {
					o.serverHeader = rr.Server
				}
				if o.htmlTitle == "" {

					if t := extractTitle(rr.Body); t != "" {
						o.htmlTitle = t
					}
				}
				rr.Interest = classify(target, rr)

				rr.Body = ""
				for _, reason := range rr.Interest {
					interesting[reason] = struct{}{}
				}
				if rr.Status != http.StatusNotFound && rr.Status != http.StatusMethodNotAllowed && rr.Status != http.StatusNotImplemented {
					o.vendorHits = append(o.vendorHits, target.Vendors...)
				}
				if len(rr.Interest) > 0 || rr.Status != http.StatusNotFound {
					er.Requests = append(er.Requests, rr)
				}
			}
			if len(er.Requests) > 0 {
				er.Interesting = setToSortedSlice(interesting)
				o.er = er
				o.hasFindings = true
			}
			outcomes[i] = o
		}(i)
	}
	wg.Wait()

	for i := range outcomes {
		o := &outcomes[i]
		if o.panicErr != "" {
			report.Errors = append(report.Errors, o.panicErr)
		}
		report.HTTPSummary.RequestsAttempted += o.requests
		report.HTTPSummary.RequestsFailed += o.failed
		if serverHeader == "" && o.serverHeader != "" {
			serverHeader = o.serverHeader
		}
		if htmlTitle == "" && o.htmlTitle != "" {
			htmlTitle = o.htmlTitle
		}
		for _, v := range o.vendorHits {
			vendorScore[v]++
		}
		if !o.hasFindings {
			continue
		}
		updateSummary(&report.HTTPSummary, o.er.Interesting)
		if report.HWVendor == "" && len(o.er.Vendors) == 1 && len(o.er.Interesting) > 0 {
			report.HWVendor = o.er.Vendors[0]
			if len(targets[i].Products) > 0 {
				report.HWProduct = targets[i].Products[0]
			}
		}
		report.HTTPFindings = append(report.HTTPFindings, o.er)
	}

	if report.HWVendor == "" {
		if v, p, ok := bmcfp.MatchAll(map[bmcfp.Kind]string{
			bmcfp.HTTPServerHeader: serverHeader,
			bmcfp.HTMLTitle:        htmlTitle,
		}); ok {
			report.HWVendor = v
			report.HWProduct = p
			vendorScore[v]++
		}
	}

	report.HTTPVendors = sortedVendorScores(vendorScore)
	if report.HWVendor == "" && len(report.HTTPVendors) > 0 {
		report.HWVendor = report.HTTPVendors[0]
	}
	if len(report.HTTPFindings) == 0 {
		return report, nil
	}
	sort.Slice(report.HTTPFindings, func(i, j int) bool {
		if len(report.HTTPFindings[i].Interesting) != len(report.HTTPFindings[j].Interesting) {
			return len(report.HTTPFindings[i].Interesting) > len(report.HTTPFindings[j].Interesting)
		}
		return report.HTTPFindings[i].Path < report.HTTPFindings[j].Path
	})
	return report, nil
}

func doRequest(parent context.Context, client *http.Client, method, url string, timeout time.Duration, path string, tags []string) RequestResult {
	rr := RequestResult{Method: method, URL: url}
	var body io.Reader
	if method == http.MethodPost {
		body = bytes.NewBufferString("probe=1")
	}
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		rr.Error = err.Error()
		return rr
	}
	if method == http.MethodPost {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	resp, err := client.Do(req)
	if err != nil {
		rr.Error = err.Error()
		return rr
	}
	defer resp.Body.Close()

	readCap := int64(defaultBodyCap)
	if method != http.MethodHead {
		readCap = bodyCapFor(path, tags)
	}
	bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, readCap))
	rr.Status = resp.StatusCode
	rr.Server = resp.Header.Get("Server")
	rr.ContentType = resp.Header.Get("Content-Type")
	rr.Location = resp.Header.Get("Location")
	rr.BodyBytes = len(bodyBytes)
	rr.Snippet = trimSnippet(bodyBytes)
	rr.Body = retainBody(bodyBytes)

	if len(bodyBytes) > 0 && resp.StatusCode >= 200 && resp.StatusCode < 300 {
		rr.Fingerprint = FingerprintBody(path, tags, rr.ContentType, bodyBytes)
	}
	return rr
}

func classify(target AggregatedTarget, rr RequestResult) []string {
	if rr.Status == 0 {
		return nil
	}
	seen := map[string]struct{}{}

	scanText := rr.Body
	if scanText == "" {
		scanText = rr.Snippet
	}
	lowSnippet := strings.ToLower(scanText)
	statusClass := rr.Status / 100

	if statusClass == 2 && rr.Method != http.MethodPost && hasAny(target.Tags, "info", "static", "schema", "metadata", "fingerprint", "docs", "snapshot", "redfish", "config") && usefulReadableBody(rr, scanText) {
		seen["preAuthReadable"] = struct{}{}
	}
	if statusClass == 2 && rr.Method == http.MethodPost {
		seen["post-accepted"] = struct{}{}
	}
	if statusClass == 3 {
		seen["redirected"] = struct{}{}
	}
	if (rr.Status == http.StatusUnauthorized || rr.Status == http.StatusForbidden || rr.Status == http.StatusMethodNotAllowed || statusClass == 5) && hasAny(target.Tags, "dynamic", "rpc", "cgi", "login", "upload", "config", "rest", "wsman", "ipmi") {
		seen["handlerReachable"] = struct{}{}
	}
	if rr.Status != http.StatusNotFound && rr.Status != http.StatusNotImplemented && target.Match == MatchPrefix {
		seen["prefixLive"] = struct{}{}
	}
	if rr.Status != http.StatusNotFound && hasAny(target.Tags, "upload") {
		seen["upload-surface"] = struct{}{}
	}
	if concreteDataLeak(rr, scanText) {
		seen["possibleDataLeak"] = struct{}{}
	}

	if statusClass == 2 && rr.BodyBytes > 0 && !isHTMLResponse(rr.ContentType, scanText) && hasAny(target.Tags, "schema", "metadata", "archive", "snapshot") {
		seen["staticDisclosure"] = struct{}{}
	}

	if hasAny(target.Tags, "ikvm") && rr.Status != http.StatusNotFound && rr.Status != http.StatusNotImplemented {
		seen["kvm.launchExposed"] = struct{}{}
	}
	if hasAny(target.Tags, "ikvm", "jnlp") && (strings.Contains(lowSnippet, "kvmtoken") || strings.Contains(lowSnippet, "sessionkey") || strings.Contains(lowSnippet, "webcookie") || strings.Contains(lowSnippet, "-kvmport") || strings.Contains(lowSnippet, "kvm_port")) {
		seen["kvm.launchTokenLeak"] = struct{}{}
	}
	return setToSortedSlice(seen)
}

func usefulReadableBody(rr RequestResult, body string) bool {
	if strings.TrimSpace(body) == "" {
		return false
	}
	if !isHTMLResponse(rr.ContentType, body) {
		return true
	}
	fp := rr.Fingerprint
	return fp.Version != "" || fp.RedfishVersion != "" || fp.Product != "" || fp.Model != "" ||
		fp.Serial != "" || fp.Firmware != "" || fp.Manufacturer != ""
}

func concreteDataLeak(rr RequestResult, body string) bool {
	trimmed := strings.TrimSpace(body)
	if trimmed == "" || isHTMLResponse(rr.ContentType, trimmed) {
		return false
	}

	var value any
	if (strings.Contains(strings.ToLower(rr.ContentType), "json") || strings.HasPrefix(trimmed, "{") || strings.HasPrefix(trimmed, "[")) &&
		json.Unmarshal([]byte(trimmed), &value) == nil {
		return jsonHasLeakValue(value)
	}

	decoder := xml.NewDecoder(strings.NewReader(trimmed))
	leakElement := false
	for {
		token, err := decoder.Token()
		if err != nil {
			break
		}
		switch typed := token.(type) {
		case xml.StartElement:
			leakElement = isLeakKey(typed.Name.Local)
		case xml.CharData:
			if leakElement && meaningfulLeakValue(string(typed)) {
				return true
			}
		case xml.EndElement:
			leakElement = false
		}
	}

	for _, match := range leakAssignmentRE.FindAllStringSubmatch(trimmed, -1) {
		if len(match) > 1 && meaningfulLeakValue(match[1]) {
			return true
		}
	}
	return false
}

func jsonHasLeakValue(value any) bool {
	switch typed := value.(type) {
	case map[string]any:
		for key, child := range typed {
			if isLeakKey(key) {
				switch scalar := child.(type) {
				case string:
					if meaningfulLeakValue(scalar) {
						return true
					}
				case float64:
					return true
				}
			}
			if jsonHasLeakValue(child) {
				return true
			}
		}
	case []any:
		if slices.ContainsFunc(typed, jsonHasLeakValue) {
			return true
		}
	}
	return false
}

func isLeakKey(key string) bool {
	normalized := strings.NewReplacer("-", "", "_", "", ".", "", " ", "").Replace(strings.ToLower(key))
	switch normalized {
	case "token", "kvmtoken", "session", "sessionkey", "webcookie", "fwversion", "bmcversion",
		"firmware", "firmwareversion", "servicetag", "uuid", "serial", "serialnumber":
		return true
	default:
		return false
	}
}

func meaningfulLeakValue(value string) bool {
	value = strings.Trim(strings.TrimSpace(value), `"'`)
	switch strings.ToLower(value) {
	case "", "null", "none", "unknown", "n/a", "false", "expired", "session expired", "unauthorized", "not authorized":
		return false
	default:
		return true
	}
}

func isHTMLResponse(contentType, body string) bool {
	if strings.Contains(strings.ToLower(contentType), "html") {
		return true
	}
	prefix := strings.ToLower(strings.TrimSpace(body))
	return strings.HasPrefix(prefix, "<!doctype html") || strings.HasPrefix(prefix, "<html")
}

var leakAssignmentRE = regexp.MustCompile(`(?i)(?:token|session(?:key)?|webcookie|fwversion|bmcversion|firmware(?:version)?|servicetag|uuid|serial(?:number)?)[[:space:]]*[:=][[:space:]]*["']?([^"'[:space:]<>,;}{]+)`)

func updateSummary(summary *Summary, reasons []string) {
	if len(reasons) == 0 {
		return
	}
	summary.InterestingHits++
	for _, reason := range reasons {
		switch reason {
		case "preAuthReadable", "possibleDataLeak", "staticDisclosure", "kvm.launchTokenLeak":
			summary.PreAuthReadable++
		case "handlerReachable", "prefixLive", "kvm.launchExposed":
			summary.HandlerReachable++
		case "upload-surface":
			summary.UploadSurface++
		}
	}
}

func sortedVendorScores(scores map[string]int) []string {
	type kv struct {
		key string
		val int
	}
	items := make([]kv, 0, len(scores))
	for key, val := range scores {
		items = append(items, kv{key: key, val: val})
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].val != items[j].val {
			return items[i].val > items[j].val
		}
		return items[i].key < items[j].key
	})
	out := make([]string, 0, len(items))
	for _, item := range items {
		out = append(out, item.key)
	}
	return out
}

func setToSortedSlice(values map[string]struct{}) []string {
	out := make([]string, 0, len(values))
	for value := range values {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func hasAny(have []string, wants ...string) bool {
	for _, want := range wants {
		if slices.Contains(have, want) {
			return true
		}
	}
	return false
}

var titleRE = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)

func extractTitle(snippet string) string {
	m := titleRE.FindStringSubmatch(snippet)
	if len(m) < 2 {
		return ""
	}

	return strings.Join(strings.Fields(m[1]), " ")
}

func trimSnippet(body []byte) string {
	trimmed := strings.TrimSpace(string(body))
	trimmed = strings.ReplaceAll(trimmed, "\n", " ")
	trimmed = strings.ReplaceAll(trimmed, "\r", " ")
	trimmed = strings.Join(strings.Fields(trimmed), " ")
	return sanitize.TruncateString(trimmed, 200)
}

func retainBody(body []byte) string {
	if len(body) == 0 {
		return ""
	}
	b := make([]byte, 0, len(body))
	for i := range body {
		c := body[i]
		if c == '\n' || c == '\t' || (c >= 0x20 && c < 0x7f) {
			b = append(b, c)
		} else if c == '\r' {

			if i+1 < len(body) && body[i+1] == '\n' {
				continue
			}
			b = append(b, '\n')
		}

	}
	if len(b) > defaultBodyCap {
		b = b[:defaultBodyCap]
	}
	return string(b)
}

func hostPort(host string, port int, scheme string) string {
	if (scheme == "http" && port == 80) || (scheme == "https" && port == 443) {
		return netaddr.URLHost(host)
	}
	return netaddr.URLHostPort(host, port)
}

func defaultScheme(port int) string {
	return netaddr.DefaultScheme(port)
}
