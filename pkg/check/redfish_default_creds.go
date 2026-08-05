package check

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/runZeroInc/oobscan/pkg/creds"
	"github.com/runZeroInc/oobscan/pkg/engine"
	"github.com/runZeroInc/oobscan/pkg/redfish"
)

func init() {
	Register(Check{
		Name:        "http.redfish.defaultCreds",
		Description: "Active Redfish default-credential login (SessionService POST, Basic fallback) -- vendor-targeted, online only",
		Category:    "creds",
		Applies:     Applicability{CrossVendor: true},
		Enabled:     true,
		Run:         runRedfishDefaultCreds,
	})
}

const maxRedfishAttempts = 8

func runRedfishDefaultCreds(ctx context.Context, t *engine.Target) []engine.Finding {
	debugf := func(string, ...any) {}
	if t != nil && t.DebugLog != nil {
		debugf = func(format string, args ...any) { t.DebugLog(fmt.Sprintf("redfish defaultCreds "+format, args...)) }
	}

	if t.DisableLogins {
		return nil
	}

	per := redfishDefaultCredsPerRequestTimeout(t.Timeout)
	budget := redfishDefaultCredsBudget(t.Timeout)
	started := time.Now()

	port := redfishPort(t)
	debugf("start host=%s port=%d timeout=%s budget=%s", t.Host, port, per, budget)
	base := redfish.BaseURL(t.Host, port)

	r := cachedRedfish(t)
	if r == nil {
		r, _ = redfish.ProbeAt(t.Host, port, per)
	}
	if !r.IsRedfish() {
		return nil
	}

	vendor := identityVendor(t)
	haveSuppliedCreds := len(suppliedCreds(t)) > 0
	vendorCreds := creds.VendorCredsFor(vendor, creds.ClassRedfish)
	if len(vendorCreds) == 0 {
		vendorCreds = creds.DocumentedDefaults(creds.ClassRedfish)
	}
	if len(vendorCreds) == 0 {
		return nil
	}

	client := redfish.InsecureClient(per)

	limit := maxRedfishAttempts
	if thr := redfish.AccountLockoutThreshold(client, base, redfishLockoutProbeTimeout(per)); thr > 0 && thr-1 < limit {
		limit = thr - 1
	}
	if limit < 1 {
		limit = 1
	}

	attempts := 0
	authPathChecked := false
	for _, c := range vendorCreds {
		if ctx.Err() != nil {
			debugf("cancelled err=%v", ctx.Err())
			return nil
		}
		if time.Since(started) >= budget {
			debugf("budget exhausted elapsed=%s attempts=%d", time.Since(started).Round(time.Millisecond), attempts)
			break
		}
		if c.Username == "" {
			continue
		}
		if attempts >= limit {
			break
		}
		attempts++

		remaining := budget - time.Since(started)
		attemptTimeout := per
		if remaining > 0 && remaining < attemptTimeout {
			attemptTimeout = remaining
		}
		if attemptTimeout < 500*time.Millisecond {
			debugf("attempt timeout too small remaining=%s", remaining.Round(time.Millisecond))
			break
		}
		debugf("attempt=%d user=%s source=%s timeout=%s", attempts, c.Username, c.Source, attemptTimeout)

		res := redfish.OpenSession(client, base, c.Username, c.Password, attemptTimeout)
		if !res.Authenticated {
			debugf("attempt=%d user=%s failed", attempts, c.Username)
			if !authPathChecked {
				authPathChecked = true
				diagTimeout := redfishAuthDiagnosticTimeout(attemptTimeout)
				st := redfish.ProbeAuthPathStatus(client, base, c.Username, c.Password, diagTimeout)
				if redfish.IsAuthPathErrorPattern(st) {

					if haveSuppliedCreds {
						continue
					}
					risk := redfishAuthPathRisk(redfish.VerifyCredential(client, base, c.Username, c.Password, diagTimeout))
					if t.SetEvidenceIfAbsent("redfish.authPathError", st) {
						resource := redfishAuthPathResource(st)
						return []engine.Finding{{
							Check: "http.redfish.authPathError", Category: "redfish", Risk: risk,
							Port: port, Transport: "tcp", Protocol: "redfish",
							Fields: engine.F(
								"username", c.Username,
								"source", c.Source,
								"resource", resource,
								"unauthStatus", fmt.Sprintf("%d", st.UnauthStatus),
								"basicStatus", fmt.Sprintf("%d", st.BasicStatus),
								"sessionStatus", fmt.Sprintf("%d", st.SessionStatus),
								"challenge", st.Challenge,
								"proof", redfishAuthPathProof(st),
							),
						}}
					}
				}
			}
			continue
		}

		hdrs := readHeaderFor(res, c.Username, c.Password)
		info := redfish.PullSystemInfo(client, base, hdrs, c.Username, attemptTimeout)
		redfish.DeleteSession(client, base, res.SessionURI, res.Token, redfishSessionDeleteTimeout(attemptTimeout))
		t.SetEvidence("redfish.postAuth", &redfish.PostAuthSnapshot{
			Method: "defaultCreds",
			Via:    res.Via,
			User:   c.Username,
			Source: c.Source,
			Info:   info,
		})

		passField := c.Password
		if passField == "" {
			passField = "(blank)"
		}

		return []engine.Finding{{
			Check: "http.redfish.defaultCreds", Category: "creds", Risk: "critical",
			Port: port, Transport: "tcp", Protocol: "redfish",
			Fields: engine.F(
				"username", c.Username,
				"password", passField,
				"loginVia", res.Via,
				"source", c.Source,
				"proof", redfishDefaultCredsProof(res, info)),
			CVE: cveOrNil(c.CVE),
		}}
	}
	debugf("done no-credential matched attempts=%d elapsed=%s", attempts, time.Since(started).Round(time.Millisecond))
	return nil
}

func redfishDefaultCredsProof(res redfish.SessionResult, info redfish.SystemInfo) string {
	status := ""
	if res.Status > 0 {
		status = strconv.Itoa(res.Status)
	}
	tokenLen := ""
	if res.Via == "session" && res.Token != "" {
		tokenLen = strconv.Itoa(len(res.Token))
	}
	return proofKV(
		"auth", res.Via,
		"resource", "admin",
		"status", status,
		"tokenLen", tokenLen,
		"vendor", info.Vendor,
		"model", info.Model,
		"firmwareVersion", info.FirmwareVersion,
		"product", info.Product,
		"serialNumber", info.SerialNumber,
		"redfishVersion", info.RedfishVersion,
		"serviceUuid", info.ServiceUUID,
		"managerId", info.ManagerID,
		"systemId", info.SystemID,
		"biosVersion", info.BIOSVersion,
		"powerState", info.PowerState,
		"accountRole", info.AccountRole,
		"accountEnabled", info.AccountEnabled,
	)
}

func redfishDefaultCredsPerRequestTimeout(scanTimeout time.Duration) time.Duration {
	if scanTimeout <= 0 {
		return 2 * time.Second
	}
	if scanTimeout > 2*time.Second {
		return 2 * time.Second
	}
	if scanTimeout < 900*time.Millisecond {
		return 900 * time.Millisecond
	}
	return scanTimeout
}

func redfishDefaultCredsBudget(scanTimeout time.Duration) time.Duration {
	if scanTimeout <= 0 {
		return 12 * time.Second
	}
	b := min(max(scanTimeout*3, 8*time.Second), 15*time.Second)
	return b
}

func redfishLockoutProbeTimeout(per time.Duration) time.Duration {
	if per > 1200*time.Millisecond {
		return 1200 * time.Millisecond
	}
	if per < 600*time.Millisecond {
		return 600 * time.Millisecond
	}
	return per
}

func redfishAuthDiagnosticTimeout(per time.Duration) time.Duration {
	if per > 1500*time.Millisecond {
		return 1500 * time.Millisecond
	}
	if per < 700*time.Millisecond {
		return 700 * time.Millisecond
	}
	return per
}

func redfishSessionDeleteTimeout(per time.Duration) time.Duration {
	if per > time.Second {
		return time.Second
	}
	if per < 400*time.Millisecond {
		return 400 * time.Millisecond
	}
	return per
}

func redfishAuthPathRisk(verified bool) string {
	if verified {
		return "critical"
	}
	return "info"
}

func redfishAuthPathResource(st redfish.AuthPathStatus) string {
	if st.Resource != "" {
		return st.Resource
	}
	return "/redfish/v1/Managers"
}

func redfishAuthPathProof(st redfish.AuthPathStatus) string {
	status := st.BasicStatus
	if status < 500 && st.SessionStatus >= 500 {
		status = st.SessionStatus
	}
	return proofKV(
		"errorStatus", strconv.Itoa(status),
		"resource", redfishAuthPathResource(st),
		"unauthStatus", strconv.Itoa(st.UnauthStatus),
		"basicStatus", strconv.Itoa(st.BasicStatus),
		"sessionStatus", strconv.Itoa(st.SessionStatus))
}

func cachedRedfish(t *engine.Target) *redfish.Result {
	if v, ok := t.Evidenced("redfish"); ok {
		if r, ok := v.(*redfish.Result); ok {
			return r
		}
	}
	return nil
}

func redfishPort(t *engine.Target) int {
	for k, v := range t.OpenSnapshot() {
		if !strings.Contains(v, "redfish") {
			continue
		}
		if i := strings.IndexByte(k, '/'); i > 0 {
			if n, err := strconv.Atoi(k[:i]); err == nil && n > 0 {
				return n
			}
		}
	}
	return webPort(t)
}

func readHeaderFor(res redfish.SessionResult, username, password string) map[string]string {
	if res.Token != "" {
		return map[string]string{"X-Auth-Token": res.Token}
	}
	req, _ := http.NewRequest(http.MethodGet, "http://x/", nil)
	req.SetBasicAuth(username, password)
	return map[string]string{"Authorization": req.Header.Get("Authorization")}
}

func cveOrNil(cve string) []string {
	if cve == "" {
		return nil
	}
	return []string{cve}
}

func init() {
	RegisterExplain("http.redfish.defaultCreds", explainRedfishDefaultCreds)
	RegisterExplain("http.redfish.authPathError", explainRedfishAuthPathError)
}

func explainRedfishDefaultCreds(host string, f engine.Finding) string {
	port := explainPortOrDefault(f, 443)
	user := explainField(f, "username")
	pass := explainField(f, "password")
	via := explainField(f, "loginVia")
	baseURL := explainBaseURL(host, f, port, "https")
	var b strings.Builder
	b.WriteString(explainHeading(host, f))
	b.WriteString(fmt.Sprintf("\nRedfish API accepted the default credential **%s / %s**", user, pass))
	if via != "" {
		b.WriteString(fmt.Sprintf(" (via %s)", via))
	}
	b.WriteString(".\n")
	b.WriteString("\n**Validate (create a session):**\n")
	b.WriteString(explainSh(
		fmt.Sprintf(`curl -sk -X POST %s/redfish/v1/SessionService/Sessions \`, baseURL),
		`  -H "Content-Type: application/json" \`,
		fmt.Sprintf(`  -d '{"UserName":"%s","Password":"%s"}'`, user, pass),
	))
	b.WriteString("\n\n**Browse the API:**\n")
	b.WriteString(explainSh(
		fmt.Sprintf("curl -sk -u '%s:%s' %s/redfish/v1/Systems/ | python3 -m json.tool", user, pass, baseURL),
		fmt.Sprintf("curl -sk -u '%s:%s' %s/redfish/v1/Managers/ | python3 -m json.tool", user, pass, baseURL),
	))
	b.WriteString("\n\n**Impact:** Full Redfish API access -- power control, firmware update, user management.\n")
	return b.String()
}

func explainRedfishAuthPathError(host string, f engine.Finding) string {
	baseURL := explainBaseURL(host, f, explainPortOrDefault(f, 443), "https")
	var b strings.Builder
	b.WriteString(explainHeading(host, f))
	b.WriteString("\nThe Redfish service correctly challenges unauthenticated admin resources but\n")
	b.WriteString("returns server errors on authenticated/session auth paths, indicating a broken\n")
	b.WriteString("or crash-prone authentication handler.\n")
	b.WriteString("\n**Validate differential:**\n")
	b.WriteString(explainSh(
		fmt.Sprintf("curl -sk -D - %s/redfish/v1/AccountService/Accounts -o /dev/null", baseURL),
		fmt.Sprintf("curl -sk -D - -u 'ADMIN:ADMIN' %s/redfish/v1/AccountService/Accounts -o /dev/null", baseURL),
		fmt.Sprintf(`curl -sk -D - -H "Content-Type: application/json" -X POST %s/redfish/v1/SessionService/Sessions -d '{"UserName":"ADMIN","Password":"ADMIN"}' -o /dev/null`, baseURL),
	))
	b.WriteString("\n\n**Impact:** Redfish authentication path is unstable (reliable credential verification may fail;\n")
	b.WriteString("potential denial-of-service surface in auth handling).\n")
	return b.String()
}
