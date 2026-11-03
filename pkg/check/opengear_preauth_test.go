package check

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/runZeroInc/oobscan/pkg/engine"
)

func TestOpengearExtract(t *testing.T) {
	// Bare JSON string.
	if v := opengearExtract("model_name", []byte(`"OM2224-24E"`)); v != "OM2224-24E" {
		t.Errorf("bare string model = %q", v)
	}
	// Flat object.
	if v := opengearExtract("model_name", []byte(`{"model_name":"CM7196A"}`)); v != "CM7196A" {
		t.Errorf("flat object model = %q", v)
	}
	// Nested wrapper.
	if v := opengearExtract("model_name", []byte(`{"system":{"model_name":"IM7248"}}`)); v != "IM7248" {
		t.Errorf("nested model = %q", v)
	}
	// Confirmed real OM/NGCS shapes (Opengear REST API spec): the model and banner
	// are wrapped under system_model_name / system_banner.
	if v := opengearExtract("model_name", []byte(`{"system_model_name":{"model_name":"OM2224-24E"}}`)); v != "OM2224-24E" {
		t.Errorf("system_model_name wrapper = %q", v)
	}
	if v := opengearExtract("banner", []byte(`{"system_banner":{"banner":"Authorized only"}}`)); v == "" {
		t.Error("system_banner wrapper should be captured")
	}
	if v := opengearExtract("local_password_policy", []byte(`{"local_password_policy":{"password_minimum_length":8}}`)); v == "" {
		t.Error("local_password_policy wrapper should be summarized")
	}
	// Password policy object -> summarized (non-empty).
	if v := opengearExtract("local_password_policy", []byte(`{"min_length":8,"complexity":true}`)); v == "" {
		t.Error("password policy object should be summarized, not dropped")
	}
	// Banner free-form text.
	if v := opengearExtract("banner", []byte(`"Authorized users only"`)); v == "" {
		t.Error("banner string should be captured")
	}
	// Empty / no data.
	if v := opengearExtract("model_name", []byte(`{}`)); v != "" {
		t.Errorf("empty object should yield no value, got %q", v)
	}
	if v := opengearExtract("banner", []byte(`{"ret":"failed","data":false,"error":{"webStatus":"noauth"}}`)); v != "" {
		t.Errorf("API error should yield no value, got %q", v)
	}
}

func opengearTarget(t *testing.T, srvURL string) *engine.Target {
	t.Helper()
	host, portStr, err := net.SplitHostPort(strings.TrimPrefix(srvURL, "http://"))
	if err != nil {
		t.Fatalf("split %q: %v", srvURL, err)
	}
	return &engine.Target{
		Host:    host,
		Timeout: 2 * time.Second,
		Identity: &engine.Identity{
			Vendor:     "opengear",
			Class:      engine.ClassSerialConsole,
			Attributes: map[string]string{"web.port": portStr, "web.scheme": "http"},
		},
	}
}

func TestRunOpengearPreauth(t *testing.T) {
	// Vulnerable: the REST endpoints answer unauthenticated JSON.
	vuln := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasSuffix(r.URL.Path, "/system/model_name"):
			// Confirmed OM/NGCS wrapper shape.
			_, _ = w.Write([]byte(`{"system_model_name":{"model_name":"OM2224-24E"}}`))
		case strings.HasSuffix(r.URL.Path, "/system/banner"):
			_, _ = w.Write([]byte(`{"system_banner":{"banner":"Authorized access only"}}`))
		case strings.HasSuffix(r.URL.Path, "/local_password_policy"):
			_, _ = w.Write([]byte(`{"local_password_policy":{"password_minimum_length":8,"password_complexity_enabled":true}}`))
		default:
			http.Error(w, "no", http.StatusNotFound)
		}
	}))
	defer vuln.Close()

	got := runOpengearPreauth(context.Background(), opengearTarget(t, vuln.URL))
	f := hasFinding(got, "http.opengear.preAuthLeak")
	if f == nil {
		t.Fatal("expected opengear.preAuthLeak when the REST endpoints leak unauthenticated")
	}
	if f.Risk != "low" {
		t.Errorf("risk = %s, want low", f.Risk)
	}
	// The model must be captured in the fields.
	var sawModel bool
	for _, fl := range f.Fields {
		if fl.Key == "model_name" && strings.Contains(fl.Val, "OM2224") {
			sawModel = true
		}
	}
	if !sawModel {
		t.Errorf("expected the leaked model in the finding fields, got %v", f.Fields)
	}

	// Patched: everything requires auth (401 / login HTML) -> no finding.
	safe := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte("<html>login</html>"))
	}))
	defer safe.Close()
	if got := runOpengearPreauth(context.Background(), opengearTarget(t, safe.URL)); len(got) != 0 {
		t.Errorf("expected no finding on an auth-gated appliance, got %v", got)
	}
}

func TestRunOpengearTestStub(t *testing.T) {
	vuln := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && (r.URL.Path == "/api/v1/test" || r.URL.Path == "/api/v2/test") {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"ok":true}`))
			return
		}
		http.NotFound(w, r)
	}))
	defer vuln.Close()

	got := runOpengearTestStub(context.Background(), opengearTarget(t, vuln.URL))
	f := hasFinding(got, "http.opengear.testStub")
	if f == nil {
		t.Fatalf("expected opengear.testStub finding, got %+v", got)
	}
	if f.Risk != "info" {
		t.Errorf("risk = %s, want info", f.Risk)
	}

	patched := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte("auth required"))
	}))
	defer patched.Close()
	if got := runOpengearTestStub(context.Background(), opengearTarget(t, patched.URL)); len(got) != 0 {
		t.Fatalf("expected no finding on auth-gated endpoint, got %+v", got)
	}

	for name, response := range map[string]struct {
		contentType string
		body        string
	}{
		"unrelated HTML":   {contentType: "text/html", body: `<title>NPort Web Console</title>`},
		"API noauth error": {contentType: "application/json", body: `{"ret":"failed","data":false,"error":{"webStatus":"noauth"}}`},
	} {
		t.Run(name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", response.contentType)
				_, _ = w.Write([]byte(response.body))
			}))
			defer server.Close()
			if got := runOpengearTestStub(context.Background(), opengearTarget(t, server.URL)); len(got) != 0 {
				t.Fatalf("expected no finding for %s, got %+v", name, got)
			}
		})
	}
}

func TestLooksLikeJSON(t *testing.T) {
	if !looksLikeJSON([]byte(`  {"a":1}`)) || !looksLikeJSON([]byte(`["x"]`)) || !looksLikeJSON([]byte(`"s"`)) {
		t.Error("JSON bodies should be detected")
	}
	if looksLikeJSON([]byte(`<html>`)) {
		t.Error("HTML must not be detected as JSON")
	}
}
