package openapi_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	auth "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/adapters/memory"
	"github.com/Plain-Org/plain-auth/plugins/bearer"
	"github.com/Plain-Org/plain-auth/plugins/openapi"
)

type obj = map[string]any

func fixture(t *testing.T, config openapi.Options, extra ...auth.Plugin) (*auth.Auth, *httptest.Server) {
	t.Helper()
	p, err := openapi.New(config)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(nil)
	t.Cleanup(server.Close)
	a, err := auth.New(auth.Options{BaseURL: "http://" + server.Listener.Addr().String(), BasePath: "/identity", Secret: strings.Repeat("a", 48), Store: memory.New(), EmailAndPassword: true, DeferSessionRefresh: true, MinPasswordLength: 10, MaxPasswordLength: 99, CookiePrefix: "portal", Plugins: append([]auth.Plugin{p}, extra...)})
	if err != nil {
		t.Fatal(err)
	}
	server.Config.Handler = a
	server.Start()
	return a, server
}

func get(t *testing.T, s *httptest.Server, path string) (*http.Response, []byte) {
	t.Helper()
	r, err := s.Client().Get(s.URL + path)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Body.Close()
	b, err := io.ReadAll(r.Body)
	if err != nil {
		t.Fatal(err)
	}
	return r, b
}

func schemaDoc(t *testing.T, s *httptest.Server) obj {
	t.Helper()
	r, b := get(t, s, "/identity/open-api/generate-schema")
	if r.StatusCode != 200 || !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		t.Fatalf("schema: %d %s", r.StatusCode, b)
	}
	var doc obj
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	return doc
}
func node(v obj, keys ...string) obj {
	for _, k := range keys {
		v, _ = v[k].(obj)
	}
	return v
}

func TestMountedSchemaAndPublicModels(t *testing.T) {
	p, err := auth.NewUsername(auth.UsernameOptions{DisableDisplay: true})
	if err != nil {
		t.Fatal(err)
	}
	raw := json.RawMessage(`{"operationId":"getReport","summary":"Review <billing>","responses":{"200":{"description":"Report","content":{"application/json":{"schema":{"type":"boolean"}}}}}}`)
	custom := auth.Plugin{ID: "report", Endpoints: []auth.Endpoint{{Method: "GET", Path: "/report", OpenAPI: raw, Handler: func(auth.EndpointContext) (any, error) { return true, nil }}}}
	a, s := fixture(t, openapi.Options{}, p, bearer.New(bearer.Options{}), custom)
	raw[0] = '['
	doc := schemaDoc(t, s)
	paths := node(doc, "paths")
	if doc["openapi"] != "3.1.1" || doc["servers"].([]any)[0].(obj)["url"] != s.URL+"/identity" {
		t.Fatal("incorrect mount or version")
	}
	for _, path := range []string{"/reference", "/open-api/generate-schema", "/organization/list", "/sign-in/social", "/change-email", "/delete-user"} {
		if paths[path] != nil {
			t.Fatal("advertised disabled route", path)
		}
	}
	for _, path := range []string{"/report", "/sign-in/username", "/reset-password/{token}", "/sign-up/email", "/get-session"} {
		if paths[path] == nil {
			t.Fatal("missing route", path)
		}
	}
	if node(paths, "/get-session", "post") == nil || node(paths, "/report", "get")["operationId"] != "getReport" {
		t.Fatal("missing deferred/custom operation")
	}
	if len(node(paths, "/sign-up/email", "post")["security"].([]any)) != 0 {
		t.Fatal("signup advertised a mandatory credential")
	}
	sec := node(paths, "/list-sessions", "get")["security"].([]any)
	if len(sec) != 2 || sec[0].(obj)["apiKeyCookie"] == nil || sec[1].(obj)["bearerAuth"] == nil {
		t.Fatal("credential alternatives", sec)
	}
	schemes := node(doc, "components", "securitySchemes")
	if node(schemes, "apiKeyCookie")["name"] != "portal.session_token" || node(schemes, "bearerAuth")["scheme"] != "bearer" {
		t.Fatal(schemes)
	}
	body := node(paths, "/sign-up/email", "post", "requestBody", "content")
	for _, media := range []string{"application/json", "application/x-www-form-urlencoded"} {
		sc := node(body, media, "schema")
		props := node(sc, "properties")
		req := sc["required"].([]any)
		if !slices.Contains(req, any("email")) || !slices.Contains(req, any("name")) || !slices.Contains(req, any("password")) {
			t.Fatal("required registration fields", req)
		}
		if node(props, "password")["minLength"] != float64(10) || node(props, "password")["maxLength"] != float64(99) || node(props, "email")["format"] != "email" || props["username"] == nil || props["displayUsername"] != nil {
			t.Fatal(props)
		}
	}
	user := node(doc, "components", "schemas", "User", "properties")
	if node(user, "createdAt")["format"] != "date-time" || user["username"] == nil || user["role"] != nil || user["displayUsername"] != nil {
		t.Fatal(user)
	}
	account := node(doc, "components", "schemas", "Account", "properties")
	if account["password"] != nil || account["accessToken"] != nil || account["providerId"] == nil {
		t.Fatal("account schema advertised private storage")
	}
	errSchema := node(doc, "components", "schemas", "Error")
	if !slices.Contains(errSchema["required"].([]any), any("message")) || slices.Contains(errSchema["required"].([]any), any("code")) {
		t.Fatal("optional error code", errSchema)
	}
	if node(paths, "/list-sessions", "get", "responses", "default")["$ref"] != "#/components/responses/Error" {
		t.Fatal("error responses")
	}
	if r, _ := get(t, s, "/identity/report"); r.StatusCode != 200 {
		t.Fatal(r.StatusCode)
	}
	r, err := s.Client().PostForm(s.URL+"/identity/sign-up/email", url.Values{"name": {"R"}, "email": {"r@example.test"}, "password": {"good-password"}})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Body.Close()
	if r.StatusCode != 200 {
		t.Fatal("advertised form request failed", r.Status)
	}
	var result obj
	if err := json.NewDecoder(r.Body).Decode(&result); err != nil {
		t.Fatal(err)
	}
	for _, key := range node(doc, "components", "schemas", "User")["required"].([]any) {
		if _, ok := result["user"].(obj)[key.(string)]; !ok {
			t.Fatal("missing advertised user field", key)
		}
	}
	reports := a.DescribeHTTP().Routes
	for _, op := range reports {
		if op.Path == "/report" {
			op.OpenAPI[0] = 'x'
		}
	}
	if node(schemaDoc(t, s), "paths", "/report", "get")["operationId"] != "getReport" {
		t.Fatal("metadata mutated after registration")
	}
}

func TestReferencePolicyAndOptions(t *testing.T) {
	_, s := fixture(t, openapi.Options{Path: "/docs", Theme: "moon", Nonce: "reference123"})
	r, b := get(t, s, "/identity/docs")
	page := string(b)
	if r.StatusCode != 200 || !strings.HasPrefix(r.Header.Get("Content-Type"), "text/html") || !strings.Contains(page, `data-theme="moon"`) || !strings.Contains(page, `nonce="reference123"`) || !strings.Contains(r.Header.Get("Content-Security-Policy"), "'nonce-reference123'") || !strings.Contains(page, `href="/identity/open-api/generate-schema"`) {
		t.Fatal("reference page configuration")
	}
	if strings.Contains(page, "<script src=") || strings.Contains(page, "cdn.jsdelivr.net") {
		t.Fatal("external reference runtime")
	}
	_, s = fixture(t, openapi.Options{DisableDefaultReference: true})
	if r, _ := get(t, s, "/identity/reference"); r.StatusCode != 404 {
		t.Fatal("disabled reference", r.Status)
	}
	schemaDoc(t, s)
	for _, options := range []openapi.Options{{Path: "/"}, {Path: "//other"}, {Path: "/a?x"}, {Nonce: "unsafe nonce"}, {Theme: "invalid"}} {
		if _, err := openapi.New(options); err == nil {
			t.Fatalf("invalid options accepted: %+v", options)
		}
	}
}

func TestConcurrentSchemaGeneration(t *testing.T) {
	a, _ := fixture(t, openapi.Options{})
	var g sync.WaitGroup
	for range 12 {
		g.Add(1)
		go func() {
			defer g.Done()
			doc, err := openapi.Generate(a)
			if err != nil {
				t.Error(err)
				return
			}
			delete(doc["paths"].(obj), "/ok")
		}()
	}
	g.Wait()
	doc, err := openapi.Generate(a)
	if err != nil || node(doc, "paths", "/ok", "get") == nil {
		t.Fatal("concurrent callers shared schema state", err)
	}
}

func TestChromeReferenceFilter(t *testing.T) {
	chrome := os.Getenv("CHROME_BIN")
	if chrome == "" {
		t.Skip("CHROME_BIN selects the local Chrome executable")
	}
	_, s := fixture(t, openapi.Options{Path: "/browser", Theme: "solarized"})
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, chrome, "--headless", "--disable-gpu", "--disable-background-networking", "--no-first-run", "--no-default-browser-check", "--user-data-dir="+t.TempDir(), "--dump-dom", s.URL+"/identity/browser?q=sign-up%2Femail")
	dom, err := cmd.Output()
	if err != nil {
		t.Fatal("headless browser", err)
	}
	view := string(dom)
	if !strings.Contains(view, `<details hidden="">`) || !strings.Contains(view, "<details><summary><strong>POST</strong> <code>/sign-up/email</code>") || !strings.Contains(view, `data-theme="solarized"`) {
		t.Fatal("Chrome did not filter operations under the nonce CSP")
	}
}

func TestOAuthProxyCompletionSchema(t *testing.T) {
	proxy, err := auth.NewOAuthProxy(auth.OAuthProxyOptions{ProductionURL: "https://login.example.test"})
	if err != nil {
		t.Fatal(err)
	}
	a, server := fixture(t, openapi.Options{}, proxy)
	doc := schemaDoc(t, server)
	scheme := node(doc, "components", "securitySchemes", "oauthProxyState")
	if scheme["in"] != "cookie" || scheme["name"] != a.DescribeHTTP().OAuthProxyStateCookie || scheme["name"] == "" {
		t.Fatal("missing binding cookie", scheme)
	}
	for path, operation := range map[string]string{
		"/callback/{id}/oauth-proxy": "oauthProxyCompletion",
		"/oauth-proxy-callback":      "oauthProxyCallback",
	} {
		op := node(doc, "paths", path, "get")
		if op["operationId"] != operation || node(op, "responses", "302") == nil || node(op, "responses", "200") != nil {
			t.Fatal("incorrect redirect operation", path)
		}
		sec := op["security"].([]any)
		if len(sec) != 1 || sec[0].(obj)["oauthProxyState"] == nil {
			t.Fatal("missing state binding requirement", path)
		}
		parameters := map[string]any{}
		for _, value := range op["parameters"].([]any) {
			p := value.(obj)
			if p["required"] != true {
				t.Fatal("optional callback parameter", p["name"])
			}
			parameters[p["name"].(string)] = p["in"]
		}
		if parameters["callbackURL"] != "query" || parameters["profile"] != "query" || (parameters["id"] == "path") != (operation == "oauthProxyCompletion") {
			t.Fatal("incorrect parameters", path, parameters)
		}
	}
}

// Core operations carry the Default tag and plugin operations the plugin ID
// with its first letter capitalized; an endpoint's own tags replace it, and
// the document lists the Default group.
func TestOperationTags(t *testing.T) {
	name, err := auth.NewUsername(auth.UsernameOptions{})
	if err != nil {
		t.Fatal(err)
	}
	ok := func(auth.EndpointContext) (any, error) { return true, nil }
	custom := auth.Plugin{ID: "billing-report", Endpoints: []auth.Endpoint{
		{Method: "GET", Path: "/billing/summary", Handler: ok},
		{Method: "GET", Path: "/billing/export", OpenAPI: json.RawMessage(`{"operationId":"exportBilling","tags":["Billing","Exports"]}`), Handler: ok},
	}}
	_, s := fixture(t, openapi.Options{}, name, custom)
	doc := schemaDoc(t, s)
	for _, tc := range []struct {
		path, method string
		want         []string
	}{
		{"/sign-up/email", "post", []string{"Default"}},
		{"/get-session", "get", []string{"Default"}},
		{"/sign-in/username", "post", []string{"Username"}},
		{"/billing/summary", "get", []string{"Billing-report"}},
		{"/billing/export", "get", []string{"Billing", "Exports"}},
	} {
		raw, _ := node(doc, "paths", tc.path, tc.method)["tags"].([]any)
		var got []string
		for _, tag := range raw {
			got = append(got, tag.(string))
		}
		if !slices.Equal(got, tc.want) {
			t.Fatal("operation tags", tc.path, got)
		}
	}
	groups, _ := doc["tags"].([]any)
	if len(groups) != 1 || groups[0].(obj)["name"] != "Default" || groups[0].(obj)["description"] == "" {
		t.Fatal("document tag groups", groups)
	}
}
