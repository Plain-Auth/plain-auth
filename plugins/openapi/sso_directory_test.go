package openapi_test

import (
	"encoding/json"
	"net/http"
	"net/url"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/Stonewrit/stonewrit-auth"
	"github.com/Stonewrit/stonewrit-auth/adapters/sqlstore"
	"github.com/Stonewrit/stonewrit-auth/plugins/bearer"
	"github.com/Stonewrit/stonewrit-auth/plugins/openapi"
	"github.com/Stonewrit/stonewrit-auth/plugins/sso"
	"github.com/Stonewrit/stonewrit-auth/schema"
)

func TestEnterpriseDirectoryOpenAPI(t *testing.T) {
	_, empty := fixture(t, openapi.Options{})
	if node(schemaDoc(t, empty), "paths")["/sign-in/sso"] != nil {
		t.Fatal("enterprise sign-in published without the directory plugin")
	}
	for _, mode := range []string{"provider", "shared"} {
		t.Run(mode, func(t *testing.T) {
			const origin = "https://directory.example"
			must := func(e error) {
				t.Helper()
				if e != nil {
					t.Fatal(e)
				}
			}
			ddl, e := schema.Generate("sqlite", []string{"sso"})
			must(e)
			store, e := sqlstore.OpenWithSchema(t.Context(), "sqlite", filepath.Join(t.TempDir(), "directory.db"), ddl)
			must(e)
			t.Cleanup(func() { store.Close() })
			directory, e := sso.New(sso.Options{SharedCallback: mode == "shared"})
			must(e)
			reference, e := openapi.New(openapi.Options{})
			must(e)
			host, e := stonewrit.New(stonewrit.Options{BaseURL: origin, BasePath: "/identity", Store: store, Secret: strings.Repeat("a", 48), CookiePrefix: "portal", EmailAndPassword: true, RateLimit: new(bool), Plugins: []stonewrit.Plugin{directory, reference, bearer.New(bearer.Options{RequireSignature: true})}})
			must(e)
			wire := ssoWire{t, host, origin}
			paths := node(wire.decode(wire.call("GET", "/open-api/generate-schema", nil, nil, 200)), "paths")
			register := node(paths, "/sso/register", "post")
			bodySchema := func(op obj) obj { return node(op, "requestBody", "content", "application/json", "schema") }
			resultSchema := func(op obj) obj { return node(op, "responses", "200", "content", "application/json", "schema") }
			body := bodySchema(register)
			if node(body, "properties", "oidcConfig", "properties", "clientSecret")["writeOnly"] != true || !slices.Contains(body["required"].([]any), "oidcConfig") {
				t.Fatal("registration omitted the confidential OIDC request")
			}
			for _, op := range []obj{register, node(paths, "/sso/get-provider", "get"), node(paths, "/sso/providers", "get"), node(paths, "/sso/delete-provider", "post")} {
				secured := op["security"].([]any)
				if len(secured) != 2 || secured[0].(obj)["apiKeyCookie"] == nil || secured[1].(obj)["bearerAuth"] == nil {
					t.Fatalf("management security: %v", secured)
				}
				encoded, e := json.Marshal(resultSchema(op))
				must(e)
				if strings.Contains(string(encoded), "clientSecret") {
					t.Fatal("published a secret as a public response field")
				}
			}
			if node(resultSchema(register), "properties")["domainVerificationToken"] != nil {
				t.Fatal("DNS registration fields advertised without DNS")
			}
			if paths["/sso/callback/:providerId"] != nil {
				t.Fatal("published the router's private colon syntax")
			}
			for _, route := range []string{"/sso/callback", "/sso/callback/{providerId}"} {
				op := node(paths, route, "get")
				if op == nil || len(op["security"].([]any)) != 0 || node(op, "responses")["200"] != nil || node(op, "responses", "302", "headers", "Location") == nil {
					t.Fatal("invalid callback contract", route)
				}
				params := map[string]obj{}
				for _, v := range op["parameters"].([]any) {
					p := v.(obj)
					params[p["in"].(string)+"/"+p["name"].(string)] = p
				}
				if params["query/state"]["required"] != true || params["query/code"] == nil || params["query/error"] == nil || params["query/iss"] == nil || (params["path/providerId"] != nil) != (route == "/sso/callback/{providerId}") {
					t.Fatal("callback parameters", params)
				}
			}
			signin := node(paths, "/sign-in/sso", "post")
			if len(signin["security"].([]any)) != 0 || len(bodySchema(signin)["anyOf"].([]any)) != 4 || node(resultSchema(signin), "properties", "redirect")["const"] != true {
				t.Fatal("public sign-in contract")
			}
			query := node(paths, "/sso/get-provider", "get")["parameters"].([]any)[0].(obj)
			if query["in"] != "query" || query["name"] != "providerId" || query["required"] != true {
				t.Fatal("provider lookup missing selector")
			}
			anon := http.Header{}
			for _, path := range []string{"/sso/providers", "/sso/get-provider?providerId=tenant"} {
				wire.call("GET", path, nil, anon, 401)
			}
			wire.call("POST", "/sso/register", obj{}, anon, 401)
			wire.call("POST", "/sso/delete-provider", obj{"providerId": "tenant"}, anon, 401)
			signup := wire.call("POST", "/sign-up/email", obj{"name": "Owner", "email": "owner@example.org", "password": "a secure fixture password"}, anon, 200)
			var cookie *http.Cookie
			for _, c := range signup.Result().Cookies() {
				if strings.HasSuffix(c.Name, ".session_token") {
					cookie = c
				}
			}
			if cookie == nil || signup.Header().Get("Set-Auth-Token") == "" {
				t.Fatal("session credentials not issued")
			}
			owner := http.Header{"Cookie": {cookie.Name + "=" + cookie.Value}}
			authorized := http.Header{"Authorization": {"Bearer " + signup.Header().Get("Set-Auth-Token")}}
			const issuer = "https://issuer.example"
			const secret = "confidential test value"
			created := wire.call("POST", "/sso/register", obj{"providerId": "tenant", "domain": "example.org", "issuer": issuer, "oidcConfig": obj{"clientId": "directory-id", "clientSecret": secret, "skipDiscovery": true, "authorizationEndpoint": issuer + "/auth", "tokenEndpoint": issuer + "/token", "jwksEndpoint": issuer + "/keys"}}, owner, 200)
			if created.Header().Get("Cache-Control") != "no-store" || node(wire.decode(created), "oidcConfig")["clientSecret"] != secret {
				t.Fatal("confidential registration result changed")
			}
			view := wire.decode(wire.call("GET", "/sso/get-provider?providerId=tenant", nil, authorized, 200))
			list := wire.decode(wire.call("GET", "/sso/providers", nil, owner, 200))["providers"].([]any)
			if len(list) != 1 || list[0].(obj)["providerId"] != "tenant" || node(view, "oidcConfig")["clientIdLastFour"] != "****y-id" || node(view, "oidcConfig")["clientSecret"] != nil {
				t.Fatal("redacted public directory", view)
			}
			wire.call("POST", "/sign-in/sso", obj{"callbackURL": "/done"}, anon, 400)
			start := wire.call("POST", "/sign-in/sso", obj{"domain": "example.org", "callbackURL": "/done", "errorCallbackURL": "/problem"}, anon, 200)
			authURL, e := url.Parse(wire.decode(start)["url"].(string))
			must(e)
			target, e := url.Parse(authURL.Query().Get("redirect_uri"))
			must(e)
			want := "/sso/callback/tenant"
			template := "/sso/callback/{providerId}"
			if mode == "shared" {
				want = "/sso/callback"
				template = want
			}
			if target.Path != "/identity"+want || authURL.Query().Get("state") == "" {
				t.Fatal("wrong bound callback", target)
			}
			binding := start.Result().Cookies()[0]
			cookieDescribed := slices.ContainsFunc(node(paths, template, "get")["parameters"].([]any), func(value any) bool {
				p := value.(obj)
				return p["in"] == "cookie" && p["name"] == binding.Name && p["required"] == true
			})
			if !cookieDescribed {
				t.Fatal("callback omits actual browser binding", binding.Name)
			}
			back := wire.call("GET", want+"?"+url.Values{"state": {authURL.Query().Get("state")}, "error": {"access_denied"}}.Encode(), nil, http.Header{"Cookie": {binding.Name + "=" + binding.Value}}, 302)
			if !strings.HasPrefix(back.Header().Get("Location"), origin+"/problem?error=") {
				t.Fatal("provider error did not redirect to trusted error callback")
			}
			del := wire.decode(wire.call("POST", "/sso/delete-provider", obj{"providerId": "tenant"}, authorized, 200))
			if del["success"] != true || len(wire.decode(wire.call("GET", "/sso/providers", nil, owner, 200))["providers"].([]any)) != 0 {
				t.Fatal("directory was not deleted")
			}
		})
	}
}

func TestEnterpriseSAMLDocumentation(t *testing.T) {
	ddl, err := schema.Generate("sqlite", []string{"sso"})
	if err != nil {
		t.Fatal(err)
	}
	store, err := sqlstore.OpenWithSchema(t.Context(), "sqlite", filepath.Join(t.TempDir(), "saml.db"), ddl)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	for _, enabled := range []bool{false, true} {
		options := sso.Options{}
		if enabled {
			options.SAML = &sso.SAMLOptions{}
		}
		plugin, err := sso.New(options)
		if err != nil {
			t.Fatal(err)
		}
		reference, err := openapi.New(openapi.Options{})
		if err != nil {
			t.Fatal(err)
		}
		const origin = "https://saml.example.test"
		host, err := stonewrit.New(stonewrit.Options{BaseURL: origin, BasePath: "/identity", Store: store, Secret: strings.Repeat("a", 48), CookiePrefix: "portal", Plugins: []stonewrit.Plugin{plugin, reference}})
		if err != nil {
			t.Fatal(err)
		}
		wire := ssoWire{t, host, origin}
		paths := node(wire.decode(wire.call("GET", "/open-api/generate-schema", nil, nil, 200)), "paths")
		schema := node(paths, "/sso/register", "post", "requestBody", "content", "application/json", "schema")
		_, registered := node(schema, "properties")["samlConfig"]
		if registered != enabled {
			t.Fatal("wrong registration options", enabled)
		}
		const acs = "/sso/saml2/sp/acs/{providerId}"
		if _, ok := paths[acs]; ok != enabled {
			t.Fatalf("unexpected ACS route, enabled=%v", enabled)
		}
		if !enabled {
			continue
		}
		if len(schema["oneOf"].([]any)) != 2 {
			t.Fatal("missing mutually exclusive SSO protocols")
		}
		if node(paths, "/sso/saml2/sp/metadata", "get", "responses", "200", "content")["application/xml"] == nil {
			t.Fatal("missing XML metadata")
		}
		op := node(paths, acs, "post")
		if node(op, "requestBody", "content", "application/x-www-form-urlencoded", "schema", "properties")["RelayState"] == nil || node(op, "responses")["302"] == nil || node(op, "responses")["200"] != nil || len(op["security"].([]any)) != 0 {
			t.Fatal("incorrect callback response, transport or authentication")
		}
		params := op["parameters"].([]any)
		if params[0].(obj)["in"] != "path" || params[1].(obj)["in"] != "cookie" || !strings.HasSuffix(params[1].(obj)["name"].(string), "portal.saml_state") {
			t.Fatal("incorrect path or browser binding", params)
		}
	}
}
