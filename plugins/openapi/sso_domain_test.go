package openapi_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	auth "github.com/Stonewrit/stonewrit-auth"
	"github.com/Stonewrit/stonewrit-auth/adapters/sqlstore"
	"github.com/Stonewrit/stonewrit-auth/plugins/bearer"
	"github.com/Stonewrit/stonewrit-auth/plugins/openapi"
	"github.com/Stonewrit/stonewrit-auth/plugins/sso"
	"github.com/Stonewrit/stonewrit-auth/schema"
)

type domainTXT map[string][]string

func (records domainTXT) LookupTXT(_ context.Context, name string) ([]string, error) {
	return records[name], nil
}

func TestEnterpriseDomainVerificationContract(t *testing.T) {
	const requestPath = "/sso/request-domain-verification"
	const verifyPath = "/sso/verify-domain"
	for _, tc := range []struct {
		name                 string
		verification, bearer bool
	}{
		{name: "disabled"},
		{name: "cookie", verification: true},
		{name: "signed bearer", verification: true, bearer: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			profile := "sso"
			dns := domainTXT{}
			var options sso.Options
			if tc.verification {
				profile = "sso-domain-verification"
				options.DomainVerification = &sso.DomainVerificationOptions{TokenPrefix: "tenant-proof", Resolver: dns}
			}
			ddl, err := schema.Generate("sqlite", []string{profile})
			if err != nil {
				t.Fatal(err)
			}
			store, err := sqlstore.OpenWithSchema(t.Context(), "sqlite", filepath.Join(t.TempDir(), "auth.sqlite"), ddl)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { store.Close() })
			directory, err := sso.New(options)
			if err != nil {
				t.Fatal(err)
			}
			docs, err := openapi.New(openapi.Options{})
			if err != nil {
				t.Fatal(err)
			}
			plugins := []auth.Plugin{directory, docs}
			if tc.bearer {
				plugins = append(plugins, bearer.New(bearer.Options{RequireSignature: true}))
			}
			const origin = "https://directory.example"
			host, err := auth.New(auth.Options{BaseURL: origin, BasePath: "/identity", Secret: strings.Repeat("s", 48), Store: store, EmailAndPassword: true, CookiePrefix: "portal", RateLimit: new(bool), Plugins: plugins})
			if err != nil {
				t.Fatal(err)
			}
			wire := ssoWire{t, host, origin}
			call, decode := wire.call, wire.decode
			document := decode(call("GET", "/open-api/generate-schema", nil, nil, 200))
			page := call("GET", "/reference", nil, nil, 200).Body.String()
			paths := node(document, "paths")
			for _, path := range []string{requestPath, verifyPath} {
				if strings.Contains(page, path) != tc.verification || (paths[path] != nil) != tc.verification {
					t.Fatal("reference and schema disagree with installed DNS routes", path)
				}
				if !tc.verification {
					call("POST", path, obj{"providerId": "company"}, nil, 404)
					continue
				}
				op := node(paths, path, "post")
				rb := node(op, "requestBody")
				spec := node(rb, "content", "application/json", "schema")
				required, _ := spec["required"].([]any)
				if rb["required"] != true || !slices.Contains(required, any("providerId")) || node(spec, "properties", "providerId")["type"] != "string" {
					t.Fatal("providerId is missing from the required JSON request", path)
				}
				rules, _ := op["security"].([]any)
				names := map[string]bool{}
				for _, r := range rules {
					schemes, ok := r.(obj)
					if !ok || len(schemes) != 1 {
						t.Fatalf("%s advertises anonymous or combined credentials: %#v", path, r)
					}
					for name := range schemes {
						names[name] = true
					}
				}
				wantRules := 1
				if tc.bearer {
					wantRules++
				}
				if len(rules) != wantRules || !names["apiKeyCookie"] || names["bearerAuth"] != tc.bearer {
					t.Fatal("incorrect session credential alternatives", path, rules)
				}
				call("POST", path, obj{"providerId": "company"}, nil, 401)
			}
			if !tc.verification {
				return
			}
			schemes := node(document, "components", "securitySchemes")
			if node(schemes, "apiKeyCookie")["in"] != "cookie" || (schemes["bearerAuth"] != nil) != tc.bearer {
				t.Fatal("configured session schemes do not match routes")
			}
			requestResponses := node(paths, requestPath, "post", "responses")
			result := node(requestResponses, "201", "content", "application/json", "schema")
			required, _ := result["required"].([]any)
			if requestResponses["200"] != nil || !slices.Contains(required, any("domainVerificationToken")) || node(result, "properties", "domainVerificationToken")["type"] != "string" {
				t.Fatal("request-domain-verification must describe its 201 token")
			}
			verifyResponses := node(paths, verifyPath, "post", "responses")
			if verifyResponses["200"] != nil || verifyResponses["204"] == nil || node(verifyResponses, "204")["content"] != nil {
				t.Fatal("verify-domain must describe an empty 204 response")
			}

			signup := call("POST", "/sign-up/email", obj{"email": "owner@local.example", "name": "Owner", "password": "a fixture password"}, nil, 200)
			raw, ok := decode(signup)["token"].(string)
			if !ok || raw == "" {
				t.Fatal("signup did not issue a session")
			}
			var cookie *http.Cookie
			for _, c := range signup.Result().Cookies() {
				if strings.HasSuffix(c.Name, ".session_token") {
					cookie = c
				}
			}
			if cookie == nil || cookie.Name != node(schemes, "apiKeyCookie")["name"] {
				t.Fatal("documented cookie name differs from the issued session cookie")
			}
			cookieAuth := http.Header{"Cookie": {cookie.Name + "=" + cookie.Value}}
			bearerAuth := func(token string) http.Header { return http.Header{"Authorization": {"Bearer " + token}} }
			call("POST", "/sso/register", obj{"providerId": "company", "domain": "example.org", "issuer": "https://identity.example",
				"oidcConfig": obj{"clientId": "client", "clientSecret": "fixture", "skipDiscovery": true, "authorizationEndpoint": "https://identity.example/authorize", "tokenEndpoint": "https://identity.example/token", "jwksEndpoint": "https://identity.example/keys"}}, cookieAuth, 200)
			payload := obj{"providerId": "company"}
			for _, path := range []string{requestPath, verifyPath} {
				call("POST", path, obj{}, cookieAuth, 400)
				call("POST", path, payload, bearerAuth(raw), 401)
			}
			out := decode(call("POST", requestPath, payload, cookieAuth, 201))
			token, ok := out["domainVerificationToken"].(string)
			if !ok || token == "" {
				t.Fatal("201 response omitted the verification token")
			}
			credentials := cookieAuth
			if tc.bearer {
				signed := signup.Header().Get("Set-Auth-Token")
				if signed == "" || signed == raw {
					t.Fatal("missing signed bearer session")
				}
				credentials = bearerAuth(signed)
				if decode(call("POST", requestPath, payload, credentials, 201))["domainVerificationToken"] != token {
					t.Fatal("bearer challenge differs from the cookie challenge")
				}
			} else {
				call("POST", requestPath, payload, bearerAuth(cookie.Value), 401)
			}
			dns["_tenant-proof-company.example.org."] = []string{token}
			verified := call("POST", verifyPath, payload, credentials, 204)
			if verified.Body.Len() != 0 {
				t.Fatal("verify-domain wrote a body with HTTP 204")
			}
		})
	}
}

type ssoWire struct {
	t      *testing.T
	host   *auth.Auth
	origin string
}

func (f ssoWire) call(method, path string, body obj, headers http.Header, want int) *httptest.ResponseRecorder {
	f.t.Helper()
	var input bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&input).Encode(body); err != nil {
			f.t.Fatal(err)
		}
	}
	r := httptest.NewRequest(method, f.origin+"/identity"+path, &input)
	for key, values := range headers {
		for _, value := range values {
			r.Header.Add(key, value)
		}
	}
	r.Header.Set("Origin", f.origin)
	if body != nil {
		r.Header.Set("Content-Type", "application/json")
	}
	w := httptest.NewRecorder()
	f.host.ServeHTTP(w, r)
	if w.Code != want {
		f.t.Fatalf("%s %s: received %d, want %d", method, path, w.Code, want)
	}
	return w
}

func (f ssoWire) decode(w *httptest.ResponseRecorder) obj {
	f.t.Helper()
	var out obj
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		f.t.Fatal(err)
	}
	return out
}
