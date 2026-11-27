package sqlstore

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/Plain-Org/plain-auth/client"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	auth "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/plugins/admin"
	org "github.com/Plain-Org/plain-auth/plugins/organization"
	"github.com/Plain-Org/plain-auth/plugins/sso"
	"github.com/Plain-Org/plain-auth/schema"
)

func TestEnterpriseProviderManagement(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			ctx := t.Context()
			must := func(e error) {
				t.Helper()
				if e != nil {
					t.Fatal(e)
				}
			}
			dsn := organizationTestDSN(t, dialect)
			initial, e := schema.Generate(dialect, []string{"organization"})
			must(e)
			before, e := OpenWithSchema(ctx, dialect, dsn, initial)
			must(e)
			now := time.Now().UTC()
			must(before.CreateUser(ctx, auth.User{ID: "kept-owner", Email: "previous@example.test", Name: "Existing", CreatedAt: now, UpdatedAt: now}, "credential", nil))
			must(before.Close())
			ddl, e := schema.Generate(dialect, []string{"organization", "sso", "admin"})
			must(e)
			a, e := OpenWithSchema(ctx, dialect, dsn, ddl)
			must(e)
			defer a.Close()
			b, e := OpenWithSchema(ctx, dialect, dsn, ddl)
			must(e)
			defer b.Close()
			_, e = a.FindAccountUser(ctx, "previous@example.test")
			must(e)
			entered, release := make(chan struct{}), make(chan struct{})
			var fetched atomic.Int32
			var idp *httptest.Server
			idp = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				fetched.Add(1)
				switch r.URL.Path {
				case "/wait":
					close(entered)
					<-release
				case "/error":
					http.Redirect(w, r, "/not-requested", http.StatusTemporaryRedirect)
					return
				case "/missing":
					http.NotFound(w, r)
					return
				case "/broken":
					http.Error(w, "unavailable", http.StatusInternalServerError)
					return
				}
				issuer := idp.URL
				if r.URL.Path == "/mismatch" {
					issuer += "/wrong"
				}
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(map[string]any{"issuer": issuer, "authorization_endpoint": "/authorize", "token_endpoint": "/token", "jwks_uri": "/keys", "token_endpoint_auth_methods_supported": []string{"client_secret_post"}})
			}))
			defer idp.Close()
			build := func(s *Store, limit int) *auth.Auth {
				plugin, e := sso.New(sso.Options{ProvidersLimit: &limit})
				must(e)
				organization, e := org.New(org.Options{Store: s})
				must(e)
				management, e := admin.New(admin.Options{})
				must(e)
				host, e := auth.New(auth.Options{BaseURL: "https://enterprise.test", BasePath: "/identity", TrustedOrigins: []string{idp.URL}, Store: s, Secret: strings.Repeat("x", 32), EmailAndPassword: true, Plugins: []auth.Plugin{organization, plugin, management},
					TrustedProviders: []string{"Partner"}})
				must(e)
				return host
			}
			one, two := build(a, 2), build(b, 2)
			p, e := sso.New(sso.Options{})
			must(e)
			catalogOnly, e := auth.New(auth.Options{BaseURL: "https://enterprise.test", BasePath: "/identity", TrustedOrigins: []string{idp.URL}, Store: b, Secret: strings.Repeat("x", 32), Plugins: []auth.Plugin{p}})
			must(e)
			type response struct {
				status int
				body   map[string]any
			}
			call := func(host *auth.Auth, route, token string, body map[string]any) response {
				var rd bytes.Buffer
				method := "GET"
				if body != nil {
					method = "POST"
					json.NewEncoder(&rd).Encode(body)
				}
				req := httptest.NewRequest(method, "https://enterprise.test/identity/"+route, &rd)
				req.Header.Set("Content-Type", "application/json")
				req.Header.Set("Origin", "https://enterprise.test")
				if token != "" {
					req.Header.Set("Cookie", token)
				}
				w := httptest.NewRecorder()
				host.ServeHTTP(w, req)
				var result map[string]any
				json.Unmarshal(w.Body.Bytes(), &result)
				return response{w.Code, result}
			}
			check := func(r response, status int) map[string]any {
				t.Helper()
				if r.status != status {
					t.Fatalf("status %d expected %d: %+v", r.status, status, r.body)
				}
				return r.body
			}
			signup := func(name string) (string, string) {
				body := map[string]any{"name": name, "email": name + "@example.test", "password": "correct-horse-staple"}
				buf, _ := json.Marshal(body)
				req := httptest.NewRequest("POST", "https://enterprise.test/identity/sign-up/email", bytes.NewReader(buf))
				req.Header.Set("Content-Type", "application/json")
				w := httptest.NewRecorder()
				one.ServeHTTP(w, req)
				if w.Code != 200 {
					t.Fatal(w.Body.String())
				}
				var result auth.AuthResult
				must(json.Unmarshal(w.Body.Bytes(), &result))
				return w.Result().Cookies()[0].String(), result.User.ID
			}
			// The native Go client keeps its cookie jar and returns redacted typed reads.
			jar, _ := cookiejar.New(nil)
			native, e := client.New("https://enterprise.test/identity", &http.Client{Jar: jar, Transport: guestTransport{one}})
			must(e)
			_, e = native.SignUpEmail(ctx, client.SignUpRequest{Name: "SDK owner", Email: "native@example.test", Password: "correct-horse-staple"})
			must(e)
			spec := client.RegisterOIDCProviderRequest{ProviderID: "native-sdk", Issuer: "https://example.org", Domain: "example.org", OIDC: client.OIDCRegistration{SkipDiscovery: true, Config: sso.Config{ClientID: "sdk-client-0123", ClientSecret: "native-sdk-secret", AuthorizationEndpoint: "https://example.org/authorize", TokenEndpoint: "https://example.org/token", JWKSEndpoint: "https://example.org/keys"}}}
			reg, e := native.RegisterOIDCProvider(ctx, spec)
			must(e)
			public, e := native.GetSSOProvider(ctx, reg.ProviderID)
			must(e)
			page, e := native.ListSSOProviders(ctx)
			must(e)
			if len(page) != 1 || public.OIDC.ClientIDLastFour != "****0123" || page[0].ProviderID != "native-sdk" {
				t.Fatal(public, page)
			}
			owner, ownerID := signup("owner")
			other, otherID := signup("other")
			member, memberID := signup("member")
			created := check(call(one, "organization/create", owner, map[string]any{"name": "Company", "slug": "company"}), 200)
			orgID := created["id"].(string)
			for uid, role := range map[string]string{otherID: "admin", memberID: "member"} {
				_, e = a.db.ExecContext(ctx, a.bind(`INSERT INTO "member" ("id","organizationId","userId","role","createdAt") VALUES (?,?,?,?,?)`), "sso-"+role, orgID, uid, role, a.date(now))
				must(e)
			}
			makeBody := func(id, orgID, path string) map[string]any {
				cfg := map[string]any{"clientId": "long-client-1234", "clientSecret": "only-the-sso-issuer-and-creator", "discoveryEndpoint": idp.URL + path}
				body := map[string]any{"providerId": id, "issuer": idp.URL, "domain": " Example.COM, example.com , subs.example.org ", "oidcConfig": cfg}
				if orgID != "" {
					body["organizationId"] = orgID
				}
				return body
			}
			path := "sso/register"
			single := "sso/get-provider?providerId="
			check(call(one, path, "", makeBody("p", "", "/discovery")), 401)
			check(call(one, path, member, makeBody("member-reg", orgID, "/discovery")), 403)
			check(call(catalogOnly, path, member, makeBody("member-reg", orgID, "/discovery")), 403)
			check(call(one, path, owner, makeBody("bad-case", strings.ToLower(orgID), "/discovery")), 400)
			check(call(one, path, other, makeBody("credential", "", "/discovery")), 422)
			// A trusted provider ID is reserved whatever its case.
			check(call(one, path, other, makeBody("partner", "", "/discovery")), 422)
			check(call(build(b, 0), path, other, makeBody("disabled", "", "/discovery")), 403)
			if fetched.Load() != 0 {
				t.Fatal("discovery ran before authorization")
			}
			// A real administrator impersonates the organization's owner. The
			// delegated session can inspect the redacted catalog; it cannot write.
			_, e = a.db.ExecContext(ctx, a.bind(`UPDATE "user" SET "role"='admin' WHERE "id"=?`), memberID)
			must(e)
			impBody, _ := json.Marshal(map[string]string{"userId": ownerID})
			imp := httptest.NewRequest("POST", "https://enterprise.test/identity/admin/impersonate-user", bytes.NewReader(impBody))
			imp.Header.Set("Cookie", member)
			imp.Header.Set("Content-Type", "application/json")
			imp.Header.Set("Origin", "https://enterprise.test")
			ir := httptest.NewRecorder()
			one.ServeHTTP(ir, imp)
			if ir.Code != 200 {
				t.Fatal(ir.Body.String())
			}
			var delegated string
			for _, cookie := range ir.Result().Cookies() {
				if strings.Contains(cookie.Name, "session_token") {
					delegated = cookie.Name + "=" + cookie.Value
				}
			}
			if delegated == "" {
				t.Fatal("missing impersonation cookie")
			}
			denied := check(call(one, path, delegated, makeBody("delegated", orgID, "/discovery")), 403)
			if denied["code"] != "OWNER_SESSION_REQUIRED" || fetched.Load() != 0 {
				t.Fatal(denied)
			}
			var delegatedToken, delegatedID string
			must(a.db.QueryRowContext(ctx, a.bind(`SELECT "id","token" FROM "session" WHERE "userId"=? AND "impersonatedBy"=?`), ownerID, memberID).Scan(&delegatedID, &delegatedToken))
			err := a.CreateSSOProvider(ctx, sso.Actor{UserID: ownerID, SessionID: delegatedID, SessionToken: delegatedToken}, sso.Provider{UserID: ownerID, ProviderID: "delegated"}, 2)
			if err != sso.ErrUnauthenticated {
				t.Fatalf("SQL accepted delegated owner: %v", err)
			}
			data := check(call(one, path, owner, makeBody("corp", orgID, "/discovery")), 200)
			denied = check(call(one, "sso/delete-provider", delegated, map[string]any{"providerId": "corp"}), 403)
			if denied["code"] != "OWNER_SESSION_REQUIRED" {
				t.Fatal("delegated session reached deletion", denied)
			}
			if err := a.DeleteSSOProvider(ctx, sso.Actor{UserID: ownerID, SessionID: delegatedID, SessionToken: delegatedToken}, "corp", data["id"].(string), nil); err != sso.ErrUnauthenticated {
				t.Fatalf("SQL authorized an impersonated deletion: %v", err)
			}
			if data["domain"] != "example.com,subs.example.org" || data["redirectURI"] != "https://enterprise.test/identity/sso/callback/corp" {
				t.Fatal(data)
			}
			check(call(catalogOnly, single+"corp", other, nil), 200)
			read := check(call(two, single+"corp", other, nil), 200)
			raw, _ := json.Marshal(read)
			if strings.Contains(string(raw), "long-client-1234") || strings.Contains(string(raw), "only-the-sso") || read["oidcConfig"].(map[string]any)["clientIdLastFour"] != "****1234" {
				t.Fatal("secret or incorrect metadata", string(raw))
			}
			if read["oidcConfig"].(map[string]any)["jwksEndpoint"] != idp.URL+"/keys" || read["oidcConfig"].(map[string]any)["tokenEndpointAuthentication"] != "client_secret_post" {
				t.Fatal(read)
			}
			check(call(one, single+"corp", member, nil), 403)
			// An organization admin who did not register a provider can change
			// and delete it; a plain member cannot.
			check(call(one, "sso/update-provider", member, map[string]any{"providerId": "corp", "domain": "member.example"}), 403)
			check(call(one, "sso/delete-provider", member, map[string]any{"providerId": "corp"}), 403)
			if changed := check(call(two, "sso/update-provider", other, map[string]any{"providerId": "corp", "domain": "admin.example.net"}), 200); changed["domain"] != "admin.example.net" {
				t.Fatal("an organization admin could not change the provider's domain", changed)
			}
			check(call(one, "sso/update-provider", owner, map[string]any{"providerId": "corp", "domain": "example.com,subs.example.org"}), 200)
			check(call(one, path, owner, makeBody("corp-spare", orgID, "/discovery")), 200)
			check(call(two, "sso/delete-provider", other, map[string]any{"providerId": "corp-spare"}), 200)
			check(call(one, single+"corp-spare", owner, nil), 404)
			check(call(one, single+"CORP", owner, nil), 404)
			check(call(two, path, other, makeBody("corp", "", "/discovery")), 422)
			check(call(two, path, owner, makeBody("wrong", "", "/mismatch")), 400)
			beforeFetch := fetched.Load()
			if body := check(call(one, path, owner, makeBody("redirect", "", "/error")), 400); body["code"] != "oidc_endpoint_redirect" {
				t.Fatal("registration answered a redirecting discovery endpoint without oidc_endpoint_redirect", body)
			}
			if fetched.Load() != beforeFetch+1 {
				t.Fatal("discovery followed redirect")
			}
			if body := check(call(two, path, owner, makeBody("missing", "", "/missing")), 400); body["code"] != "discovery_not_found" {
				t.Fatal("registration answered a missing discovery document without discovery_not_found", body)
			}
			if body := check(call(two, path, owner, makeBody("broken", "", "/broken")), 502); body["code"] != "discovery_unexpected_error" {
				t.Fatal("registration answered a failing discovery endpoint without discovery_unexpected_error", body)
			}
			ftp := makeBody("ftp-issuer", "", "/discovery")
			ftp["issuer"] = "ftp://idp.example.test/tenant"
			beforeFTP := fetched.Load()
			if body := check(call(two, path, owner, ftp), 400); body["code"] != "discovery_invalid_url" || fetched.Load() != beforeFTP {
				t.Fatal("registration accepted or fetched for a non-HTTP issuer", body)
			}
			// Four unique IDs compete for one remaining creator slot across processes.
			results := make(chan response, 4)
			for n := range 4 {
				go func() {
					h := []*auth.Auth{one, two}[n%2]
					results <- call(h, path, owner, makeBody(fmt.Sprint("personal-", n), "", "/discovery"))
				}()
			}
			wins := 0
			for range 4 {
				r := <-results
				if r.status == 200 {
					wins++
				} else {
					check(r, 403)
				}
			}
			if wins != 1 {
				t.Fatal("quota winners", wins)
			}
			go func() { results <- call(two, path, other, makeBody("raced-role", orgID, "/wait")) }()
			<-entered
			_, e = a.db.ExecContext(ctx, a.bind(`UPDATE "member" SET "role"='member' WHERE "userId"=?`), otherID)
			must(e)
			close(release)
			check(<-results, 403)
			check(call(one, single+"raced-role", owner, nil), 404)
			check(call(two, single+"corp", other, nil), 403)
			l := check(call(two, "sso/providers", other, nil), 200)["providers"].([]any)
			if len(l) != 0 {
				t.Fatal("list visibility leaked", l)
			}
			_, e = a.db.ExecContext(ctx, a.bind(`UPDATE "member" SET "role"='member' WHERE "userId"=?`), ownerID)
			must(e)
			check(call(one, single+"corp", owner, nil), 403)
			l = check(call(two, "sso/providers", owner, nil), 200)["providers"].([]any)
			if len(l) != 1 {
				t.Fatal("personal provider visibility", l)
			}
			check(call(catalogOnly, single+"corp", owner, nil), 403)
			check(call(catalogOnly, path, owner, makeBody("demoted", orgID, "/discovery")), 403)
			scoped := check(call(catalogOnly, "sso/providers", owner, nil), 200)["providers"].([]any)
			if len(scoped) != 1 || scoped[0].(map[string]any)["providerId"] != l[0].(map[string]any)["providerId"] {
				t.Fatal("SSO-only node changed owner visibility", scoped)
			}
			// A creator can be deleted on every engine, including MySQL builds
			// that parse inline REFERENCES without enforcing the cascade.
			var sessionToken string
			must(a.db.QueryRowContext(ctx, a.bind(`SELECT "token" FROM "session" WHERE "userId"=? AND "impersonatedBy" IS NULL`), ownerID).Scan(&sessionToken))
			_, e = a.db.ExecContext(ctx, a.bind(`INSERT INTO "account" ("id","accountId","providerId","userId","createdAt","updatedAt") VALUES ('departed-sso','subject','corp',?,?,?)`), memberID, a.date(now), a.date(now))
			must(e)
			must(a.DeleteAccount(ctx, ownerID, sessionToken, "", "", time.Now()))
			var remaining int
			must(b.db.QueryRowContext(ctx, b.bind(`SELECT COUNT(*) FROM "ssoProvider" WHERE "userId"=?`), ownerID).Scan(&remaining))
			if remaining != 0 {
				t.Fatal("creator-owned provider row survived account deletion")
			}
			check(call(two, path, other, makeBody("corp", "", "/discovery")), 422)

		})
	}
}
