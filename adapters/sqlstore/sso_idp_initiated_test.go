package sqlstore

import (
	"context"
	"crypto/rand"
	"errors"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Plain-Org/plain-auth/plugins/sso"
	"github.com/Plain-Org/plain-auth/schema"
)

// A stateless callback for a provider the host approves restarts the sign-in
// at the provider with fresh browser state; any other one reports the
// missing state.
func TestEnterpriseOIDCIdPInitiated(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			ctx := t.Context()
			must := func(err error) {
				t.Helper()
				if err != nil {
					t.Fatal(err)
				}
			}
			ddl, err := schema.Generate(dialect, []string{"organization", "sso"})
			must(err)
			store, err := OpenWithSchema(ctx, dialect, organizationTestDSN(t, dialect), ddl)
			must(err)
			defer store.Close()
			idp := newSSOIssuer(t)
			var mu sync.Mutex
			var seen []sso.OIDCDirectory
			approve := func(_ context.Context, d sso.OIDCDirectory) (bool, error) {
				mu.Lock()
				defer mu.Unlock()
				seen = append(seen, d)
				return d.ProviderID != "other", nil
			}
			approving := newSSOHost(t, store, idp, sso.Options{AllowIDPInitiatedOIDC: approve})
			closed := newSSOHost(t, store, idp, sso.Options{})
			shared := newSSOHost(t, store, idp, sso.Options{SharedCallback: true, AllowIDPInitiatedOIDC: approve})
			failing := newSSOHost(t, store, idp, sso.Options{AllowIDPInitiatedOIDC: func(context.Context, sso.OIDCDirectory) (bool, error) {
				return false, errors.New("directory unavailable")
			}})
			owner := approving.signUp("owner@service.test")
			for _, id := range []string{"acme", "other"} {
				if w := approving.register(owner, map[string]any{"providerId": id, "issuer": idp.URL, "domain": id + ".example", "oidcConfig": map[string]any{"clientId": "enterprise-client", "clientSecret": "oidc-secret", "skipDiscovery": true,
					"authorizationEndpoint": idp.URL + "/authorize", "tokenEndpoint": idp.URL + "/token", "jwksEndpoint": idp.URL + "/keys", "allowIdpInitiated": true}}); w.Code != 200 {
					t.Fatal("registration failed", id, w.Code, w.Body.String())
				}
			}
			var raw string
			must(store.db.QueryRowContext(ctx, store.bind(`SELECT "oidcConfig" FROM "ssoProvider" WHERE "providerId"=?`), "acme").Scan(&raw))
			if strings.Contains(raw, "allowIdpInitiated") {
				t.Fatal("registration stored allowIdpInitiated", raw)
			}
			missingState := func(w *httptest.ResponseRecorder) bool {
				return w.Code == 302 && w.Header().Get("Location") == "https://service.test/identity/error?error=state_not_found"
			}
			if w := closed.call("GET", "sso/callback/acme?code=idp-code", "", nil); !missingState(w) {
				t.Fatal("a stateless callback restarted without a policy", w.Code, w.Header().Get("Location"))
			}
			if w := approving.call("GET", "sso/callback/other?code=idp-code", "", nil); !missingState(w) {
				t.Fatal("a stateless callback restarted for an unapproved provider", w.Code, w.Header().Get("Location"))
			}
			if w := approving.call("GET", "sso/callback?code=idp-code", "", nil); !missingState(w) {
				t.Fatal("the shared callback restarted a stateless sign-in", w.Code, w.Header().Get("Location"))
			}
			if w := failing.call("GET", "sso/callback/acme?code=idp-code", "", nil); w.Code != 503 {
				t.Fatal("a failing OIDC directory policy did not fail closed", w.Code, w.Body.String())
			}

			// restart bounces a stateless callback, then has the issuer grant a
			// code for the new authorization and returns through its callback.
			restart := func(h *ssoHost, path, callback, email, subject string) *httptest.ResponseRecorder {
				t.Helper()
				before := idp.tokens.Load()
				w := h.call("GET", path, "", nil)
				target, err := url.Parse(w.Header().Get("Location"))
				must(err)
				q := target.Query()
				if w.Code != 302 || target.Scheme+"://"+target.Host+target.Path != idp.URL+"/authorize" || q.Get("state") == "" || q.Get("nonce") == "" || q.Get("code_challenge_method") != "S256" || q.Get("client_id") != "enterprise-client" || q.Get("redirect_uri") != callback {
					t.Fatal("a stateless callback was not restarted at the authorization endpoint", w.Code, target)
				}
				var state string
				for _, c := range w.Result().Cookies() {
					if strings.Contains(c.Name, "sso_state") {
						state = c.Name + "=" + c.Value
					}
				}
				if state == "" {
					t.Fatal("the restarted flow set no browser state")
				}
				if idp.tokens.Load() != before {
					t.Fatal("the IdP-initiated code was exchanged")
				}
				code := rand.Text()
				idp.mu.Lock()
				idp.codes[code] = ssoCode{q.Get("nonce"), q.Get("code_challenge"), callback, email, subject, "client_secret_basic", ""}
				idp.mu.Unlock()
				cb, err := url.Parse(callback)
				must(err)
				return h.call("GET", strings.TrimPrefix(cb.Path, "/identity/")+"?"+url.Values{"code": {code}, "state": {q.Get("state")}}.Encode(), state, nil)
			}
			if w := restart(approving, "sso/callback/acme?code=idp-code", "https://service.test/identity/sso/callback/acme", "ada@acme.example", "ada"); w.Header().Get("Location") != "https://service.test/" {
				t.Fatal("the restarted sign-in did not return to the host root", w.Code, w.Header().Get("Location"))
			}
			acme, err := store.FindBrowserProvider(ctx, sso.Selector{ProviderID: "acme", Protocol: "oidc"})
			must(err)
			mu.Lock()
			last := seen[len(seen)-1]
			mu.Unlock()
			if last != (sso.OIDCDirectory{RecordID: acme.ID, Reference: acme.Reference, ProviderID: "acme", Issuer: idp.URL, ClientID: "enterprise-client"}) {
				t.Fatal("the policy did not receive the current registration", last)
			}
			if w := restart(shared, "sso/callback/acme?code=idp-code", "https://service.test/identity/sso/callback", "lin@acme.example", "lin"); w.Header().Get("Location") != "https://service.test/" {
				t.Fatal("a restarted sign-in did not complete through the shared callback", w.Code, w.Header().Get("Location"))
			}
			// The restarted flow cannot request sign-up.
			strict := newSSOHost(t, store, idp, sso.Options{DisableImplicitSignUp: true, AllowIDPInitiatedOIDC: approve})
			if w := restart(strict, "sso/callback/acme?code=idp-code", "https://service.test/identity/sso/callback/acme", "nobody@acme.example", "nobody"); !strings.Contains(w.Header().Get("Location"), "error=signup+disabled") {
				t.Fatal("a restarted sign-in signed up a user under DisableImplicitSignUp", w.Code, w.Header().Get("Location"))
			}
			if _, err := store.FindAccountUser(ctx, "nobody@acme.example"); err == nil {
				t.Fatal("a restarted sign-in stored a user under DisableImplicitSignUp")
			}
			// A failed runtime discovery reports the missing state.
			if w := approving.register(owner, map[string]any{"providerId": "lazy", "issuer": idp.URL, "domain": "lazy.example", "oidcConfig": map[string]any{"clientId": "enterprise-client", "clientSecret": "oidc-secret", "skipDiscovery": true,
				"authorizationEndpoint": idp.URL + "/authorize", "tokenEndpoint": idp.URL + "/token"}}); w.Code != 200 {
				t.Fatal("registration failed", w.Code, w.Body.String())
			}
			idp.discoveryDown.Store(true)
			if w := approving.call("GET", "sso/callback/lazy?code=idp-code", "", nil); !missingState(w) {
				t.Fatal("a restart whose discovery failed did not report the missing state", w.Code, w.Header().Get("Location"))
			}
			idp.discoveryDown.Store(false)
			// The policy sees the provider's organization.
			var owned string
			must(store.db.QueryRowContext(ctx, store.bind(`SELECT "id" FROM "user" WHERE "email"=?`), "owner@service.test").Scan(&owned))
			now := store.date(time.Now())
			_, err = store.db.ExecContext(ctx, store.bind(`INSERT INTO "organization" ("id","name","slug","createdAt") VALUES (?,?,?,?)`), "tenant", "Tenant", "tenant", now)
			must(err)
			_, err = store.db.ExecContext(ctx, store.bind(`INSERT INTO "member" ("id","organizationId","userId","role","createdAt") VALUES (?,?,?,?,?)`), "owner-member", "tenant", owned, "owner", now)
			must(err)
			if w := approving.register(owner, map[string]any{"providerId": "orgacme", "issuer": idp.URL, "domain": "orgacme.example", "organizationId": "tenant", "oidcConfig": map[string]any{"clientId": "enterprise-client", "clientSecret": "oidc-secret", "skipDiscovery": true,
				"authorizationEndpoint": idp.URL + "/authorize", "tokenEndpoint": idp.URL + "/token", "jwksEndpoint": idp.URL + "/keys"}}); w.Code != 200 {
				t.Fatal("registration failed", w.Code, w.Body.String())
			}
			approving.call("GET", "sso/callback/orgacme?code=idp-code", "", nil)
			mu.Lock()
			last = seen[len(seen)-1]
			mu.Unlock()
			if last.ProviderID != "orgacme" || last.OrganizationID != "tenant" {
				t.Fatal("the policy did not receive the provider's organization", last)
			}
		})
	}
}
