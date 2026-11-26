package sqlstore

import (
	"database/sql"
	"encoding/json"
	"testing"

	auth "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/plugins/sso"
	"github.com/Plain-Org/plain-auth/schema"
)

// overrideUserInfo refreshes a returning OIDC user's profile at each
// sign-in; DefaultOverrideUserInfo stores it on every registration.
func TestEnterpriseOIDCProfileOverride(t *testing.T) {
	fields := map[string]auth.UserField{"department": {Type: auth.FieldString}}
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			ctx := t.Context()
			must := func(err error) {
				t.Helper()
				if err != nil {
					t.Fatal(err)
				}
			}
			store, err := OpenWithAdditionalFields(ctx, dialect, organizationTestDSN(t, dialect), []string{"sso"}, schema.AdditionalFields{User: fields})
			must(err)
			defer store.Close()
			idp := newSSOIssuer(t)
			declare := func(o *auth.Options) { o.UserAdditionalFields = fields }
			plain, forcing := newSSOHost(t, store, idp, sso.Options{}, declare), newSSOHost(t, store, idp, sso.Options{DefaultOverrideUserInfo: true}, declare)
			owner := plain.signUp("owner@service.test")
			register := func(h *ssoHost, id string, override any) {
				t.Helper()
				body := map[string]any{"providerId": id, "issuer": idp.URL, "domain": id + ".example", "oidcConfig": map[string]any{"clientId": "enterprise-client", "clientSecret": "oidc-secret", "skipDiscovery": true,
					"authorizationEndpoint": idp.URL + "/authorize", "tokenEndpoint": idp.URL + "/token", "jwksEndpoint": idp.URL + "/keys", "mapping": map[string]any{"extraFields": map[string]any{"department": "dept"}}}}
				if override != nil {
					body["overrideUserInfo"] = override
				}
				if w := h.register(owner, body); w.Code != 200 {
					t.Fatal("registration failed", id, w.Code, w.Body.String())
				}
			}
			stored := func(id string) bool {
				var raw string
				must(store.db.QueryRowContext(ctx, store.bind(`SELECT "oidcConfig" FROM "ssoProvider" WHERE "providerId"=?`), id).Scan(&raw))
				var cfg struct{ OverrideUserInfo bool }
				must(json.Unmarshal([]byte(raw), &cfg))
				return cfg.OverrideUserInfo
			}
			type row struct {
				name, email string
				image, dept sql.NullString
				verified    bool
			}
			// user reads the one user linked to the provider.
			user := func(provider string) row {
				t.Helper()
				var r row
				must(store.db.QueryRowContext(ctx, store.bind(`SELECT "name","email","image","department","emailVerified" FROM "user" WHERE "id" IN (SELECT "userId" FROM "account" WHERE "providerId"=?)`), provider).Scan(&r.name, &r.email, &r.image, &r.dept, &r.verified))
				return r
			}
			idp.mu.Lock()
			idp.claims = map[string]map[string]any{
				"v1": {"name": "First Name", "picture": "https://images.example.test/1.png", "dept": "Sales"},
				"v2": {"name": "Second Name", "picture": "https://images.example.test/2.png", "dept": "Support"},
			}
			idp.mu.Unlock()
			twice := func(h *ssoHost, id string) {
				t.Helper()
				for _, mode := range []string{"v1", "v2"} {
					if w := h.signIn(map[string]any{"providerId": id}, id+"@"+id+".example", "subject-"+id, "client_secret_basic", mode); w.Header().Get("Location") != "https://service.test/home" {
						t.Fatal("sign-in failed", id, mode, w.Code, w.Header().Get("Location"))
					}
				}
			}

			register(plain, "sync", true)
			register(plain, "keep", nil)
			register(forcing, "forced", false)
			if !stored("sync") || stored("keep") {
				t.Fatal("overrideUserInfo was not stored from the registration")
			}
			if !stored("forced") {
				t.Fatal("DefaultOverrideUserInfo was not stored over the request's false")
			}
			twice(plain, "sync")
			synced := user("sync")
			if synced.name != "Second Name" || synced.image.String != "https://images.example.test/2.png" {
				t.Fatal("overrideUserInfo did not refresh the returning user's name and image", synced)
			}
			if synced.dept.String != "Support" {
				t.Fatal("overrideUserInfo did not refresh the mapped department", synced.dept)
			}
			twice(plain, "keep")
			if kept := user("keep"); kept.name != "First Name" || kept.dept.String != "Sales" {
				t.Fatal("a provider without overrideUserInfo replaced the profile", kept)
			}
			twice(forcing, "forced")
			if forced := user("forced"); forced.name != "Second Name" {
				t.Fatal("DefaultOverrideUserInfo did not refresh the profile", forced)
			}
			// A host that declares no user fields still refreshes the profile.
			bare := newSSOHost(t, store, idp, sso.Options{})
			register(bare, "bare", true)
			twice(bare, "bare")
			if refreshed := user("bare"); refreshed.name != "Second Name" || refreshed.dept.Valid {
				t.Fatal("overrideUserInfo did not refresh the profile on a host without user fields", refreshed)
			}

			_, err = store.db.ExecContext(ctx, store.bind(`UPDATE "user" SET "emailVerified"=? WHERE "email"=?`), true, "sync@sync.example")
			must(err)
			if w := plain.signIn(map[string]any{"providerId": "sync"}, "moved@sync.example", "subject-sync", "client_secret_basic", "v2"); w.Header().Get("Location") != "https://service.test/home" {
				t.Fatal("a sign-in with a changed email failed", w.Code, w.Header().Get("Location"))
			}
			if moved := user("sync"); moved.email != "moved@sync.example" || moved.verified {
				t.Fatal("overrideUserInfo did not store the changed email unverified", moved)
			}
		})
	}
}
