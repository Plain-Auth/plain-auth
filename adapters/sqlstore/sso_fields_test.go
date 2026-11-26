package sqlstore

import (
	"encoding/json"
	"strings"
	"testing"

	auth "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/plugins/sso"
	"github.com/Plain-Org/plain-auth/schema"
)

// Declared provider fields are taken at the top level of registration and
// update bodies, stored in their own columns and returned beside the
// built-in keys, except Hidden ones, as another runtime does.
func TestEnterpriseProviderFields(t *testing.T) {
	fields := map[string]sso.ProviderField{
		"tier":   {Type: auth.FieldString, Required: true},
		"note":   {Type: auth.FieldString, ServerOnly: true},
		"region": {Type: auth.FieldString, Hidden: true, Default: "eu"},
	}
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			ctx := t.Context()
			must := func(err error) {
				t.Helper()
				if err != nil {
					t.Fatal(err)
				}
			}
			ddl, err := schema.GenerateWithAdditionalFields(dialect, []string{"sso"}, schema.AdditionalFields{SSOProvider: fields})
			must(err)
			store, err := OpenWithSchema(ctx, dialect, organizationTestDSN(t, dialect), ddl)
			must(err)
			defer store.Close()
			idp := newSSOIssuer(t)
			h := newSSOHost(t, store, idp, sso.Options{ProviderAdditionalFields: fields})
			owner := h.signUp("owner@service.test")
			body := func(id string, extra map[string]any) map[string]any {
				b := map[string]any{"providerId": id, "issuer": idp.URL, "domain": id + ".example", "oidcConfig": map[string]any{"clientId": "enterprise-client", "clientSecret": "oidc-secret", "skipDiscovery": true,
					"authorizationEndpoint": idp.URL + "/authorize", "tokenEndpoint": idp.URL + "/token", "jwksEndpoint": idp.URL + "/keys"}}
				for k, v := range extra {
					b[k] = v
				}
				return b
			}
			code := func(raw []byte) string {
				var e struct{ Code string }
				json.Unmarshal(raw, &e)
				return e.Code
			}
			for _, c := range []struct {
				extra map[string]any
				code  string
			}{
				{nil, "MISSING_FIELD"},
				{map[string]any{"tier": "gold", "note": "set by a client"}, "FIELD_NOT_ALLOWED"},
				{map[string]any{"tier": map[string]any{"level": 1}}, "VALIDATION_ERROR"},
			} {
				if w := h.register(owner, body("acme", c.extra)); w.Code != 400 || code(w.Body.Bytes()) != c.code {
					t.Fatal("an unusable provider field was not refused", c.extra, w.Code, w.Body.String())
				}
			}
			visible := func(raw []byte, tier string) bool {
				var got map[string]any
				return json.Unmarshal(raw, &got) == nil && got["tier"] == tier && got["region"] == nil && got["note"] == nil
			}
			w := h.register(owner, body("acme", map[string]any{"tier": "gold"}))
			if w.Code != 200 || !visible(w.Body.Bytes(), "gold") {
				t.Fatal("a registration did not return its fields without the hidden one", w.Code, w.Body.String())
			}
			var tier, region string
			must(store.db.QueryRowContext(ctx, store.bind(`SELECT "tier","region" FROM "ssoProvider" WHERE "providerId"=?`), "acme").Scan(&tier, &region))
			if tier != "gold" || region != "eu" {
				t.Fatal("the provider fields were not stored", tier, region)
			}
			if w := h.call("GET", "sso/get-provider?providerId=acme", owner, nil); w.Code != 200 || !visible(w.Body.Bytes(), "gold") {
				t.Fatal("get-provider did not return the visible fields only", w.Code, w.Body.String())
			}
			if w := h.call("GET", "sso/providers", owner, nil); w.Code != 200 || !strings.Contains(w.Body.String(), `"tier":"gold"`) || strings.Contains(w.Body.String(), `"region"`) {
				t.Fatal("the provider list did not return the visible fields only", w.Code, w.Body.String())
			}
			// A field alone is an update, and it is not part of the identity.
			if w := h.call("POST", "sso/update-provider", owner, map[string]any{"providerId": "acme", "tier": "platinum"}); w.Code != 200 || !visible(w.Body.Bytes(), "platinum") {
				t.Fatal("a provider field update was refused", w.Code, w.Body.String())
			}
			must(store.db.QueryRowContext(ctx, store.bind(`SELECT "tier","region" FROM "ssoProvider" WHERE "providerId"=?`), "acme").Scan(&tier, &region))
			if tier != "platinum" || region != "eu" {
				t.Fatal("a provider field update changed the wrong columns", tier, region)
			}
			if w := h.call("POST", "sso/update-provider", owner, map[string]any{"providerId": "acme", "note": "set by a client"}); w.Code != 400 || code(w.Body.Bytes()) != "FIELD_NOT_ALLOWED" {
				t.Fatal("a server-only field was set through update-provider", w.Code, w.Body.String())
			}
		})
	}
}
