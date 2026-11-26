package sqlstore

import (
	"context"
	"database/sql"
	"encoding/json"
	"strings"
	"testing"

	auth "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/plugins/sso"
	"github.com/Plain-Org/plain-auth/schema"
)

// A provider's mapping chooses the claims for the email, name, image and
// declared user fields of an enterprise sign-up.
func TestEnterpriseOIDCClaimMapping(t *testing.T) {
	fields := map[string]auth.UserField{"department": {Type: auth.FieldString}, "clearance": {Type: auth.FieldString, ServerOnly: true},
		"region": {Type: auth.FieldString, Default: func() string { return "emea" }}, "tier": {Type: auth.FieldString, ServerOnly: true, Default: "basic"},
		"level": {Type: auth.FieldNumber}, "active": {Type: auth.FieldBoolean}, "team": {Type: auth.FieldString}}
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
			var checked []map[string]any
			h := newSSOHost(t, store, idp, sso.Options{}, func(o *auth.Options) {
				o.UserAdditionalFields = fields
				o.ValidateUserInfo = func(_ context.Context, v auth.UserInfoValidation) error {
					if v.Method == "sso-oidc" {
						checked = append(checked, v.User.Fields)
					}
					return nil
				}
			})
			owner := h.signUp("owner@service.test")
			register := func(id string, mapping map[string]any) int {
				t.Helper()
				cfg := map[string]any{"clientId": "enterprise-client", "clientSecret": "oidc-secret", "skipDiscovery": true, "authorizationEndpoint": idp.URL + "/authorize", "tokenEndpoint": idp.URL + "/token", "jwksEndpoint": idp.URL + "/keys"}
				if mapping != nil {
					cfg["mapping"] = mapping
				}
				return h.register(owner, map[string]any{"providerId": id, "issuer": idp.URL, "domain": id + ".example", "oidcConfig": cfg}).Code
			}
			type row struct {
				name                   string
				image, dept, clearance sql.NullString
				verified               bool
			}
			user := func(email string) (row, bool) {
				var r row
				err := store.db.QueryRowContext(ctx, store.bind(`SELECT "name","image","emailVerified","department","clearance" FROM "user" WHERE "email"=?`), email).Scan(&r.name, &r.image, &r.verified, &r.dept, &r.clearance)
				return r, err == nil
			}
			idp.mu.Lock()
			idp.claims = map[string]map[string]any{
				"mapped": {"mail": "mapped@mapped.example", "display": "Mapped Person", "avatar": "https://images.example.test/mapped.png", "mail_verified": true, "dept": "Finance", "level": "top",
					"grade": "3", "enabled": "true", "teams": []string{"blue", "green"}},
				"list":  {"emails": []string{"first@list.example", "second@list.example"}},
				"plain": {"picture": "https://images.example.test/plain.png"},
			}
			idp.mu.Unlock()

			if register("mapped", map[string]any{"email": "mail", "name": "display", "image": "avatar", "emailVerified": "mail_verified", "extraFields": map[string]any{"department": "dept", "clearance": "level",
				"level": "grade", "active": "enabled", "team": "teams"}}) != 200 {
				t.Fatal("a provider with a claim mapping was not registered")
			}
			if w := h.signIn(map[string]any{"providerId": "mapped"}, "token-email@mapped.example", "mapped", "client_secret_basic", "mapped"); w.Header().Get("Location") != "https://service.test/home" {
				t.Fatal("mapped enterprise sign-in failed", w.Code, w.Header().Get("Location"))
			}
			mapped, ok := user("mapped@mapped.example")
			if !ok {
				t.Fatal("mapping.email did not choose the mail claim")
			}
			if mapped.name != "Mapped Person" {
				t.Fatal("mapping.name did not choose the display claim", mapped.name)
			}
			if mapped.image.String != "https://images.example.test/mapped.png" {
				t.Fatal("mapping.image did not choose the avatar claim", mapped.image)
			}
			if mapped.verified {
				t.Fatal("mapping.emailVerified was trusted for an OIDC user")
			}
			if mapped.dept.String != "Finance" {
				t.Fatal("extraFields did not fill the department user field", mapped.dept)
			}
			if mapped.clearance.Valid {
				t.Fatal("extraFields wrote a server-only user field", mapped.clearance)
			}
			var region, tier, team sql.NullString
			var level sql.NullInt64
			var active sql.NullBool
			must(store.db.QueryRowContext(ctx, store.bind(`SELECT "region","tier","level","active","team" FROM "user" WHERE "email"=?`), "mapped@mapped.example").Scan(&region, &tier, &level, &active, &team))
			if region.String != "emea" || tier.String != "basic" {
				t.Fatal("an enterprise sign-up did not apply the user field defaults", region, tier)
			}
			if level.Int64 != 3 || !active.Bool {
				t.Fatal("a string claim did not fill a number or boolean user field", level, active)
			}
			if team.Valid {
				t.Fatal("a claim with several values filled a scalar user field", team)
			}
			// The gate copies numbers as json.Number.
			if gate := checked[len(checked)-1]; gate["level"] != json.Number("3") || gate["active"] != true || gate["team"] != nil {
				t.Fatal("ValidateUserInfo saw the provider's values before they were fitted", gate)
			}

			if register("list", map[string]any{"email": "emails"}) != 200 {
				t.Fatal("a provider with an email list mapping was not registered")
			}
			h.signIn(map[string]any{"providerId": "list"}, "token-email@list.example", "listed", "client_secret_basic", "list")
			if _, ok := user("first@list.example"); !ok {
				t.Fatal("a list email claim did not use the first address")
			}

			if register("plain", nil) != 200 {
				t.Fatal("a provider without a mapping was not registered")
			}
			h.signIn(map[string]any{"providerId": "plain"}, "plain@plain.example", "plain", "client_secret_basic", "plain")
			if plain, ok := user("plain@plain.example"); !ok || plain.name != "Enterprise User" || plain.image.String != "https://images.example.test/plain.png" {
				t.Fatal("the default mapping did not read the name and picture claims", plain, ok)
			}

			idp.mu.Lock()
			idp.claims["noemail"] = map[string]any{"email": ""}
			idp.mu.Unlock()
			if w := h.signIn(map[string]any{"providerId": "plain"}, "plain@plain.example", "plain", "client_secret_basic", "noemail"); w.Header().Get("Location") != "https://service.test/retry?error=invalid_provider&error_description=missing_user_info" {
				t.Fatal("a profile without an email was not refused as missing user info", w.Header().Get("Location"))
			}
			if register("numeric", map[string]any{"extraFields": map[string]any{"department": 7}}) != 400 {
				t.Fatal("registration accepted an extraFields entry that names no claim")
			}
			if register("unknown", map[string]any{"nickname": "nick"}) != 400 {
				t.Fatal("registration accepted an unknown mapping key")
			}

		})
	}
}

// A required user field the provider does not fill refuses an enterprise
// sign-up with MISSING_FIELD and stores no user.
func TestEnterpriseRequiredUserField(t *testing.T) {
	fields := map[string]auth.UserField{"locale": {Type: auth.FieldString, Required: true}}
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			ctx := t.Context()
			store, err := OpenWithAdditionalFields(ctx, dialect, organizationTestDSN(t, dialect), []string{"sso"}, schema.AdditionalFields{User: fields})
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			idp := newSSOIssuer(t)
			h := newSSOHost(t, store, idp, sso.Options{}, func(o *auth.Options) { o.UserAdditionalFields = fields })
			signup := h.call("POST", "sign-up/email", "", map[string]any{"name": "Owner", "email": "owner@service.test", "password": "correct-horse-staple", "locale": "en"})
			var owner string
			for _, c := range signup.Result().Cookies() {
				if strings.Contains(c.Name, "session_token") {
					owner = c.Name + "=" + c.Value
				}
			}
			if w := h.register(owner, map[string]any{"providerId": "acme", "issuer": idp.URL, "domain": "acme.example", "oidcConfig": map[string]any{"clientId": "enterprise-client", "clientSecret": "oidc-secret", "skipDiscovery": true,
				"authorizationEndpoint": idp.URL + "/authorize", "tokenEndpoint": idp.URL + "/token", "jwksEndpoint": idp.URL + "/keys"}}); w.Code != 200 {
				t.Fatal("registration failed", w.Code, w.Body.String())
			}
			if w := h.signIn(map[string]any{"providerId": "acme"}, "late@acme.example", "late", "client_secret_basic", ""); !strings.Contains(w.Header().Get("Location"), "error=MISSING_FIELD") {
				t.Fatal("a sign-up missing a required user field did not redirect with MISSING_FIELD", w.Header().Get("Location"))
			}
			if _, err := store.FindAccountUser(ctx, "late@acme.example"); err == nil {
				t.Fatal("a sign-up missing a required user field stored the user")
			}
		})
	}
}
