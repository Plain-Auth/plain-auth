package sqlstore

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	auth "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/plugins/sso"
	"github.com/Plain-Org/plain-auth/schema"
)

// ResolveUser decides each verified OIDC identity before the sign-in
// transaction: continue, link to a chosen user, or reject.
func TestEnterpriseOIDCResolveUser(t *testing.T) {
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
			now := time.Now().UTC().Truncate(time.Millisecond)
			for _, u := range []auth.User{
				{ID: "selected", Name: "Provisioned Employee", Email: "provisioned@example.test", CreatedAt: now, UpdatedAt: now},
				{ID: "other", Name: "Other", Email: "other@example.test", CreatedAt: now, UpdatedAt: now},
			} {
				must(store.CreateUser(ctx, u, "credential", nil))
			}
			var mu sync.Mutex
			var inputs []sso.UserResolutionInput
			var actions []auth.UserInfoAction
			var readErr error
			decide := func(sso.UserResolutionInput) (sso.UserResolution, error) {
				return sso.UserResolution{Action: sso.ResolveContinue}, nil
			}
			set := func(d func(sso.UserResolutionInput) (sso.UserResolution, error)) { mu.Lock(); decide = d; mu.Unlock() }
			link := func(id, profile string) func(sso.UserResolutionInput) (sso.UserResolution, error) {
				return func(sso.UserResolutionInput) (sso.UserResolution, error) {
					return sso.UserResolution{Action: sso.ResolveLink, UserID: id, Profile: profile}, nil
				}
			}
			resolve := func(rc context.Context, in sso.UserResolutionInput) (sso.UserResolution, error) {
				// A read through the store would wait for the sign-in transaction
				// on SQLite's single connection if the resolver ran inside it.
				read, cancel := context.WithTimeout(rc, 2*time.Second)
				defer cancel()
				_, e := store.FindAccountUser(read, "provisioned@example.test")
				mu.Lock()
				inputs = append(inputs, in)
				readErr = e
				d := decide
				mu.Unlock()
				return d(in)
			}
			h := newSSOHost(t, store, idp, sso.Options{DisableImplicitSignUp: true, ResolveUser: resolve}, func(o *auth.Options) {
				o.ValidateUserInfo = func(_ context.Context, v auth.UserInfoValidation) error {
					if v.Method == "sso-oidc" {
						mu.Lock()
						actions = append(actions, v.Action)
						mu.Unlock()
					}
					return nil
				}
			})
			owner := h.signUp("owner@service.test")
			for id, userinfo := range map[string]bool{"acme": false, "acme-ui": true} {
				cfg := map[string]any{"clientId": "enterprise-client", "clientSecret": "oidc-secret", "skipDiscovery": true, "authorizationEndpoint": idp.URL + "/authorize", "tokenEndpoint": idp.URL + "/token", "jwksEndpoint": idp.URL + "/keys"}
				if userinfo {
					cfg["userInfoEndpoint"] = idp.URL + "/userinfo"
				}
				if w := h.register(owner, map[string]any{"providerId": id, "issuer": idp.URL, "domain": id + ".example", "oidcConfig": cfg}); w.Code != 200 {
					t.Fatal("registration failed", id, w.Code, w.Body.String())
				}
			}
			signIn := func(provider, subject, email, mode string) string {
				t.Helper()
				return h.signIn(map[string]any{"providerId": provider}, email, subject, "client_secret_basic", mode).Header().Get("Location")
			}
			count := func(q string, args ...any) int {
				t.Helper()
				var n int
				must(store.db.QueryRowContext(ctx, store.bind(q), args...).Scan(&n))
				return n
			}
			profile := func(id string) (name, email string, verified bool) {
				t.Helper()
				must(store.db.QueryRowContext(ctx, store.bind(`SELECT "name","email","emailVerified" FROM "user" WHERE "id"=?`), id).Scan(&name, &email, &verified))
				return
			}
			users := count(`SELECT COUNT(*) FROM "user"`)
			last := func() sso.UserResolutionInput {
				mu.Lock()
				defer mu.Unlock()
				return inputs[len(inputs)-1]
			}

			set(link("selected", "preserve"))
			if got := signIn("acme", "employee", "employee@acme.example", ""); got != "https://service.test/home" {
				t.Fatal("a resolver link did not finish the enterprise sign-in", got)
			}
			mu.Lock()
			e := readErr
			mu.Unlock()
			if e != nil {
				t.Fatal("the resolver could not read the store, so it ran inside the sign-in transaction", e)
			}
			in := last()
			if in.Protocol != "oidc" || in.ProviderID != "acme" {
				t.Fatal("the OIDC resolver input named the wrong protocol or provider", in.Protocol, in.ProviderID)
			}
			if in.AccountKey.Issuer != idp.URL {
				t.Fatal("the OIDC account key issuer was not the ID token issuer", in.AccountKey)
			}
			if in.AccountKey.AccountID != "employee" {
				t.Fatal("the OIDC account key ID was not the ID token subject", in.AccountKey)
			}
			if in.User.Email != "employee@acme.example" || in.User.Name != "Enterprise User" || in.User.EmailVerified {
				t.Fatal("the normalized OIDC provider profile was wrong", in.User)
			}
			if in.IDTokenClaims["iss"] != idp.URL || in.IDTokenClaims["nonce"] == nil {
				t.Fatal("the resolver did not receive the verified ID token claims", in.IDTokenClaims)
			}
			if in.Claims["sub"] != "employee" {
				t.Fatal("the resolver did not receive the provider claims", in.Claims)
			}
			acme, err := store.FindBrowserProvider(ctx, sso.Selector{ProviderID: "acme"})
			must(err)
			if in.ProviderReference != acme.Reference {
				t.Fatal("the resolver did not receive the accepted provider reference")
			}
			if n := count(`SELECT COUNT(*) FROM "user"`); n != users {
				t.Fatal("a resolver link created a user", n, users)
			}
			if n := count(`SELECT COUNT(*) FROM "account" WHERE "providerId"=? AND "accountId"=? AND "userId"=?`, "acme", "employee", "selected"); n != 1 {
				t.Fatal("the enterprise identity was not linked to the resolved user")
			}
			if name, email, _ := profile("selected"); name != "Provisioned Employee" || email != "provisioned@example.test" {
				t.Fatal("a preserve link changed the resolved user's profile", name, email)
			}
			mu.Lock()
			first := append([]auth.UserInfoAction(nil), actions...)
			mu.Unlock()
			if len(first) != 1 || first[0] != auth.UserInfoLinkAccount {
				t.Fatal("ValidateUserInfo did not check the first resolver link as link-account", first)
			}

			set(link("selected", "update"))
			if got := signIn("acme", "employee", "employee@acme.example", ""); got != "https://service.test/home" {
				t.Fatal("a returning resolver link did not finish the enterprise sign-in", got)
			}
			mu.Lock()
			action := actions[len(actions)-1]
			mu.Unlock()
			if action != auth.UserInfoSignIn {
				t.Fatal("ValidateUserInfo did not check the returning resolver link as sign-in", action)
			}
			if name, email, verified := profile("selected"); name != "Enterprise User" || email != "employee@acme.example" || verified {
				t.Fatal("an update link did not copy the provider profile to the resolved user", name, email, verified)
			}

			sessions := count(`SELECT COUNT(*) FROM "session"`)
			set(func(sso.UserResolutionInput) (sso.UserResolution, error) {
				return sso.UserResolution{Action: sso.ResolveReject, Code: "PROVISIONED_USER_NOT_FOUND", Message: "Ask your administrator"}, nil
			})
			if got := signIn("acme", "stranger", "stranger@acme.example", ""); got != "https://service.test/retry?error=PROVISIONED_USER_NOT_FOUND&error_description=Ask+your+administrator" {
				t.Fatal("a rejected enterprise sign-in did not reach the error callback with the resolver's code", got)
			}
			if count(`SELECT COUNT(*) FROM "account" WHERE "accountId"=?`, "stranger") != 0 || count(`SELECT COUNT(*) FROM "session"`) != sessions {
				t.Fatal("a rejected enterprise sign-in stored an account or session")
			}
			set(link("missing", "preserve"))
			if got := signIn("acme", "newcomer", "newcomer@acme.example", ""); !strings.Contains(got, "error=user_not_found") {
				t.Fatal("a link to a missing user did not answer user_not_found", got)
			}
			set(link("other", "preserve"))
			if got := signIn("acme", "employee", "employee@acme.example", ""); !strings.Contains(got, "error=account_ownership_conflict") {
				t.Fatal("a link to an identity another user owns did not answer account_ownership_conflict", got)
			}
			if count(`SELECT COUNT(*) FROM "session"`) != sessions {
				t.Fatal("an ownership conflict issued a session")
			}
			failed := func(got string) bool {
				u, err := url.Parse(got)
				return err == nil && u.Query().Get("error") == "SSO_USER_RESOLUTION_FAILED" && u.Query().Get("error_description") == "Unable to resolve the SSO user"
			}
			set(func(sso.UserResolutionInput) (sso.UserResolution, error) {
				return sso.UserResolution{}, errors.New("directory down")
			})
			if got := signIn("acme", "employee", "employee@acme.example", ""); !failed(got) {
				t.Fatal("a failing resolver did not answer SSO_USER_RESOLUTION_FAILED", got)
			}
			set(link("selected", "merge"))
			if got := signIn("acme", "employee", "employee@acme.example", ""); !failed(got) {
				t.Fatal("an invalid resolver decision was not refused", got)
			}
			set(func(sso.UserResolutionInput) (sso.UserResolution, error) { panic("directory down") })
			if got := signIn("acme", "employee", "employee@acme.example", ""); !failed(got) {
				t.Fatal("a panicking resolver was not refused", got)
			}
			set(func(sso.UserResolutionInput) (sso.UserResolution, error) {
				return sso.UserResolution{Action: sso.ResolveContinue}, nil
			})
			if got := signIn("acme", "fresh", "fresh@acme.example", ""); !strings.Contains(got, "error=signup_disabled") {
				t.Fatal("a continued sign-in skipped the built-in sign-up rule", got)
			}
			mu.Lock()
			before := len(inputs)
			mu.Unlock()
			got := signIn("acme-ui", "employee", "employee@acme.example", "userinfo-only")
			mu.Lock()
			after := len(inputs)
			mu.Unlock()
			if after != before || !strings.Contains(got, "error=invalid_provider") || !strings.Contains(got, "error_description=id_token_required_for_user_resolution") {
				t.Fatal("a resolver ran or the sign-in continued without an ID token", got)
			}
			raw, _ := json.Marshal(in.Claims)
			if strings.Contains(string(raw), "oidc-secret") {
				t.Fatal("the resolver input carried the client secret")
			}
		})
	}
}
