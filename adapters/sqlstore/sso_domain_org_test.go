package sqlstore

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	auth "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/client"
	"github.com/Plain-Org/plain-auth/plugins/sso"
	"github.com/Plain-Org/plain-auth/schema"
	"golang.org/x/oauth2"
)

// With DomainVerification on, a social sign-in whose verified email domain
// the verified providers of exactly one organization serve joins that
// organization, as in another runtime. An unverified email, a pending
// invitation, an existing membership and a domain two organizations serve
// join nothing.
func TestEnterpriseDomainOrganizationAssignment(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			ctx := t.Context()
			must := func(err error) {
				t.Helper()
				if err != nil {
					t.Fatal(err)
				}
			}
			ddl, err := schema.Generate(dialect, []string{"organization", "sso-domain-verification"})
			must(err)
			store, err := OpenWithSchema(ctx, dialect, organizationTestDSN(t, dialect), ddl)
			must(err)
			defer store.Close()
			exec := func(q string, args ...any) {
				t.Helper()
				_, err := store.db.ExecContext(ctx, store.bind(q), args...)
				must(err)
			}
			dns := &dnsAnswers{records: map[string][]string{}}
			idp := newSSOIssuer(t)
			var profile auth.OAuthProfile
			social := auth.OAuthProvider{Config: oauth2.Config{ClientID: "client", Endpoint: oauth2.Endpoint{AuthURL: "https://social.example/authorize", TokenURL: "https://social.example/token"}},
				ExchangeCode: func(context.Context, oauth2.Config, string, string, url.Values) (*oauth2.Token, error) {
					return &oauth2.Token{AccessToken: "local"}, nil
				},
				Resolve: func(context.Context, *oauth2.Token, string) (auth.OAuthProfile, error) { return profile, nil }}
			build := func(o sso.Options) *auth.Auth {
				o.DomainVerification = &sso.DomainVerificationOptions{Resolver: dns}
				plugin, err := sso.New(o)
				must(err)
				h, err := auth.New(auth.Options{BaseURL: "https://domain.test", BasePath: "/identity", Store: store, Secret: strings.Repeat("x", 32), TrustedOrigins: []string{idp.URL}, EmailAndPassword: true, RateLimit: new(bool),
					Plugins: []auth.Plugin{plugin}, SocialProviders: map[string]auth.OAuthProvider{"social": social}})
				must(err)
				return h
			}
			h, admin := build(sso.Options{}), build(sso.Options{DefaultOrganizationRole: "admin"})
			var resolved []sso.OrganizationRoleInput
			chooser := build(sso.Options{ResolveOrganizationRole: func(_ context.Context, in sso.OrganizationRoleInput) (string, error) {
				resolved = append(resolved, in)
				return "member", nil
			}})
			owner, err := client.New("https://domain.test/identity", &http.Client{Transport: guestTransport{h}})
			must(err)
			created, err := owner.SignUpEmail(ctx, client.SignUpRequest{Name: "Owner", Email: "owner@local.example", Password: "an independent fixture password"})
			must(err)
			now := time.Now().UTC()
			for _, id := range []string{"acme-org", "beta-org"} {
				exec(`INSERT INTO "organization" ("id","name","slug","createdAt") VALUES (?,?,?,?)`, id, id, id, store.date(now))
				exec(`INSERT INTO "member" ("id","organizationId","userId","role","createdAt") VALUES (?,?,?,'owner',?)`, id+"-owner", id, created.User.ID, store.date(now))
			}
			register := func(id, organization string) {
				t.Helper()
				_, err := owner.RegisterOIDCProvider(ctx, client.RegisterOIDCProviderRequest{ProviderID: id, Domain: "acme.example", Issuer: idp.URL, OrganizationID: organization, OIDC: client.OIDCRegistration{SkipDiscovery: true, Config: sso.Config{ClientID: "enterprise-client", ClientSecret: "oidc-secret",
					AuthorizationEndpoint: idp.URL + "/authorize", TokenEndpoint: idp.URL + "/token", JWKSEndpoint: idp.URL + "/keys"}}})
				must(err)
			}
			verify := func(id string) {
				t.Helper()
				token, err := owner.RequestSSODomainVerification(ctx, id)
				must(err)
				dns.put("_plain-auth-token-"+id+".acme.example.", token)
				must(owner.VerifySSODomain(ctx, id))
			}
			signIn := func(h *auth.Auth, email string, verified bool) string {
				t.Helper()
				profile = auth.OAuthProfile{Subject: email, Name: "Employee", Email: email, EmailVerified: verified}
				request := func(method, path, body string, cookie *http.Cookie) *httptest.ResponseRecorder {
					r := httptest.NewRequest(method, "https://domain.test/identity"+path, strings.NewReader(body))
					if method == "POST" {
						r.Header.Set("Origin", "https://domain.test")
						r.Header.Set("Content-Type", "application/json")
					}
					if cookie != nil {
						r.AddCookie(cookie)
					}
					w := httptest.NewRecorder()
					h.ServeHTTP(w, r)
					return w
				}
				start := request("POST", "/sign-in/social", `{"provider":"social","disableRedirect":true}`, nil)
				var body struct{ URL string }
				must(json.Unmarshal(start.Body.Bytes(), &body))
				target, err := url.Parse(body.URL)
				must(err)
				if w := request("GET", "/callback/social?code=valid&state="+target.Query().Get("state"), "", start.Result().Cookies()[0]); w.Code != 302 {
					t.Fatal("the social callback failed", w.Code, w.Body.String())
				}
				var id string
				must(store.db.QueryRowContext(ctx, store.bind(`SELECT "id" FROM "user" WHERE "email"=?`), email).Scan(&id))
				return id
			}
			roles := func(userID string) []string {
				t.Helper()
				rows, err := store.db.QueryContext(ctx, store.bind(`SELECT "organizationId","role" FROM "member" WHERE "userId"=? ORDER BY "organizationId"`), userID)
				must(err)
				defer rows.Close()
				var out []string
				for rows.Next() {
					var group, role string
					must(rows.Scan(&group, &role))
					out = append(out, group+":"+role)
				}
				must(rows.Err())
				return out
			}
			register("acme", "acme-org")
			if got := roles(signIn(h, "early@acme.example", true)); len(got) != 0 {
				t.Fatal("a provider without a DNS proof assigned an organization", got)
			}
			verify("acme")
			if got := roles(signIn(h, "employee@acme.example", true)); len(got) != 1 || got[0] != "acme-org:member" {
				t.Fatal("a verified email in a verified domain did not join the organization as a member", got)
			}
			if got := roles(signIn(admin, "lead@acme.example", true)); len(got) != 1 || got[0] != "acme-org:admin" {
				t.Fatal("DefaultOrganizationRole did not set the role of a domain assignment", got)
			}
			if got := roles(signIn(h, "unverified@acme.example", false)); len(got) != 0 {
				t.Fatal("an unverified email joined an organization", got)
			}
			exec(`INSERT INTO "invitation" ("id","organizationId","email","status","expiresAt","inviterId","createdAt") VALUES (?,?,?,'pending',?,?,?)`, "invited", "acme-org", "invited@acme.example", store.date(now.Add(time.Hour)), created.User.ID, store.date(now))
			if got := roles(signIn(h, "invited@acme.example", true)); len(got) != 0 {
				t.Fatal("a user with a pending invitation joined the organization", got)
			}
			// A returning member keeps the role they have.
			employee := signIn(admin, "employee@acme.example", true)
			if got := roles(employee); len(got) != 1 || got[0] != "acme-org:member" {
				t.Fatal("a returning member's role changed", got)
			}
			// The role is resolved only for a user who would join, from the
			// stored user with no provider profile or token.
			signIn(chooser, "employee@acme.example", true)
			signIn(chooser, "invited@acme.example", true)
			if len(resolved) != 0 {
				t.Fatal("ResolveOrganizationRole ran for a member or a pending invitee", resolved)
			}
			chosen := signIn(chooser, "chosen@acme.example", true)
			if len(resolved) != 1 || resolved[0].UserID != chosen || resolved[0].User.Email != "chosen@acme.example" || !resolved[0].User.EmailVerified || resolved[0].UserInfo.Email != "" || resolved[0].Token != nil || resolved[0].Provider.ProviderID != "acme" {
				t.Fatal("ResolveOrganizationRole did not receive the stored user and an empty profile", resolved)
			}
			register("beta", "beta-org")
			verify("beta")
			if got := roles(signIn(h, "ambiguous@acme.example", true)); len(got) != 0 {
				t.Fatal("a domain two organizations serve assigned one", got)
			}
		})
	}
}
