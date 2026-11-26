package sqlstore

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	auth "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/plugins/sso"
	"github.com/Plain-Org/plain-auth/schema"
)

// ProvisionUser runs after an enterprise sign-in commits and before the
// session cookie is set; a failure removes that session but keeps the user.
func TestEnterpriseProvisionUser(t *testing.T) {
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
			now := time.Now().UTC()
			must(store.CreateUser(ctx, auth.User{ID: "owner", Name: "Owner", Email: "owner@example.test", CreatedAt: now, UpdatedAt: now}, "credential", nil))
			_, err = store.db.ExecContext(ctx, store.bind(`INSERT INTO "organization" ("id","name","slug","createdAt") VALUES (?,?,?,?)`), "tenant", "Tenant", "tenant", store.date(now))
			must(err)
			pkce := true
			raw, err := json.Marshal(sso.Config{Issuer: idp.URL, ClientID: "enterprise-client", ClientSecret: "oidc-secret", AuthorizationEndpoint: idp.URL + "/authorize", TokenEndpoint: idp.URL + "/token", JWKSEndpoint: idp.URL + "/keys", TokenEndpointAuthentication: "client_secret_basic", PKCE: &pkce})
			must(err)
			_, err = store.db.ExecContext(ctx, store.bind(`INSERT INTO "ssoProvider" ("id","providerId","issuer","oidcConfig","domain","userId","organizationId") VALUES (?,?,?,?,?,?,?)`), "record-acme", "acme", idp.URL, string(raw), "acme.example", "owner", "tenant")
			must(err)
			var mu sync.Mutex
			var calls []sso.Provisioning
			var readErr error
			var members int
			fail := false
			record := func(rc context.Context, p sso.Provisioning) error {
				read, cancel := context.WithTimeout(rc, 2*time.Second)
				defer cancel()
				var n int
				e := store.db.QueryRowContext(read, store.bind(`SELECT COUNT(*) FROM "member" WHERE "userId"=?`), p.User.ID).Scan(&n)
				mu.Lock()
				defer mu.Unlock()
				calls, readErr, members = append(calls, p), e, n
				if fail {
					return errors.New("crm down")
				}
				return nil
			}
			once := newSSOHost(t, store, idp, sso.Options{ProvisionUser: record})
			every := newSSOHost(t, store, idp, sso.Options{ProvisionUser: record, ProvisionUserOnEveryLogin: true})
			signIn := func(h *ssoHost, subject string) (code int, location string, session bool) {
				t.Helper()
				w := h.signIn(map[string]any{"providerId": "acme"}, subject+"@acme.example", subject, "client_secret_basic", "")
				return w.Code, w.Header().Get("Location"), strings.Contains(strings.Join(w.Header().Values("Set-Cookie"), ";"), "session_token=")
			}
			made := func() int { mu.Lock(); defer mu.Unlock(); return len(calls) }

			if _, location, _ := signIn(once, "employee"); location != "https://service.test/home" {
				t.Fatal("a provisioned enterprise sign-up did not finish", location)
			}
			if made() != 1 {
				t.Fatal("ProvisionUser did not run once for a new enterprise user", made())
			}
			stored, err := store.FindAccountUser(ctx, "employee@acme.example")
			must(err)
			mu.Lock()
			first, e, n := calls[0], readErr, members
			mu.Unlock()
			if first.User.ID != stored.ID || first.User.Email != "employee@acme.example" {
				t.Fatal("ProvisionUser did not receive the stored user", first.User)
			}
			if first.UserInfo.Subject != "employee" || first.UserInfo.Name != "Enterprise User" {
				t.Fatal("ProvisionUser did not receive the mapped provider profile", first.UserInfo)
			}
			if first.Token == nil || first.Token.AccessToken != "access-employee" || first.Token.IDToken == "" {
				t.Fatal("ProvisionUser did not receive the OIDC tokens", first.Token)
			}
			if first.Provider.ProviderID != "acme" || first.Provider.OrganizationID == nil || *first.Provider.OrganizationID != "tenant" {
				t.Fatal("ProvisionUser did not receive the provider record", first.Provider)
			}
			if e != nil || n != 1 {
				t.Fatal("ProvisionUser ran inside the sign-in transaction or before the membership committed", e, n)
			}
			signIn(once, "employee")
			if made() != 1 {
				t.Fatal("ProvisionUser ran for a returning user without ProvisionUserOnEveryLogin", made())
			}
			signIn(every, "employee")
			if made() != 2 {
				t.Fatal("ProvisionUserOnEveryLogin did not run ProvisionUser for a returning user", made())
			}
			mu.Lock()
			fail = true
			mu.Unlock()
			if code, _, session := signIn(once, "second"); code != 500 || session {
				t.Fatal("a failed ProvisionUser still published a session", code, session)
			}
			panicking := newSSOHost(t, store, idp, sso.Options{ProvisionUser: func(context.Context, sso.Provisioning) error { panic("crm down") }})
			if code, _, session := signIn(panicking, "third"); code != 500 || session {
				t.Fatal("a panicking ProvisionUser still published a session", code, session)
			}
			third, err := store.FindAccountUser(ctx, "third@acme.example")
			must(err)
			var left int
			must(store.db.QueryRowContext(ctx, store.bind(`SELECT COUNT(*) FROM "session" WHERE "userId"=?`), third.ID).Scan(&left))
			if left != 0 {
				t.Fatal("a panicking ProvisionUser left the unpublished session", left)
			}
			second, err := store.FindAccountUser(ctx, "second@acme.example")
			if err != nil {
				t.Fatal("a failed ProvisionUser removed the new user", err)
			}
			var sessions int
			must(store.db.QueryRowContext(ctx, store.bind(`SELECT COUNT(*) FROM "session" WHERE "userId"=?`), second.ID).Scan(&sessions))
			if sessions != 0 {
				t.Fatal("a failed ProvisionUser left the unpublished session", sessions)
			}
		})
	}
}
