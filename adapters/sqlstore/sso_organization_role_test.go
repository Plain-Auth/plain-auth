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

// A provider's organization gives a provisioned user DefaultOrganizationRole
// or the role ResolveOrganizationRole chooses before the sign-in
// transaction, and a failing resolver fails the sign-in without a member.
func TestEnterpriseOrganizationRole(t *testing.T) {
	if _, err := sso.New(sso.Options{DefaultOrganizationRole: "owner"}); err == nil {
		t.Fatal("a DefaultOrganizationRole other than member or admin was accepted")
	}
	if _, err := sso.New(sso.Options{DefaultOrganizationRole: "admin", ResolveOrganizationRole: func(context.Context, sso.OrganizationRoleInput) (string, error) { return "member", nil }}); err == nil {
		t.Fatal("conflicting organization role options were accepted")
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
			role := func(email string) string {
				t.Helper()
				var r string
				if err := store.db.QueryRowContext(ctx, store.bind(`SELECT "m"."role" FROM "member" "m" JOIN "user" "u" ON "u"."id"="m"."userId" WHERE "u"."email"=?`), email).Scan(&r); err != nil {
					return ""
				}
				return r
			}
			signIn := func(h *ssoHost, subject string) (int, bool) {
				t.Helper()
				w := h.signIn(map[string]any{"providerId": "acme"}, subject+"@acme.example", subject, "client_secret_basic", "")
				return w.Code, strings.Contains(strings.Join(w.Header().Values("Set-Cookie"), ";"), "session_token=")
			}

			signIn(newSSOHost(t, store, idp, sso.Options{}), "plain")
			if role("plain@acme.example") != "member" {
				t.Fatal("a provisioned user did not get the member role by default", role("plain@acme.example"))
			}
			signIn(newSSOHost(t, store, idp, sso.Options{DefaultOrganizationRole: "admin"}), "lead")
			if role("lead@acme.example") != "admin" {
				t.Fatal("DefaultOrganizationRole did not set the provisioned role", role("lead@acme.example"))
			}
			var mu sync.Mutex
			var seen []sso.OrganizationRoleInput
			var readErr error
			resolver := func(rc context.Context, in sso.OrganizationRoleInput) (string, error) {
				read, cancel := context.WithTimeout(rc, 2*time.Second)
				defer cancel()
				_, e := store.FindAccountUser(read, "owner@example.test")
				mu.Lock()
				defer mu.Unlock()
				seen, readErr = append(seen, in), e
				switch in.UserInfo.Subject {
				case "chosen":
					return "admin", nil
				case "owner-role":
					return "owner", nil
				case "failing":
					return "", errors.New("directory unavailable")
				}
				panic("unexpected subject")
			}
			chooser := newSSOHost(t, store, idp, sso.Options{ResolveOrganizationRole: resolver})
			signIn(chooser, "chosen")
			if role("chosen@acme.example") != "admin" {
				t.Fatal("ResolveOrganizationRole did not set the provisioned role", role("chosen@acme.example"))
			}
			mu.Lock()
			first, e := seen[0], readErr
			mu.Unlock()
			if first.User.Email != "chosen@acme.example" || first.Token == nil || first.Token.AccessToken != "access-chosen" || first.Provider.ProviderID != "acme" {
				t.Fatal("ResolveOrganizationRole did not receive the provider user, tokens and provider", first)
			}
			if e != nil {
				t.Fatal("ResolveOrganizationRole ran inside the sign-in transaction", e)
			}
			for _, subject := range []string{"owner-role", "failing", "panicking"} {
				if code, session := signIn(chooser, subject); code != 500 || session || role(subject+"@acme.example") != "" {
					t.Fatal("a failing or invalid organization role still signed in or added a member", subject, code, session)
				}
			}
			// The resolver would panic for this subject, so it must not run.
			if code, session := signIn(newSSOHost(t, store, idp, sso.Options{DisableOrganizationProvisioning: true, ResolveOrganizationRole: resolver}), "skipped"); code != 302 || !session || role("skipped@acme.example") != "" {
				t.Fatal("DisableOrganizationProvisioning still resolved a role or added a member", code, session)
			}
		})
	}
}
