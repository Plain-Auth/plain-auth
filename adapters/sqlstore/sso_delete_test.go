package sqlstore

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	auth "github.com/Stonewrit/stonewrit-auth"
	"github.com/Stonewrit/stonewrit-auth/client"
	"github.com/Stonewrit/stonewrit-auth/plugins/sso"
	"github.com/Stonewrit/stonewrit-auth/schema"
)

func TestEnterpriseProviderDeletion(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			ctx := t.Context()
			must := func(err error) {
				t.Helper()
				if err != nil {
					t.Fatal(err)
				}
			}
			code := func(err error, want int) {
				t.Helper()
				var ae *auth.APIError
				if !errors.As(err, &ae) || ae.Status != want {
					t.Fatalf("wanted %d, got %v", want, err)
				}
			}
			dsn := organizationTestDSN(t, dialect)
			ddl, e := schema.Generate(dialect, []string{"sso", "organization", "admin"})
			must(e)
			first, e := OpenWithSchema(ctx, dialect, dsn, ddl)
			must(e)
			defer first.Close()
			second, e := OpenWithSchema(ctx, dialect, dsn, ddl)
			must(e)
			defer second.Close()
			makeClient := func(s *Store, g sso.MutationGuard) *client.Client {
				t.Helper()
				p, e := sso.New(sso.Options{GuardProviderMutation: g})
				must(e)
				// Neither node serves organization routes. Shared SQL roles still govern deletion.
				a, e := auth.New(auth.Options{BaseURL: "https://enterprise.test", BasePath: "/identity", Store: s, Plugins: []auth.Plugin{p}, RateLimit: new(bool), EmailAndPassword: true, Secret: strings.Repeat("s", 32)})
				must(e)
				c, e := client.New("https://enterprise.test/identity", &http.Client{Transport: guestTransport{a}})
				must(e)
				return c
			}
			owner, admin, foreign := makeClient(first, nil), makeClient(second, nil), makeClient(second, nil)
			signup := func(c *client.Client, name string) auth.User {
				r, e := c.SignUpEmail(ctx, client.SignUpRequest{Name: name, Email: name + "@enterprise.test", Password: "valid-long-password"})
				must(e)
				return r.User
			}
			alice, bob, eve := signup(owner, "alice"), signup(admin, "bob"), signup(foreign, "eve")
			now := time.Now().UTC()
			exec := func(sql string, args ...any) {
				t.Helper()
				_, e := first.db.ExecContext(ctx, first.bind(sql), args...)
				must(e)
			}
			count := func(q string, args ...any) int {
				t.Helper()
				var n int
				must(first.db.QueryRowContext(ctx, first.bind(q), args...).Scan(&n))
				return n
			}
			exec(`INSERT INTO "organization" ("id","name","slug","createdAt") VALUES ('tenant','Company','company',?)`, first.date(now))
			for role, uid := range map[string]string{"owner": alice.ID, "admin": bob.ID, "member": eve.ID} {
				exec(`INSERT INTO "member" ("id","organizationId","userId","role","createdAt") VALUES (?,'tenant',?,?,?)`, role, uid, role, first.date(now))
			}
			register := func(c *client.Client, id, org string) sso.Registered {
				p, e := c.RegisterOIDCProvider(ctx, client.RegisterOIDCProviderRequest{ProviderID: id, OrganizationID: org, Domain: "enterprise.test", Issuer: "https://idp.example", OIDC: client.OIDCRegistration{SkipDiscovery: true, Config: sso.Config{ClientID: "application", ClientSecret: "private", AuthorizationEndpoint: "https://idp.example/authorize", TokenEndpoint: "https://idp.example/token", JWKSEndpoint: "https://idp.example/keys"}}})
				must(e)
				return p
			}
			account := func(id, provider, subject, uid string) {
				exec(`INSERT INTO "account" ("id","providerId","accountId","userId","createdAt","updatedAt") VALUES (?,?,?,?,?,?)`, id, provider, subject, uid, first.date(now), first.date(now))
			}
			personal := register(owner, "personal", "")
			p := register(owner, "corp", "tenant")
			account("a-one", "corp", "one", bob.ID)
			account("a-two", "corp", "two", eve.ID)
			account("a-case", "Corp", "foreign", eve.ID)
			account("a-other", "personal", "one", alice.ID)
			// A static OAuth node uses the same provider name for an unrelated subject.
			socialCandidate := auth.User{ID: "social-owner", Name: "Social owner", Email: "social@example.test", CreatedAt: now, UpdatedAt: now}
			socialSession := auth.StoredSession{Session: auth.Session{ID: "social-session", Token: "social-token", CreatedAt: now, UpdatedAt: now, ExpiresAt: now.Add(time.Hour)}}
			_, _, e = second.CompleteOAuth(ctx, "corp", "ordinary-subject", auth.OAuthTokens{AccessToken: "static-only"}, socialCandidate, socialSession, auth.OAuthLoginOptions{})
			must(e)
			var staticID string
			must(first.db.QueryRowContext(ctx, first.bind(`SELECT "id" FROM "account" WHERE "providerId"='corp' AND "accountId"='ordinary-subject'`)).Scan(&staticID))
			// A historical canonical row with no origin is ambiguous even when the
			// subject and email are known. Only a trusted explicit classification can resolve it.
			if _, err := second.ProviderCredential(ctx, bob.ID, "a-one"); !errors.Is(err, auth.ErrNotFound) {
				t.Fatalf("unclassified credential exposed: %v", err)
			}
			mismatch := OAuthAccountAttribution{AccountID: "a-one", UserID: bob.ID, Subject: "one", ProviderID: "corp", EnterpriseRecordID: p.ID, EnterpriseIssuer: "https://different.example", EnterpriseOrganizationID: "tenant"}
			if err := second.ReconcileOAuthAccount(ctx, mismatch); !errors.Is(err, auth.ErrOAuthLinkRequired) {
				t.Fatalf("reconciled wrong issuer: %v", err)
			}
			mismatch.EnterpriseIssuer = p.Issuer
			mismatch.EnterpriseOrganizationID = "other-tenant"
			if e := first.ReconcileOAuthAccount(ctx, mismatch); !errors.Is(e, auth.ErrOAuthLinkRequired) {
				t.Fatalf("reconciled foreign tenant: %v", e)
			}
			code(admin.DeleteSSOProvider(ctx, "corp"), 409)
			for _, fixture := range []struct{ id, subject, uid string }{{"a-one", "one", bob.ID}, {"a-two", "two", eve.ID}} {
				must(first.ReconcileOAuthAccount(ctx, OAuthAccountAttribution{AccountID: fixture.id, UserID: fixture.uid, Subject: fixture.subject, ProviderID: "corp", EnterpriseRecordID: p.ID, EnterpriseIssuer: p.Issuer, EnterpriseOrganizationID: "tenant"}))
			}
			must(first.ReconcileOAuthAccount(ctx, OAuthAccountAttribution{AccountID: "a-other", UserID: alice.ID, Subject: "one", ProviderID: "personal", EnterpriseRecordID: personal.ID, EnterpriseIssuer: personal.Issuer}))
			if err := second.ReconcileOAuthAccount(ctx, OAuthAccountAttribution{AccountID: "a-one", UserID: bob.ID, Subject: "one", ProviderID: "corp"}); !errors.Is(err, auth.ErrOAuthLinkRequired) {
				t.Fatalf("changed established attribution: %v", err)
			}
			browser, e := first.FindBrowserProvider(ctx, sso.Selector{ProviderID: p.ProviderID})
			must(e)
			direct := sso.Actor{UserID: bob.ID}
			must(first.db.QueryRowContext(ctx, first.bind(`SELECT "id","token" FROM "session" WHERE "userId"=?`), bob.ID).Scan(&direct.SessionID, &direct.SessionToken))
			code(makeClient(first, nil).DeleteSSOProvider(ctx, "corp"), 401)
			code(foreign.DeleteSSOProvider(ctx, "corp"), 403)
			code(admin.DeleteSSOProvider(ctx, "personal"), 403)
			code(owner.DeleteSSOProvider(ctx, "CORP"), 404)
			code(first.DeleteSSOProvider(ctx, direct, "credential", p.ID, nil), 404)
			exec(`UPDATE "member" SET "role"='member' WHERE "userId"=?`, alice.ID)
			code(owner.DeleteSSOProvider(ctx, "corp"), 403)
			missing := direct
			missing.SessionToken = "stale-session"
			code(first.DeleteSSOProvider(ctx, missing, "corp", p.ID, nil), 401)
			rejected := makeClient(second, func(_ context.Context, m sso.ProviderMutation) error {
				if m.Action != "delete" || m.ID != p.ID || m.ProviderID != "corp" || m.OrganizationID == nil || *m.OrganizationID != "tenant" || m.LinkedAccounts != 2 || m.Reference != browser.Reference {
					t.Fatalf("unexpected guard snapshot %+v", m)
				}
				return errors.New("confidential application detail")
			})
			_, e = rejected.SignInEmail(ctx, client.SignInRequest{Email: bob.Email, Password: "valid-long-password"})
			must(e)
			err := rejected.DeleteSSOProvider(ctx, "corp")
			code(err, 409)
			if strings.Contains(err.Error(), "confidential application detail") || count(`SELECT COUNT(*) FROM "account" WHERE "id" IN ('a-one','a-two')`) != 2 {
				t.Fatal("guard did not preserve links or exposed its error")
			}
			// Hold the exact provider while a second node tries issuing a linked session.
			entered, release := make(chan struct{}), make(chan struct{})
			deleted := make(chan error, 1)
			go func() {
				deleted <- second.DeleteSSOProvider(ctx, direct, p.ProviderID, p.ID, func(context.Context, sso.ProviderMutation) error { close(entered); <-release; return nil })
			}()
			<-entered
			waiting := make(chan error, 1)
			started := make(chan struct{})
			go func() {
				close(started)
				_, _, err := first.CompleteEnterpriseLogin(ctx, browser.Reference, true, "corp", "one", auth.OAuthTokens{}, auth.User{ID: "unused", Email: bob.Email, Name: "returned", CreatedAt: now, UpdatedAt: now}, auth.StoredSession{Session: auth.Session{ID: "post-deletion", Token: "post-deletion-token", CreatedAt: now, UpdatedAt: now, ExpiresAt: now.Add(time.Hour)}}, auth.OAuthLoginOptions{})
				waiting <- err
			}()
			<-started
			close(release)
			must(<-deleted)
			if err := <-waiting; !errors.Is(err, sso.ErrChanged) {
				t.Fatalf("stale login returned %v", err)
			}
			if count(`SELECT COUNT(*) FROM "session" WHERE "id"='post-deletion'`) != 0 || count(`SELECT COUNT(*) FROM "account" WHERE "id" IN ('a-one','a-two')`) != 0 {
				t.Fatal("removed provider left a link or issued a session")
			}
			if count(`SELECT COUNT(*) FROM "account" WHERE "id" IN ('a-case','a-other')`) != 2 || count(`SELECT COUNT(*) FROM "member" WHERE "organizationId"='tenant'`) != 3 {
				t.Fatal("unrelated identity or tenant membership changed")
			}
			code(admin.DeleteSSOProvider(ctx, "corp"), 404)
			cred, e := second.ProviderCredential(ctx, socialCandidate.ID, staticID)
			must(e)
			if cred.AccessToken != "static-only" {
				t.Fatal("deletion removed same-name static credentials")
			}
			must(second.UnlinkAccount(ctx, socialCandidate.ID, staticID, true))
			if count(`SELECT COUNT(*) FROM "verification" WHERE "id"=?`, sourceID(staticID)) != 0 {
				t.Fatal("unlink retained stale source")
			}

			// The case-distinct fixture remains in a MySQL case-insensitive namespace;
			// remove it here before requesting a fresh registration.
			exec(`DELETE FROM "account" WHERE "id"='a-case'`)
			replacement := register(admin, "corp", "tenant")
			if replacement.ID == p.ID {
				t.Fatal("reused old record ID")
			}
			code(second.DeleteSSOProvider(ctx, direct, "corp", p.ID, nil), 404)
			// Link-first ordering: deletion must include a link committed by the
			// in-flight holder of the same provider lock.
			link, err := first.beginMembershipChange(ctx)
			must(err)
			defer link.Rollback()
			var locked string
			must(link.QueryRowContext(ctx, first.readForUpdate(`SELECT "id" FROM "ssoProvider" WHERE "id"=?`), replacement.ID).Scan(&locked))
			linkFirst := make(chan struct{})
			go func() {
				close(linkFirst)
				deleted <- second.DeleteSSOProvider(ctx, direct, "corp", replacement.ID, func(_ context.Context, m sso.ProviderMutation) error {
					if m.LinkedAccounts != 1 {
						return errors.New("newly committed account missing from deletion snapshot")
					}
					return nil
				})
			}()
			<-linkFirst
			_, err = link.ExecContext(ctx, first.bind(`INSERT INTO "account" ("id","providerId","accountId","userId","createdAt","updatedAt") VALUES ('last-link','corp','last',?,?,?)`), eve.ID, first.date(now), first.date(now))
			must(err)
			must(first.writeAccountSource(ctx, link, oauthIdentity{ID: "last-link", UserID: eve.ID, ProviderID: "corp", Subject: "last", CreatedMS: now.UnixMilli()}, enterpriseAuthority(replacement.ID, replacement.Issuer, replacement.OrganizationID)))
			must(link.Commit())
			must(<-deleted)
			if count(`SELECT COUNT(*) FROM "account" WHERE "id"='last-link'`) != 0 {
				t.Fatal("last link survived concurrent deletion")
			}
			if count(`SELECT COUNT(*) FROM "ssoProvider" WHERE "id"=?`, personal.ID) != 1 {
				t.Fatal("foreign record deleted")
			}
			must(owner.DeleteSSOProvider(ctx, personal.ProviderID))
		})
	}
}
