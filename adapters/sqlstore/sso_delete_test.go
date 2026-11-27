package sqlstore

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	auth "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/client"
	"github.com/Plain-Org/plain-auth/plugins/sso"
	"github.com/Plain-Org/plain-auth/schema"
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
			// The guard runs outside the transaction, so a sign-in on another
			// node completes while it decides; the deletion then still commits.
			var during error
			calls := 0
			must(second.DeleteSSOProvider(ctx, direct, p.ProviderID, p.ID, func(context.Context, sso.ProviderMutation) error {
				if calls++; calls == 1 {
					_, _, during = first.CompleteEnterpriseLogin(ctx, browser.Reference, "member", "corp", "one", auth.OAuthTokens{}, auth.User{ID: "unused", Email: bob.Email, Name: "returned", CreatedAt: now, UpdatedAt: now}, auth.StoredSession{Session: auth.Session{ID: "during-guard", Token: "during-guard-token", CreatedAt: now, UpdatedAt: now, ExpiresAt: now.Add(time.Hour)}}, auth.OAuthLoginOptions{})
				}
				return nil
			}))
			if during != nil {
				t.Fatal("a sign-in waited on or failed during a guard that should run outside the transaction", during)
			}
			// Deleting a provider ends no session, as in another runtime.
			if count(`SELECT COUNT(*) FROM "session" WHERE "id"='during-guard'`) != 1 {
				t.Fatal("deleting a provider ended a session it issued")
			}
			_, _, err = first.CompleteEnterpriseLogin(ctx, browser.Reference, "member", "corp", "one", auth.OAuthTokens{}, auth.User{ID: "unused", Email: bob.Email, Name: "returned", CreatedAt: now, UpdatedAt: now}, auth.StoredSession{Session: auth.Session{ID: "post-deletion", Token: "post-deletion-token", CreatedAt: now, UpdatedAt: now, ExpiresAt: now.Add(time.Hour)}}, auth.OAuthLoginOptions{})
			if !errors.Is(err, sso.ErrChanged) {
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
			deleted := make(chan error, 1)
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

// GuardProviderMutation runs outside the store's transaction; a provider
// that changes while it decides is reviewed again before the commit.
func TestEnterpriseProviderGuardOutsideTransaction(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			ctx := t.Context()
			must := func(err error) {
				t.Helper()
				if err != nil {
					t.Fatal(err)
				}
			}
			ddl, err := schema.Generate(dialect, []string{"sso", "organization"})
			must(err)
			store, err := OpenWithSchema(ctx, dialect, organizationTestDSN(t, dialect), ddl)
			must(err)
			defer store.Close()
			idp := newSSOIssuer(t)
			h := newSSOHost(t, store, idp, sso.Options{})
			owner := h.signUp("alice@enterprise.test")
			ids := map[string]string{}
			for _, id := range []string{"rotating", "flappy", "swapping", "updating"} {
				w := h.register(owner, map[string]any{"providerId": id, "issuer": idp.URL, "domain": id + ".example", "oidcConfig": map[string]any{"clientId": "application", "clientSecret": "private", "skipDiscovery": true,
					"authorizationEndpoint": idp.URL + "/authorize", "tokenEndpoint": idp.URL + "/token", "jwksEndpoint": idp.URL + "/keys"}})
				var reg struct{ ID string }
				if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &reg) != nil {
					t.Fatal("registration failed", id, w.Code, w.Body.String())
				}
				ids[id] = reg.ID
			}
			alice, err := store.FindAccountUser(ctx, "alice@enterprise.test")
			must(err)
			actor := sso.Actor{UserID: alice.ID}
			must(store.db.QueryRowContext(ctx, store.bind(`SELECT "id","token" FROM "session" WHERE "userId"=?`), alice.ID).Scan(&actor.SessionID, &actor.SessionToken))
			var seen []sso.ProviderMutation
			var readErr error
			issuer := 0
			change := func(id string) {
				issuer++
				_, err := store.db.ExecContext(ctx, store.bind(`UPDATE "ssoProvider" SET "issuer"=? WHERE "id"=?`), fmt.Sprintf("%s/rotated-%d", idp.URL, issuer), id)
				must(err)
			}
			guard := func(gc context.Context, m sso.ProviderMutation) error {
				read, cancel := context.WithTimeout(gc, 2*time.Second)
				defer cancel()
				_, readErr = store.FindAccountUser(read, "alice@enterprise.test")
				seen = append(seen, m)
				if len(seen) == 1 {
					change(m.ID)
				}
				return nil
			}
			if err := store.DeleteSSOProvider(ctx, actor, "rotating", ids["rotating"], guard); err != nil || len(seen) != 2 || seen[0].Reference == seen[1].Reference {
				t.Fatal("a provider changed after the guard ran was deleted without asking the guard again", err, len(seen))
			}
			if readErr != nil {
				t.Fatal("the mutation guard could not read the store, so it ran inside the transaction", readErr)
			}
			var n int
			must(store.db.QueryRowContext(ctx, store.bind(`SELECT COUNT(*) FROM "ssoProvider" WHERE "providerId"=?`), "rotating").Scan(&n))
			if n != 0 {
				t.Fatal("a guarded deletion did not commit after the guard approved the current snapshot", n)
			}
			// A different set of linked accounts of the same size is reviewed
			// again too.
			now := store.date(time.Now())
			link := func(account, subject string) {
				t.Helper()
				_, err := store.db.ExecContext(ctx, store.bind(`INSERT INTO "account" ("id","providerId","accountId","userId","createdAt","updatedAt") VALUES (?,?,?,?,?,?)`), account, "swapping", subject, alice.ID, now, now)
				must(err)
				must(store.ReconcileOAuthAccount(ctx, OAuthAccountAttribution{AccountID: account, UserID: alice.ID, Subject: subject, ProviderID: "swapping", EnterpriseRecordID: ids["swapping"], EnterpriseIssuer: idp.URL}))
			}
			link("swap-a", "subject-a")
			var swaps []sso.ProviderMutation
			swap := func(_ context.Context, m sso.ProviderMutation) error {
				if swaps = append(swaps, m); len(swaps) == 1 {
					_, err := store.db.ExecContext(ctx, store.bind(`DELETE FROM "account" WHERE "id"=?`), "swap-a")
					must(err)
					link("swap-b", "subject-b")
				}
				return nil
			}
			if err := store.DeleteSSOProvider(ctx, actor, "swapping", ids["swapping"], swap); err != nil || len(swaps) != 2 || swaps[0].LinkedAccounts != 1 || swaps[1].LinkedAccounts != 1 {
				t.Fatal("a deletion committed over a different set of linked accounts than the guard approved", err, len(swaps))
			}
			// The general update asks the guard outside the transaction too.
			var updates []sso.ProviderMutation
			var updateRead error
			updateGuard := func(gc context.Context, m sso.ProviderMutation) error {
				read, cancel := context.WithTimeout(gc, 2*time.Second)
				defer cancel()
				_, updateRead = store.FindAccountUser(read, "alice@enterprise.test")
				if updates = append(updates, m); len(updates) == 1 {
					change(m.ID)
				}
				return nil
			}
			scopes := func(current sso.Provider) (sso.Provider, bool, error) {
				cfg := *current.OIDC
				cfg.Scopes = []string{"openid", "email"}
				current.OIDC = &cfg
				return current, false, nil
			}
			if _, err := store.UpdateSSOProvider(ctx, actor, "updating", ids["updating"], scopes, updateGuard); err != nil || len(updates) != 2 || updates[0].Reference == updates[1].Reference || updateRead != nil {
				t.Fatal("an update guard did not run outside the transaction and review the changed provider again", err, len(updates), updateRead)
			}
			last := updates[len(updates)-1]
			if last.Action != "update" || last.ID != ids["updating"] || last.ProviderID != "updating" || last.Reference == "" || last.OrganizationID != nil || last.AuthenticationBoundaryChanged {
				t.Fatal("the update guard did not receive the provider and the change it reviews", last)
			}
			// A refusing guard stops the update without exposing its reason.
			refuse := func(context.Context, sso.ProviderMutation) error { return errors.New("private policy detail") }
			_, err = store.UpdateSSOProvider(ctx, actor, "updating", ids["updating"], func(current sso.Provider) (sso.Provider, bool, error) {
				cfg := *current.OIDC
				cfg.Scopes = []string{"openid"}
				current.OIDC = &cfg
				return current, false, nil
			}, refuse)
			var stored string
			must(store.db.QueryRowContext(ctx, store.bind(`SELECT "oidcConfig" FROM "ssoProvider" WHERE "providerId"=?`), "updating").Scan(&stored))
			if !errors.Is(err, sso.ErrMutationRejected) || strings.Contains(err.Error(), "private policy detail") || !strings.Contains(stored, `"email"`) {
				t.Fatal("a refusing update guard did not stop the update as a conflict", err)
			}
			// A refusing guard stops a deletion the same way.
			if err := store.DeleteSSOProvider(ctx, actor, "updating", ids["updating"], refuse); !errors.Is(err, sso.ErrMutationRejected) || strings.Contains(err.Error(), "private policy detail") {
				t.Fatal("a refusing deletion guard did not stop the deletion as a conflict", err)
			}
			must(store.db.QueryRowContext(ctx, store.bind(`SELECT COUNT(*) FROM "ssoProvider" WHERE "providerId"=?`), "updating").Scan(&n))
			if n != 1 {
				t.Fatal("a refused deletion removed the provider", n)
			}
			// An identity change reaches the guard as a boundary change.
			var boundary []sso.ProviderMutation
			record := func(_ context.Context, m sso.ProviderMutation) error { boundary = append(boundary, m); return nil }
			if _, err := store.UpdateSSOProvider(ctx, actor, "updating", ids["updating"], func(current sso.Provider) (sso.Provider, bool, error) {
				cfg := *current.OIDC
				cfg.ClientID = "other-application"
				current.OIDC = &cfg
				return current, true, nil
			}, record); err != nil || len(boundary) != 1 || boundary[0].Action != "update" || !boundary[0].AuthenticationBoundaryChanged {
				t.Fatal("the update guard did not see an identity change as a boundary change", err, boundary)
			}
			flapping := func(_ context.Context, m sso.ProviderMutation) error { change(m.ID); return nil }
			err = store.DeleteSSOProvider(ctx, actor, "flappy", ids["flappy"], flapping)
			must(store.db.QueryRowContext(ctx, store.bind(`SELECT COUNT(*) FROM "ssoProvider" WHERE "providerId"=?`), "flappy").Scan(&n))
			if !errors.Is(err, sso.ErrChanged) || n != 1 {
				t.Fatal("a provider that kept changing under its guard was deleted", err, n)
			}
		})
	}
}
