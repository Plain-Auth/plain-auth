package sqlstore

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	auth "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/plugins/apikey"
	org "github.com/Plain-Org/plain-auth/plugins/organization"
	"github.com/Plain-Org/plain-auth/plugins/sso"
	"github.com/Plain-Org/plain-auth/schema"
)

func TestAdminProfileOnLiveServers(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			ctx := t.Context()
			must := func(e error) {
				t.Helper()
				if e != nil {
					t.Fatal(e)
				}
			}
			dsn := organizationTestDSN(t, dialect)
			open := func(profiles ...string) *Store {
				t.Helper()
				ddl, e := schema.Generate(dialect, profiles)
				must(e)
				s, e := OpenWithSchema(ctx, dialect, dsn, ddl)
				must(e)
				t.Cleanup(func() { s.Close() })
				return s
			}
			// Each path gets a server opened before migration, with an independent
			// connection pool and capability cache. Exercise direct writes first.
			read := open("sso", "organization", "two-factor")
			registration, deletion, mint, bannedRead := open(), open(), open(), open()
			keyRead, factor := open(), open()
			ssop, e := sso.New(sso.Options{})
			must(e)
			orgp, e := org.New(org.Options{Store: read})
			must(e)
			host, e := auth.New(auth.Options{Store: read, BaseURL: "https://profile.test", Secret: strings.Repeat("A", 32), Plugins: []auth.Plugin{ssop, orgp}})
			must(e)
			now := time.Now().UTC().Truncate(time.Millisecond)
			session := func(id, user string) auth.StoredSession {
				return auth.StoredSession{Session: auth.Session{ID: id, UserID: user, Token: id + "-token", CreatedAt: now, UpdatedAt: now, ExpiresAt: now.Add(time.Hour)}}
			}
			owner, operator := session("owner-session", "Owner"), session("admin-session", "Operator")
			for _, ss := range []auth.StoredSession{owner, operator} {
				must(read.CreateUser(ctx, auth.User{ID: ss.UserID, Name: ss.UserID, Email: strings.ToLower(ss.UserID) + "@example.test", CreatedAt: now, UpdatedAt: now}, "", &ss))
			}
			provider := func(id string) sso.Provider {
				return sso.Provider{ID: id + "-record", ProviderID: id, UserID: owner.UserID, Issuer: "https://identity.example", Domain: "example.test", OIDC: &sso.Config{ClientID: "company", ClientSecret: "fixture"}}
			}
			actor := func(ss auth.StoredSession) sso.Actor {
				return sso.Actor{UserID: ss.UserID, SessionID: ss.ID, SessionToken: ss.Token}
			}
			before := provider("before")
			must(registration.CreateSSOProvider(ctx, actor(owner), before, 5))
			_, _, e = read.Session(ctx, owner.Token)
			must(e)
			call := func(token, route string, body any) (int, string) {
				t.Helper()
				payload, e := json.Marshal(body)
				must(e)
				r := httptest.NewRequest("POST", "https://profile.test/api/auth/"+route, bytes.NewReader(payload))
				r.Header.Set("Origin", "https://profile.test")
				r.Header.Set("Content-Type", "application/json")
				r.AddCookie(host.SessionCookie(token, true))
				w := httptest.NewRecorder()
				host.ServeHTTP(w, r)
				return w.Code, w.Body.String()
			}
			check := func(token, route string, body any, status int) {
				t.Helper()
				got, reply := call(token, route, body)
				if got != status {
					t.Fatalf("%s: wanted %d, got %d (%s)", route, status, got, reply)
				}
			}
			check(owner.Token, "organization/create", map[string]string{"name": "Before", "slug": "before"}, 200)

			// MySQL can commit an ALTER between individual migration statements.
			// A visible ban column already carries authorization semantics.
			_, e = read.db.ExecContext(ctx, read.bind(`ALTER TABLE "user" ADD COLUMN "banned" BOOLEAN`))
			must(e)
			if row, _, e := read.Session(ctx, owner.Token); e == nil || row.Token != "" {
				t.Fatal("an incomplete administrative schema exposed an ordinary session")
			}
			if e := registration.CheckSSORegistration(ctx, actor(owner), provider("partial"), 5); e == nil {
				t.Fatal("a privileged mutation passed an incomplete administrative schema")
			}
			upgraded := open("sso", "organization", "admin")
			// Create an actual delegated login with its live source-session binding.
			_, e = upgraded.db.ExecContext(ctx, upgraded.bind(`UPDATE "user" SET "role"='admin' WHERE "id"=?`), operator.UserID)
			must(e)
			delegated := session("delegated", owner.UserID)
			must(upgraded.AdminTransaction(ctx, operator.Token, owner.UserID, now, func(tx auth.AdminTransaction, source auth.SessionResult) error {
				return tx.Impersonate(delegated, source.Session)
			}))
			if e := registration.CreateSSOProvider(ctx, actor(delegated), provider("masked"), 5); !errors.Is(e, sso.ErrUnauthenticated) {
				t.Fatalf("cold registration node accepted a delegated login: %v", e)
			}
			if e := deletion.DeleteSSOProvider(ctx, actor(delegated), before.ProviderID, before.ID, nil); !errors.Is(e, sso.ErrUnauthenticated) {
				t.Fatalf("cold deletion node accepted a delegated login: %v", e)
			}
			if e := factor.WithTwoFactor(ctx, auth.FactorSubject{SessionToken: delegated.Token, Now: now}, func(auth.FactorState) (auth.FactorChange, error) {
				t.Fatal("delegated login reached factor management")
				return auth.FactorChange{}, nil
			}); !errors.Is(e, auth.ErrNotFound) {
				t.Fatalf("cold factor store misclassified a delegated login: %v", e)
			}
			stored, _, e := read.Session(ctx, delegated.Token)
			must(e)
			if stored.ImpersonatedBy == nil || *stored.ImpersonatedBy != operator.UserID {
				t.Fatal("live session reader lost its delegated-session authority")
			}
			check(delegated.Token, "sso/delete-provider", map[string]string{"providerId": before.ProviderID}, 403)
			check(delegated.Token, "organization/create", map[string]string{"name": "Disallowed", "slug": "disallowed"}, 403)
			must(registration.CreateSSOProvider(ctx, actor(owner), provider("after"), 5))
			check(owner.Token, "organization/create", map[string]string{"name": "After", "slug": "after"}, 200)

			// Keep the sessions in place to verify live authorization independent
			// of any session cleanup performed by an administrative endpoint.
			_, e = upgraded.db.ExecContext(ctx, upgraded.bind(`UPDATE "user" SET "banned"=? WHERE "id"=?`), true, owner.UserID)
			must(e)
			if _, _, e := bannedRead.Session(ctx, owner.Token); !errors.Is(e, auth.ErrNotFound) {
				t.Fatalf("cold node returned a banned account's established session: %v", e)
			}
			if _, e := keyRead.APIKeySessionUser(ctx, owner.UserID); !errors.Is(e, apikey.ErrBanned) {
				t.Fatalf("cold API-key session reader returned a banned owner: %v", e)
			}
			var deny *auth.APIError
			if e := mint.CreateSession(ctx, session("banned-new", owner.UserID)); !errors.As(e, &deny) || deny.Code != "BANNED_USER" {
				t.Fatalf("cold node issued session after ban: %v", e)
			}
			if e := deletion.DeleteSSOProvider(ctx, actor(owner), before.ProviderID, before.ID, nil); !errors.As(e, &deny) || deny.Code != "BANNED_USER" {
				t.Fatalf("banned account changed its registration: %v", e)
			}
			check(owner.Token, "organization/create", map[string]string{"name": "Banned", "slug": "banned"}, 401)
			if e := registration.SetActiveOrganization(ctx, owner.ID, owner.UserID, nil); !errors.As(e, &deny) || deny.Code != "BANNED_USER" {
				t.Fatalf("banned actor changed the active organization in a transaction: %v", e)
			}
			_, e = upgraded.db.ExecContext(ctx, upgraded.bind(`UPDATE "user" SET "banned"=? WHERE "id"=?`), false, owner.UserID)
			must(e)
			must(deletion.DeleteSSOProvider(ctx, actor(owner), before.ProviderID, before.ID, nil))
			must(upgraded.DeleteSession(ctx, operator.Token))
			if _, _, e := read.Session(ctx, delegated.Token); !errors.Is(e, auth.ErrNotFound) {
				t.Fatalf("delegated login survived revocation of its source: %v", e)
			}
		})
	}
}
