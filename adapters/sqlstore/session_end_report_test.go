package sqlstore

import (
	"context"
	"errors"
	"net/http"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	authn "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/client"
	"github.com/Plain-Org/plain-auth/internal/kvtest"
	"github.com/Plain-Org/plain-auth/schema"
)

// A store with a receiver reports each committed session end once, with
// its user and the OAuth clients that held tokens on it, revoked or not. A
// rollback reports nothing, a copy of the store shares the receiver, an
// untracked transaction is refused, a preserved row is not reported again
// when its user is deleted, and New attaches plugin observers in place of
// the earlier receiver.
func TestSessionEndReports(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			ctx := t.Context()
			must := func(err error) {
				t.Helper()
				if err != nil {
					t.Fatal(err)
				}
			}
			s, err := OpenWithOptions(ctx, dialect, organizationTestDSN(t, dialect), []string{"oauth-provider"}, schema.Options{})
			must(err)
			t.Cleanup(func() { s.Close() })
			now := time.Now().UTC().Truncate(time.Second)
			issued, until := s.date(now), s.date(now.Add(time.Hour))
			write := func(q string, args ...any) {
				t.Helper()
				_, err := s.db.ExecContext(ctx, s.bind(q), args...)
				must(err)
			}
			session := func(id string) {
				t.Helper()
				write(`INSERT INTO "session" ("id","userId","token","createdAt","updatedAt","expiresAt") VALUES (?,'owner',?,?,?,?)`, id, id+"-token", issued, issued, until)
			}
			write(`INSERT INTO "user" ("id","email","name","emailVerified","createdAt","updatedAt") VALUES ('owner','owner@ends.test','Owner',?,?,?)`, true, issued, issued)
			write(`INSERT INTO "oauthClient" ("id","clientId","redirectUris") VALUES ('alpha','alpha','[]'),('beta','beta','[]')`)
			var mu sync.Mutex
			var reports [][]authn.EndedSession
			s.ReportSessionEnds(func(_ context.Context, ended []authn.EndedSession) {
				mu.Lock()
				defer mu.Unlock()
				reports = append(reports, ended)
			})
			expect := func(want ...[]authn.EndedSession) {
				t.Helper()
				mu.Lock()
				got := reports
				reports = nil
				mu.Unlock()
				if len(got) != len(want) || len(want) > 0 && !reflect.DeepEqual(got, want) {
					t.Fatalf("reported %+v, want %+v", got, want)
				}
			}
			session("first")
			session("second")
			session("keep")
			write(`INSERT INTO "oauthAccessToken" ("id","token","clientId","sessionId","scopes","createdAt","expiresAt") VALUES ('a1','a1','alpha','first','[]',?,?),('a2','a2','alpha','first','[]',?,?)`, issued, until, issued, until)
			write(`INSERT INTO "oauthRefreshToken" ("id","token","clientId","userId","sessionId","scopes","revoked","createdAt","expiresAt") VALUES ('r1','r1','beta','owner','first','[]',?,?,?)`, issued, issued, until)
			// A sign-out reports the session and both clients, the revoked
			// refresh token's included.
			must(s.DeleteSession(ctx, "first-token"))
			expect([]authn.EndedSession{{ID: "first", UserID: "owner", OAuthClients: []string{"alpha", "beta"}}})
			must(s.DeleteSession(ctx, "first-token"))
			expect()
			// A rolled-back end reports nothing.
			tx, err := s.db.BeginTx(ctx, nil)
			must(err)
			ends := s.trackSessionEnds(ctx, tx)
			_, err = s.deleteSessionsTx(ctx, tx, `"id"=?`, "second")
			must(err)
			must(tx.Rollback())
			ends.close()
			expect()
			// An untracked transaction cannot end a session a receiver
			// would not hear about.
			tx, err = s.db.BeginTx(ctx, nil)
			must(err)
			_, err = s.deleteSessionsTx(ctx, tx, `"id"=?`, "second")
			must(tx.Rollback())
			if !errors.Is(err, errUntrackedSessionEnd) {
				t.Fatal("an untracked transaction ended a session", err)
			}
			// A copy of the store reports through the same receiver.
			fielded, err := s.WithAccountFields(nil, nil)
			must(err)
			must(fielded.DeleteOtherSessions(ctx, "owner", "keep-token"))
			expect([]authn.EndedSession{{ID: "second", UserID: "owner"}})
			// A preserved row is reported when it ends, and deleting its user
			// later reports only the sessions still live.
			must(s.MirrorSessions(kvtest.New(), authn.SessionMirrorOptions{PreserveEndedSessions: true}))
			session("kept")
			must(s.DeleteSession(ctx, "kept-token"))
			expect([]authn.EndedSession{{ID: "kept", UserID: "owner"}})
			must(s.DeleteFixtureUser(ctx, "owner"))
			expect([]authn.EndedSession{{ID: "keep", UserID: "owner"}})
			// New attaches a plugin's observer, which sees an HTTP sign-out.
			var observed []authn.SessionsEnded
			observer := authn.Plugin{ID: "observer", OnSessionsEnded: func(_ context.Context, e authn.SessionsEnded) {
				mu.Lock()
				defer mu.Unlock()
				observed = append(observed, e)
			}}
			const origin = "https://ends.example.test"
			off := false
			h, err := authn.New(authn.Options{BaseURL: origin, Secret: strings.Repeat("e", 40), Store: s, EmailAndPassword: true, Plugins: []authn.Plugin{observer}, RateLimit: &off})
			must(err)
			c, err := client.New(origin, &http.Client{Transport: guestTransport{h}})
			must(err)
			signed, err := c.SignUpEmail(ctx, client.SignUpRequest{Name: "Owner", Email: "signed@ends.test", Password: "local session end password"})
			must(err)
			must(c.SignOut(ctx))
			mu.Lock()
			got, earlier := observed, reports
			mu.Unlock()
			// The observer replaced the receiver attached before it.
			if len(earlier) != 0 {
				t.Fatal("a replaced receiver still heard session ends", earlier)
			}
			if len(got) != 1 || got[0].Auth != h || len(got[0].Sessions) != 1 || got[0].Sessions[0].UserID != signed.User.ID {
				t.Fatal("the plugin observer did not see the sign-out", got)
			}
		})
	}
}
