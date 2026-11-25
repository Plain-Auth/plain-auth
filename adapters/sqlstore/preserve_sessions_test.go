package sqlstore

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	plainauth "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/internal/kvtest"
	"github.com/Plain-Org/plain-auth/plugins/onetimetoken"
)

// cookieSessionToken returns the session token a session cookie carries.
func cookieSessionToken(t *testing.T, cookie string) string {
	t.Helper()
	_, value, _ := strings.Cut(cookie, "=")
	raw, err := url.QueryUnescape(value)
	if err != nil {
		t.Fatal(err)
	}
	token, _, ok := strings.Cut(raw, ".")
	if !ok {
		t.Fatal("unsigned session cookie", cookie)
	}
	return token
}

// With PreserveSessionInDatabase, ending a session keeps its row: expiresAt
// becomes a fixed time long past, so no clock compares it as live, and
// updatedAt records the end. Neither replica serves it again, its copy is
// gone, its delete hooks run once, OAuth grants bound to it are revoked, and
// ending it again or reading it changes nothing. A session that expired on
// its own ends the same way when read, once, and a session whose creator's
// clock ran ahead ends too. Deleting the user removes every row and runs the
// hooks only for sessions that had not ended.
func TestPreservedSessions(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			ctx := t.Context()
			store := openMirrorStore(t, dialect, "oauth-provider")
			storage := kvtest.New()
			var mu sync.Mutex
			var ended []string
			hooks := plainauth.DatabaseHooks{Session: plainauth.ModelHooks[plainauth.SessionRecord]{Delete: plainauth.OperationHooks[plainauth.SessionRecord]{
				After: func(_ context.Context, row plainauth.SessionRecord, _ *plainauth.HookContext) error {
					mu.Lock()
					defer mu.Unlock()
					ended = append(ended, row.Token)
					return nil
				},
			}}}
			endedTokens := func() []string {
				mu.Lock()
				defer mu.Unlock()
				return append([]string(nil), ended...)
			}
			newNode := func() mirrorReplica {
				node, err := plainauth.New(plainauth.Options{Store: store, Secret: strings.Repeat("s", 32), BaseURL: "https://auth.example", EmailAndPassword: true,
					RateLimit: new(bool), DeleteUserEnabled: true, FreshAge: -1, SecondaryStorage: storage, StoreSessionInDatabase: true,
					PreserveSessionInDatabase: true, DatabaseHooks: hooks})
				if err != nil {
					t.Fatal(err)
				}
				return mirrorReplica{t, node}
			}
			a, b := newNode(), newNode()
			const email = "preserve@example.org"
			status, out, first := a.call("POST", "/sign-up/email", `{"name":"Person","email":"`+email+`","password":"`+mirrorPassword+`"}`, "")
			if status != 200 || first == "" {
				t.Fatal("sign-up", status, out)
			}
			signIn := func() string {
				t.Helper()
				status, out, cookie := b.call("POST", "/sign-in/email", `{"email":"`+email+`","password":"`+mirrorPassword+`"}`, "")
				if status != 200 || cookie == "" {
					t.Fatal("sign-in", status, out)
				}
				return cookie
			}
			second, third := signIn(), signIn()
			type row struct {
				id                              string
				createdAt, updatedAt, expiresAt time.Time
			}
			read := func(token string) (row, bool) {
				t.Helper()
				var r row
				err := store.db.QueryRowContext(ctx, store.bind(`SELECT "id","createdAt","updatedAt","expiresAt" FROM "session" WHERE "token"=?`), token).
					Scan(&r.id, &r.createdAt, &r.updatedAt, &r.expiresAt)
				if err != nil {
					return row{}, false
				}
				return r, true
			}
			firstToken := cookieSessionToken(t, first)
			live, ok := read(firstToken)
			if !ok {
				t.Fatal("the first session has no row")
			}
			// An OAuth grant bound to the session ends with it.
			now := time.Now().UTC().Truncate(time.Second)
			write := func(q string, args ...any) {
				t.Helper()
				if _, err := store.db.ExecContext(ctx, store.bind(q), args...); err != nil {
					t.Fatal(err)
				}
			}
			write(`INSERT INTO "oauthClient" ("id","clientId","redirectUris") VALUES ('app','app',?)`, `["https://client.example.test/cb"]`)
			write(`INSERT INTO "oauthAccessToken" ("id","token","clientId","sessionId","scopes","createdAt","expiresAt") VALUES ('grant','digest','app',?,?,?,?)`,
				live.id, `["openid"]`, store.date(now), store.date(now.Add(time.Hour)))

			before := time.Now()
			if status, _, _ := a.call("POST", "/sign-out", `{}`, first); status != 200 {
				t.Fatal("sign-out", status)
			}
			after := time.Now()
			gone, ok := read(firstToken)
			if !ok {
				t.Fatal("sign-out deleted the preserved row")
			}
			if !gone.expiresAt.Equal(endedSessionExpiry) || !gone.createdAt.Equal(live.createdAt) || gone.updatedAt.Before(before.Add(-time.Second)) || gone.updatedAt.After(after.Add(time.Second)) {
				t.Fatalf("the ended row read expiresAt %v and updatedAt %v, ended between %v and %v", gone.expiresAt, gone.updatedAt, before, after)
			}
			if _, _, ok := storage.Lookup(sessionKey(firstToken)); ok {
				t.Fatal("the ended session kept its copy")
			}
			if a.sessionUser(first) != "" || b.sessionUser(first) != "" {
				t.Fatal("a replica served an ended session")
			}
			var revoked *time.Time
			if err := store.db.QueryRowContext(ctx, store.bind(`SELECT "revoked" FROM "oauthAccessToken" WHERE "id"='grant'`)).Scan(&revoked); err != nil || revoked == nil {
				t.Fatal("the grant bound to the ended session stayed active:", revoked, err)
			}
			if got := endedTokens(); len(got) != 1 || got[0] != firstToken {
				t.Fatal("the delete hooks ran for", got)
			}
			// Signing out again, and reading the ended cookie, change nothing.
			a.call("POST", "/sign-out", `{}`, first)
			if again, _ := read(firstToken); again != gone {
				t.Fatalf("a second sign-out changed the ended row from %+v to %+v", gone, again)
			}
			if got := endedTokens(); len(got) != 1 {
				t.Fatal("the delete hooks ran again for an ended session:", got)
			}

			// Revoking the other sessions ends only the live one; the list
			// omits ended rows.
			if status, _, _ := b.call("POST", "/revoke-other-sessions", `{}`, third); status != 200 {
				t.Fatal("revoke-other-sessions", status)
			}
			secondToken := cookieSessionToken(t, second)
			if ended, ok := read(secondToken); !ok || ended.expiresAt.After(time.Now()) {
				t.Fatal("revoke-other-sessions did not end the second session:", ended, ok)
			}
			if again, _ := read(firstToken); again != gone {
				t.Fatal("revoke-other-sessions changed an ended row")
			}
			if got := endedTokens(); len(got) != 2 || got[1] != secondToken {
				t.Fatal("the delete hooks ran for", got)
			}
			if list, err := b.node.ListSessions(ctx, http.Header{"Cookie": {third}}); err != nil || len(list) != 1 {
				t.Fatal("list-sessions returned", len(list), "sessions, want only the live one:", err)
			}
			if n := len(store.sessionTokens(t, email)); n != 3 {
				t.Fatal("the database held", n, "session rows, want 3")
			}

			// A session that expired on its own ends when read: its row is
			// kept and marked ended, and its delete hooks run once.
			fourth := signIn()
			fourthToken := cookieSessionToken(t, fourth)
			write(`UPDATE "session" SET "expiresAt"=? WHERE "token"=?`, store.date(time.Now().Add(-time.Minute)), fourthToken)
			storage.Clear()
			if a.sessionUser(fourth) != "" || b.sessionUser(fourth) != "" {
				t.Fatal("an expired session was served")
			}
			if expired, ok := read(fourthToken); !ok || !expired.expiresAt.Equal(endedSessionExpiry) {
				t.Fatal("reading an expired preserved session did not keep it as ended:", expired, ok)
			}
			if got := endedTokens(); len(got) != 3 || got[2] != fourthToken {
				t.Fatal("the delete hooks ran for", got)
			}

			// A session whose creator's clock ran ahead still ends.
			thirdToken := cookieSessionToken(t, third)
			write(`UPDATE "session" SET "createdAt"=? WHERE "token"=?`, store.date(time.Now().Add(time.Hour)), thirdToken)
			if status, _, _ := a.call("POST", "/sign-out", `{}`, third); status != 200 {
				t.Fatal("sign-out", status)
			}
			if ahead, ok := read(thirdToken); !ok || !ahead.expiresAt.Equal(endedSessionExpiry) || a.sessionUser(third) != "" {
				t.Fatal("a session created ahead of this clock did not end:", ahead, ok)
			}

			// Deleting the user removes every row, ended ones included, and
			// runs the hooks only for the session that had not ended.
			fifth := signIn()
			if status, out, _ := a.call("POST", "/delete-user", `{"password":"`+mirrorPassword+`"}`, fifth); status != 200 {
				t.Fatal("delete-user", status, out)
			}
			var rows int
			if err := store.db.QueryRowContext(ctx, store.bind(`SELECT COUNT(*) FROM "session" WHERE "token" IN (?,?,?,?)`), firstToken, secondToken, thirdToken, fourthToken).Scan(&rows); err != nil || rows != 0 {
				t.Fatal("deleting the user left ended rows:", rows, err)
			}
			if n := len(store.sessionTokens(t, email)); n != 0 {
				t.Fatal("deleting the user left", n, "session rows")
			}
			if got := endedTokens(); len(got) != 5 || got[4] != cookieSessionToken(t, fifth) {
				t.Fatal("account deletion ran the delete hooks for", got)
			}
		})
	}
}

// A one-time token issued before its session ended finds no session, as it
// would if the row had been deleted.
func TestPreservedSessionOneTimeToken(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			store := openMirrorStore(t, dialect)
			plugin, err := onetimetoken.New(onetimetoken.Options{})
			if err != nil {
				t.Fatal(err)
			}
			node, err := plainauth.New(plainauth.Options{Store: store, Secret: strings.Repeat("s", 32), BaseURL: "https://auth.example", EmailAndPassword: true,
				RateLimit: new(bool), SecondaryStorage: kvtest.New(), StoreSessionInDatabase: true, PreserveSessionInDatabase: true, Plugins: []plainauth.Plugin{plugin}})
			if err != nil {
				t.Fatal(err)
			}
			a := mirrorReplica{t, node}
			status, out, cookie := a.call("POST", "/sign-up/email", `{"name":"Person","email":"ott@example.org","password":"`+mirrorPassword+`"}`, "")
			if status != 200 || cookie == "" {
				t.Fatal("sign-up", status, out)
			}
			status, out, _ = a.call("GET", "/one-time-token/generate", "", cookie)
			token, _ := out["token"].(string)
			if status != 200 || token == "" {
				t.Fatal("generate", status, out)
			}
			if status, _, _ := a.call("POST", "/sign-out", `{}`, cookie); status != 200 {
				t.Fatal("sign-out", status)
			}
			status, out, _ = a.call("POST", "/one-time-token/verify", `{"token":"`+token+`"}`, "")
			if status != 400 || out["message"] != "Session not found" {
				t.Fatal("a one-time token for an ended session answered", status, out)
			}
		})
	}
}

// PreserveSessionInDatabase needs SecondaryStorage, and one store keeps one
// setting.
func TestPreservedSessionsConfiguration(t *testing.T) {
	store := openMirrorStore(t, "sqlite")
	opts := plainauth.Options{Store: store, Secret: strings.Repeat("s", 32), BaseURL: "https://auth.example", PreserveSessionInDatabase: true}
	if _, err := plainauth.New(opts); err == nil || !strings.Contains(err.Error(), "PreserveSessionInDatabase requires SecondaryStorage") {
		t.Fatal("PreserveSessionInDatabase without SecondaryStorage:", err)
	}
	opts.SecondaryStorage, opts.StoreSessionInDatabase = kvtest.New(), true
	if _, err := plainauth.New(opts); err != nil {
		t.Fatal(err)
	}
	opts.PreserveSessionInDatabase = false
	if _, err := plainauth.New(opts); err == nil || !strings.Contains(err.Error(), "different PreserveSessionInDatabase setting") {
		t.Fatal("a second setting on the same store:", err)
	}
}
