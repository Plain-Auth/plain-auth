package sqlstore

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	auth "github.com/Plain-Auth/plain-auth"
	"github.com/Plain-Auth/plain-auth/plugins/onetimetoken"
)

func TestOneTimeSessionTransfer(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			ctx := t.Context()
			dsn := filepath.Join(t.TempDir(), "transfer.db")
			if dialect != "sqlite" {
				dsn = os.Getenv("AUTH_TEST_" + strings.ToUpper(dialect) + "_DSN")
				if dsn == "" {
					t.Skip("requires disposable network database")
				}
			}
			a, err := Open(ctx, dialect, dsn)
			if err != nil {
				t.Fatal(err)
			}
			defer a.Close()
			b, err := Open(ctx, dialect, dsn)
			if err != nil {
				t.Fatal(err)
			}
			defer b.Close()
			const origin = "https://transfer.example"
			makeAuth := func(s *Store, opts onetimetoken.Options) *auth.Auth {
				t.Helper()
				p, err := onetimetoken.New(opts)
				if err != nil {
					t.Fatal(err)
				}
				limit := false
				server, err := auth.New(auth.Options{Store: s, BaseURL: origin, Secret: "one-time-transfer-fixture-secret-000000", EmailAndPassword: true, Plugins: []auth.Plugin{p}, RateLimit: &limit})
				if err != nil {
					t.Fatal(err)
				}
				return server
			}
			opts := onetimetoken.Options{SetHeaderOnNewSession: true, HashTokens: true}
			first, second := makeAuth(a, opts), makeAuth(b, opts)
			call := func(server *auth.Auth, method, route string, body map[string]any, cookies ...*http.Cookie) *httptest.ResponseRecorder {
				raw, _ := json.Marshal(body)
				r := httptest.NewRequest(method, origin+"/api/auth/"+route, strings.NewReader(string(raw)))
				r.Header.Set("Content-Type", "application/json")
				r.Header.Set("Origin", origin)
				for _, c := range cookies {
					r.AddCookie(c)
				}
				w := httptest.NewRecorder()
				server.ServeHTTP(w, r)
				return w
			}
			register := func() (auth.AuthResult, string) {
				t.Helper()
				w := call(first, "POST", "sign-up/email", map[string]any{"email": strings.ToLower(rand.Text()) + "@example.test", "password": "test-only-credential", "name": "Owner"})
				var out auth.AuthResult
				if err := json.Unmarshal(w.Body.Bytes(), &out); w.Code != 200 || err != nil || out.Token == "" {
					t.Fatal("registration failed", w.Code)
				}
				header := w.Header().Get("Set-Ott")
				if header == "" || !strings.Contains(strings.ToLower(w.Header().Get("Access-Control-Expose-Headers")), "set-ott") {
					t.Fatal("transfer token header missing")
				}
				return out, header
			}
			owner, fromHeader := register()
			other, _ := register()
			defer func() {
				for _, u := range []auth.User{owner.User, other.User} {
					for _, q := range []string{`DELETE FROM "session" WHERE "userId"=?`, `DELETE FROM "account" WHERE "userId"=?`, `DELETE FROM "user" WHERE "id"=?`} {
						_, _ = a.db.ExecContext(ctx, a.bind(q), u.ID)
					}
				}
			}()
			ownerCookie := first.SessionCookie(owner.Token, true)
			otherCookie := first.SessionCookie(other.Token, true)
			headers := http.Header{"Cookie": {ownerCookie.Name + "=" + ownerCookie.Value}}
			generate := func(server *auth.Auth, cookie *http.Cookie) string {
				t.Helper()
				w := call(server, "GET", "one-time-token/generate", nil, cookie)
				var body struct{ Token string }
				if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &body) != nil || body.Token == "" {
					t.Fatalf("generation HTTP %d %s", w.Code, w.Body)
				}
				return body.Token
			}
			verify := func(server *auth.Auth, token string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
				return call(server, "POST", "one-time-token/verify", map[string]any{"token": token, "userId": other.User.ID}, cookies...)
			}
			if w := call(first, "GET", "one-time-token/generate", nil); w.Code != 401 {
				t.Fatal("unauthenticated transfer request")
			}
			if w := call(first, "POST", "update-user", map[string]any{"name": "Updated"}, ownerCookie); w.Code != 200 || w.Header().Get("Set-Ott") != "" {
				t.Fatal("profile update generated a transfer credential")
			}
			win := verify(second, fromHeader, otherCookie)
			var state auth.SessionResult
			if win.Code != 200 || json.Unmarshal(win.Body.Bytes(), &state) != nil || state.User.ID != owner.User.ID || state.Session.Token != owner.Token || win.Header().Get("Set-Ott") != "" {
				t.Fatal("token did not transfer its bound identity exactly once")
			}
			if w := verify(first, fromHeader); w.Code != 400 || len(w.Result().Cookies()) != 0 {
				t.Fatal("header replay accepted")
			}
			transfer := generate(first, ownerCookie)
			sum := sha256.Sum256([]byte(transfer))
			var stored string
			var created, expires time.Time
			key := "one-time-token:" + base64.RawURLEncoding.EncodeToString(sum[:])
			if err := a.db.QueryRowContext(ctx, a.bind(`SELECT "value","createdAt","expiresAt" FROM "verification" WHERE "identifier"=?`), key).Scan(&stored, &created, &expires); err != nil || stored != owner.Token || expires.Sub(created) != 3*time.Minute {
				t.Fatal("unexpected hashed transfer storage")
			}
			var wg sync.WaitGroup
			statuses := make(chan int, 2)
			for _, server := range []*auth.Auth{first, second} {
				wg.Add(1)
				go func() { defer wg.Done(); statuses <- verify(server, transfer).Code }()
			}
			wg.Wait()
			close(statuses)
			var accepted, denied int
			for st := range statuses {
				switch st {
				case 200:
					accepted++
				case 400:
					denied++
				default:
					t.Fatalf("racing transfer: %d", st)
				}
			}
			if accepted != 1 || denied != 1 {
				t.Fatal("transfer did not have a unique winner")
			}
			opts.ExpiresIn = time.Minute
			opts.DisableClientRequest = true
			opts.DisableSetSessionCookie = true
			hidden := makeAuth(a, opts)
			if w := call(hidden, "GET", "one-time-token/generate", nil, ownerCookie); w.Code != 400 {
				t.Fatal("server-only generation exposed")
			}
			native, err := hidden.GenerateOneTimeToken(ctx, headers)
			if err != nil {
				t.Fatal(err)
			}
			nativeKey := sha256.Sum256([]byte(native))
			if err := a.db.QueryRowContext(ctx, a.bind(`SELECT "createdAt","expiresAt" FROM "verification" WHERE "identifier"=?`), "one-time-token:"+base64.RawURLEncoding.EncodeToString(nativeKey[:])).Scan(&created, &expires); err != nil || expires.Sub(created) != time.Minute {
				t.Fatal("custom transfer lifetime was not stored")
			}
			if w := verify(hidden, native); w.Code != 200 || len(w.Result().Cookies()) != 0 {
				t.Fatal("disabled cookie written")
			}
			row, _, err := a.Session(ctx, owner.Token)
			if err != nil {
				t.Fatal(err)
			}
			expired := rand.Text()
			if err := a.SaveOneTimeToken(ctx, expired, row.Session, time.Now(), time.Now().Add(-time.Second)); err != nil {
				t.Fatal(err)
			}
			if _, err := b.ConsumeOneTimeToken(ctx, expired, time.Now()); !errors.Is(err, auth.ErrNotFound) {
				t.Fatal("expired transfer accepted")
			}
			sourceExpired := generate(first, ownerCookie)
			if _, err := a.db.ExecContext(ctx, a.bind(`UPDATE "session" SET "expiresAt"=? WHERE "token"=?`), a.date(time.Now().Add(-time.Hour)), owner.Token); err != nil {
				t.Fatal(err)
			}
			if w := verify(second, sourceExpired); w.Code != 400 || len(w.Result().Cookies()) != 0 || !strings.Contains(w.Body.String(), "Session expired") {
				t.Fatal("expired source session transferred")
			}
			revoked := generate(first, otherCookie)
			if err := a.DeleteSession(ctx, other.Token); err != nil {
				t.Fatal(err)
			}
			if w := verify(second, revoked); w.Code != 400 || len(w.Result().Cookies()) != 0 || !strings.Contains(w.Body.String(), "Session not found") {
				t.Fatal("revoked source session transferred")
			}
		})
	}
}
