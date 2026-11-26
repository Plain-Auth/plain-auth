package sqlstore

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	auth "github.com/Plain-Org/plain-auth"
	op "github.com/Plain-Org/plain-auth/plugins/oauthprovider"
	"github.com/Plain-Org/plain-auth/schema"
)

// OAuth authorization codes run the verification hooks on SQLite, PostgreSQL
// and MySQL, outside the store's transactions: the create hooks once the
// client, session and consent checks pass and before the code is stored, and
// the delete hooks once the exchange's checks pass and before the code is
// spent and its tokens stored.
func TestVerificationHooksAroundAuthorizationCodes(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			ctx := t.Context()
			must := func(err error) {
				t.Helper()
				if err != nil {
					t.Fatal(err)
				}
			}
			dsn := organizationTestDSN(t, dialect)
			open := func() *Store {
				t.Helper()
				s, err := OpenWithOptions(ctx, dialect, dsn, []string{"oauth-provider"}, schema.Options{})
				must(err)
				t.Cleanup(func() { s.Close() })
				return s
			}
			s, peer := open(), open()
			write := func(q string, args ...any) {
				t.Helper()
				_, err := s.db.ExecContext(ctx, s.bind(q), args...)
				must(err)
			}
			count := func(q string, args ...any) int {
				t.Helper()
				var n int
				must(s.db.QueryRowContext(ctx, s.bind(q), args...).Scan(&n))
				return n
			}
			digest := func(raw string) string {
				sum := sha256.Sum256([]byte(raw))
				return base64.RawURLEncoding.EncodeToString(sum[:])
			}

			var mu sync.Mutex
			var events []string
			var records []auth.VerificationRecord
			var paths []string
			seen := map[string][2]int{} // event → code rows and access tokens the hook read
			decline, failing := map[string]bool{}, map[string]bool{}
			note := func(ctx context.Context, event string, rec auth.VerificationRecord, c *auth.HookContext) error {
				// Each store reads on its one SQLite connection, which a hook run
				// inside that store's transaction would hold.
				read, cancel := context.WithTimeout(ctx, 5*time.Second)
				defer cancel()
				var codes, tokens int
				for _, st := range []*Store{s, peer} {
					if err := st.db.QueryRowContext(read, st.bind(`SELECT COUNT(*) FROM "verification" WHERE "identifier" LIKE 'code-%'`)).Scan(&codes); err != nil {
						t.Error("a store was locked during", event, err)
					}
					if err := st.db.QueryRowContext(read, st.bind(`SELECT COUNT(*) FROM "oauthAccessToken"`)).Scan(&tokens); err != nil {
						t.Error("a store was locked during", event, err)
					}
				}
				mu.Lock()
				defer mu.Unlock()
				events = append(events, event)
				records = append(records, rec)
				seen[event] = [2]int{codes, tokens}
				if c != nil {
					paths = append(paths, c.Path)
				}
				if decline[event] {
					return auth.ErrSkipWrite
				}
				if failing[event] {
					return errors.New("hook failed")
				}
				return nil
			}
			toggle := func(m map[string]bool, event string, on bool) {
				mu.Lock()
				defer mu.Unlock()
				m[event] = on
			}
			drain := func() ([]string, []auth.VerificationRecord) {
				mu.Lock()
				defer mu.Unlock()
				e, r := events, records
				events, records, paths = nil, nil, nil
				return e, r
			}
			same := func(got []string, want ...string) {
				t.Helper()
				if len(got)+len(want) > 0 && !reflect.DeepEqual(got, want) {
					t.Fatalf("hooks ran as %q, want %q", got, want)
				}
			}
			const (
				create  = "v-create-before:authorization-code"
				created = "v-create-after:authorization-code"
				spend   = "v-delete-before:authorization-code"
				spent   = "v-delete-after:authorization-code"
			)
			var hooks auth.DatabaseHooks
			v := &hooks.Verification
			v.Create.Before = func(ctx context.Context, r *auth.VerificationRecord, c *auth.HookContext) error {
				return note(ctx, "v-create-before:"+r.Identifier, *r, c)
			}
			v.Create.After = func(ctx context.Context, r auth.VerificationRecord, c *auth.HookContext) error {
				return note(ctx, "v-create-after:"+r.Identifier, r, c)
			}
			v.Delete.Before = func(ctx context.Context, r *auth.VerificationRecord, c *auth.HookContext) error {
				return note(ctx, "v-delete-before:"+r.Identifier, *r, c)
			}
			v.Delete.After = func(ctx context.Context, r auth.VerificationRecord, c *auth.HookContext) error {
				return note(ctx, "v-delete-after:"+r.Identifier, r, c)
			}

			var onHash func()
			var refreshes atomic.Int32
			config := op.Options{Scopes: []string{"reports", "offline_access"}, Authorization: op.BrowserAuthorizationOptions{ConsentPage: "/approve", CodeLifetime: 2 * time.Minute},
				Tokens: op.TokenOptions{
					HashAuthorizationCode: func(_ context.Context, raw string) (string, error) {
						if onHash != nil {
							onHash()
						}
						return "code-" + digest(raw), nil
					},
					GenerateRefreshToken: func(context.Context) (string, error) {
						refreshes.Add(1)
						return rand.Text(), nil
					},
				}}
			const base = "https://issuer.example.test"
			host := func(store *Store) *auth.Auth {
				t.Helper()
				p, err := op.New(config)
				must(err)
				off := false
				h, err := auth.New(auth.Options{BaseURL: base, Secret: strings.Repeat("c", 40), Store: store, Plugins: []auth.Plugin{p}, RateLimit: &off, DatabaseHooks: hooks})
				must(err)
				return h
			}
			h1, h2 := host(s), host(peer)
			now := time.Now().UTC().Truncate(time.Second)
			write(`INSERT INTO "user" ("id","name","email","emailVerified","createdAt","updatedAt") VALUES ('owner','Owner','owner@example.test',?,?,?)`, true, s.date(now), s.date(now))
			write(`INSERT INTO "session" ("id","userId","token","createdAt","updatedAt","expiresAt") VALUES ('sid','owner','browser',?,?,?)`, s.date(now), s.date(now), s.date(now.Add(time.Hour)))
			const callback = "http://127.0.0.1:41234/cb"
			write(`INSERT INTO "oauthClient" ("id","clientId","applicationType","redirectUris","scopes","tokenEndpointAuthMethod","skipConsent") VALUES ('app','app','native',?,?,'none',?)`, `["`+callback+`"]`, `["reports","offline_access"]`, true)
			write(`INSERT INTO "oauthClient" ("id","clientId","applicationType","redirectUris","scopes","tokenEndpointAuthMethod","skipConsent") VALUES ('asks','asks','native',?,?,'none',?)`, `["`+callback+`"]`, `["reports"]`, false)
			verifier := strings.Repeat("v", 64)
			authorize := func(h *auth.Auth, client, scope string, extra ...string) *httptest.ResponseRecorder {
				q := url.Values{"client_id": {client}, "response_type": {"code"}, "redirect_uri": {callback}, "scope": {scope}, "state": {"saved-state"},
					"code_challenge": {digest(verifier)}, "code_challenge_method": {"S256"}}
				for i := 0; i+1 < len(extra); i += 2 {
					q.Set(extra[i], extra[i+1])
				}
				r := httptest.NewRequest("GET", base+"/api/auth/oauth2/authorize?"+q.Encode(), nil)
				r.AddCookie(h.SessionCookie("browser", true))
				w := httptest.NewRecorder()
				h.ServeHTTP(w, r)
				return w
			}
			codeFrom := func(w *httptest.ResponseRecorder, wantErr string) string {
				t.Helper()
				u, err := url.Parse(w.Header().Get("Location"))
				must(err)
				if w.Code != 302 || u.Query().Get("error") != wantErr {
					t.Fatalf("authorize answered %d %s", w.Code, w.Header().Get("Location"))
				}
				return u.Query().Get("code")
			}
			exchange := func(h *auth.Auth, code, verifier string) *httptest.ResponseRecorder {
				form := url.Values{"grant_type": {"authorization_code"}, "client_id": {"app"}, "code": {code}, "code_verifier": {verifier}, "redirect_uri": {callback}}
				r := httptest.NewRequest("POST", base+"/api/auth/oauth2/token", strings.NewReader(form.Encode()))
				r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				w := httptest.NewRecorder()
				h.ServeHTTP(w, r)
				return w
			}
			answer := func(w *httptest.ResponseRecorder, status int, code, description string) {
				t.Helper()
				var reply struct{ Error string }
				json.Unmarshal(w.Body.Bytes(), &reply)
				if w.Code != status || reply.Error != code || description != "" && !strings.Contains(w.Body.String(), description) {
					t.Fatalf("the exchange answered %d %s, want %d %s", w.Code, w.Body.String(), status, code)
				}
			}
			row := func(code string) (string, time.Time, time.Time) {
				t.Helper()
				var id string
				var created, expires time.Time
				err := s.db.QueryRowContext(ctx, s.bind(`SELECT "id","createdAt","expiresAt" FROM "verification" WHERE "identifier"=?`), "code-"+digest(code)).Scan(&id, &created, &expires)
				if err != nil {
					return "", time.Time{}, time.Time{}
				}
				return id, created, expires
			}
			// clean checks that no record carries a secret of the flow.
			clean := func(recs []auth.VerificationRecord, secrets ...string) {
				t.Helper()
				for _, r := range recs {
					for _, secret := range append(secrets, verifier, digest(verifier), "saved-state", callback, "sid", "browser") {
						if secret != "" && strings.Contains(fmt.Sprint(r), secret) {
							t.Fatal("a record carried a secret:", r)
						}
					}
				}
			}

			// A stored code runs its create hooks once the checks pass, before it
			// is stored, with the stored row's ID.
			code := codeFrom(authorize(h1, "app", "reports"), "")
			got, recs := drain()
			same(got, create, created)
			id, start, expires := row(code)
			want := op.AuthorizationCodeRecord(op.AuthorizationCodeRecordID("code-"+digest(code)), "owner", expires)
			if id != want.ID || expires.Sub(start) != 2*time.Minute || len(recs) != 2 || recs[0] != want || recs[1] != want {
				t.Fatal("the create hooks saw", recs, "for the row", id, start, expires)
			}
			if seen[create][0] != 0 || seen[created][0] != 1 {
				t.Fatal("the create hooks read", seen[create], seen[created], "code rows")
			}
			clean(recs, code, "code-"+digest(code))
			// The exchange spends the code with its delete hooks before its tokens
			// are stored.
			answer(exchange(h2, code, verifier), 200, "", "")
			got, recs = drain()
			same(got, spend, spent)
			if recs[0] != want || recs[1] != want || seen[spend] != [2]int{1, 0} || seen[spent] != [2]int{0, 1} {
				t.Fatal("the delete hooks saw", recs, seen[spend], seen[spent])
			}

			// A visit that needs consent runs no code hooks.
			if w := authorize(h1, "asks", "reports"); w.Code != 302 || !strings.Contains(w.Header().Get("Location"), "/approve") {
				t.Fatal("a visit that needs consent answered", w.Code, w.Header().Get("Location"))
			}
			got, _ = drain()
			same(got)
			// An accepted consent runs the create hooks at /oauth2/consent; a denial runs none.
			prompt := func() string {
				t.Helper()
				w := authorize(h1, "asks", "reports", "prompt", "consent")
				u, err := url.Parse(w.Header().Get("Location"))
				must(err)
				fields, err := h1.VerifyOAuthPageQuery(u.RawQuery)
				must(err)
				return fields.Encode()
			}
			consent := func(h *auth.Auth, signed string, accept bool) *httptest.ResponseRecorder {
				body, _ := json.Marshal(map[string]any{"accept": accept, "oauth_query": signed, "scope": "reports"})
				r := httptest.NewRequest("POST", base+"/api/auth/oauth2/consent", bytes.NewReader(body))
				r.Header.Set("Origin", base)
				r.Header.Set("Content-Type", "application/json")
				r.AddCookie(h.SessionCookie("browser", true))
				w := httptest.NewRecorder()
				h.ServeHTTP(w, r)
				return w
			}
			if w := consent(h2, prompt(), false); w.Code != 200 || !strings.Contains(w.Body.String(), "access_denied") {
				t.Fatal("a denied consent answered", w.Code, w.Body.String())
			}
			got, _ = drain()
			same(got)
			// A declined code at consent still records the consent.
			toggle(decline, create, true)
			signed := prompt()
			if w := consent(h2, signed, true); w.Code != 200 || !strings.Contains(w.Body.String(), "code=") {
				t.Fatal("a declined code at consent answered", w.Code, w.Body.String())
			}
			toggle(decline, create, false)
			mu.Lock()
			atConsent := append([]string(nil), paths...)
			mu.Unlock()
			got, _ = drain()
			same(got, create)
			if !reflect.DeepEqual(atConsent, []string{"/oauth2/consent"}) || seen[create][0] != 0 {
				t.Fatal("the consent's create hook ran at", atConsent, "reading", seen[create])
			}
			if count(`SELECT COUNT(*) FROM "oauthConsent" WHERE "clientId"='asks'`) != 1 || count(`SELECT COUNT(*) FROM "verification" WHERE "identifier" LIKE 'code-%'`) != 0 {
				t.Fatal("a declined code at consent lost the consent or stored the code")
			}
			if w := consent(h1, signed, true); w.Code != 400 {
				t.Fatal("a spent consent prompt answered", w.Code)
			}
			drain()
			if w := consent(h1, prompt(), true); w.Code != 200 {
				t.Fatal("an accepted consent answered", w.Code, w.Body.String())
			}
			got, _ = drain()
			same(got, create, created)

			// A declined code is sent but never stored.
			toggle(decline, create, true)
			dead := codeFrom(authorize(h1, "app", "reports"), "")
			toggle(decline, create, false)
			got, _ = drain()
			same(got, create)
			if id, _, _ := row(dead); id != "" {
				t.Fatal("a declined code was stored")
			}
			answer(exchange(h2, dead, verifier), 400, "invalid_grant", "invalid code")
			got, _ = drain()
			same(got)
			// The checks come first: a changed client and an expired session run no hooks.
			onHash = func() {
				write(`UPDATE "oauthClient" SET "redirectUris"=? WHERE "clientId"='app'`, `["https://changed.example.test/cb"]`)
			}
			codeFrom(authorize(h1, "app", "reports"), "invalid_client")
			write(`UPDATE "oauthClient" SET "redirectUris"=? WHERE "clientId"='app'`, `["`+callback+`"]`)
			onHash = func() { write(`UPDATE "session" SET "expiresAt"=? WHERE "id"='sid'`, s.date(now)) }
			codeFrom(authorize(h1, "app", "reports"), "login_required")
			write(`UPDATE "session" SET "expiresAt"=? WHERE "id"='sid'`, s.date(now.Add(time.Hour)))
			onHash = nil
			got, _ = drain()
			same(got)
			// A failed create after hook is answered, and the code stays stored.
			stored := count(`SELECT COUNT(*) FROM "verification" WHERE "identifier" LIKE 'code-%'`)
			toggle(failing, created, true)
			w := authorize(h1, "app", "reports")
			toggle(failing, created, false)
			got, _ = drain()
			same(got, create, created)
			if w.Code < 400 || count(`SELECT COUNT(*) FROM "verification" WHERE "identifier" LIKE 'code-%'`) != stored+1 {
				t.Fatal("a failed create after hook answered", w.Code, "and removed its code")
			}
			write(`DELETE FROM "verification" WHERE "identifier" LIKE 'code-%'`)

			// An exchange refused by its checks runs no hooks.
			code = codeFrom(authorize(h1, "app", "reports"), "")
			drain()
			answer(exchange(h2, code, strings.Repeat("w", 64)), 400, "invalid_grant", "code verification failed")
			got, _ = drain()
			same(got)
			// A declined exchange keeps the code.
			toggle(decline, spend, true)
			answer(exchange(h2, code, verifier), 400, "invalid_grant", "invalid code")
			toggle(decline, spend, false)
			got, _ = drain()
			same(got, spend)
			if id, _, _ := row(code); id == "" || count(`SELECT COUNT(*) FROM "oauthAccessToken"`) != 1 {
				t.Fatal("a declined exchange spent the code or issued a token")
			}
			answer(exchange(h1, code, verifier), 200, "", "")
			got, _ = drain()
			same(got, spend, spent)

			// An offline grant spends its code once across its two passes, and
			// draws one refresh token, after the hooks approved the spend.
			code = codeFrom(authorize(h1, "app", "reports offline_access"), "")
			got, recs = drain()
			refreshes.Store(0)
			w = exchange(h2, code, verifier)
			answer(w, 200, "", "")
			got2, recs2 := drain()
			same(got2, spend, spent)
			if !strings.Contains(w.Body.String(), "refresh_token") || refreshes.Load() != 1 || recs2[0] != recs[0] || recs2[1] != recs[0] {
				t.Fatal("an offline exchange drew", refreshes.Load(), "refresh tokens and saw", recs2, "for", recs)
			}

			// Concurrent exchanges of one authorization code run one delete after hook.
			code = codeFrom(authorize(h1, "app", "reports"), "")
			drain()
			var wg sync.WaitGroup
			statuses := make(chan int, 8)
			for i := range 8 {
				wg.Go(func() { statuses <- exchange([]*auth.Auth{h1, h2}[i%2], code, verifier).Code })
			}
			wg.Wait()
			close(statuses)
			ok := 0
			for status := range statuses {
				if status == 200 {
					ok++
				} else if status != 400 {
					t.Fatal("a concurrent exchange answered", status)
				}
			}
			spends := 0
			got, _ = drain()
			for _, e := range got {
				if e == spent {
					spends++
				}
			}
			if ok != 1 || spends != 1 {
				t.Fatal("eight concurrent exchanges answered", ok, "tokens with", spends, "spends")
			}

			// A row another runtime stored is named by its own ID; an expired code runs none.
			value, err := json.Marshal(map[string]any{"type": "authorization_code", "userId": "owner", "sessionId": "sid", "query": map[string]any{
				"client_id": "app", "redirect_uri": callback, "scope": "reports", "code_challenge": digest(verifier), "code_challenge_method": "S256"}})
			must(err)
			foreign := rand.Text()
			write(`INSERT INTO "verification" ("id","identifier","value","createdAt","updatedAt","expiresAt") VALUES (?,?,?,?,?,?)`, foreign, "code-"+digest("foreign"), string(value), s.date(now), s.date(now), s.date(now.Add(time.Hour)))
			answer(exchange(h1, "foreign", verifier), 200, "", "")
			got, recs = drain()
			same(got, spend, spent)
			if recs[0].ID != foreign || recs[1].ID != foreign {
				t.Fatal("a foreign row was named", recs[0].ID)
			}
			write(`INSERT INTO "verification" ("id","identifier","value","createdAt","updatedAt","expiresAt") VALUES (?,?,?,?,?,?)`, rand.Text(), "code-"+digest("expired"), string(value), s.date(now.Add(-time.Hour)), s.date(now.Add(-time.Hour)), s.date(now.Add(-time.Minute)))
			answer(exchange(h1, "expired", verifier), 400, "invalid_grant", "invalid code")
			got, _ = drain()
			same(got)

			// A failed delete after hook removes the tokens the exchange stored.
			code = codeFrom(authorize(h1, "app", "reports offline_access"), "")
			drain()
			toggle(failing, spent, true)
			w = exchange(h2, code, verifier)
			toggle(failing, spent, false)
			got, _ = drain()
			same(got, spend, spent)
			identifier := "code-" + digest(code)
			if w.Code < 400 || strings.Contains(w.Body.String(), "access_token") || count(`SELECT COUNT(*) FROM "verification" WHERE "identifier"=?`, identifier) != 0 ||
				count(`SELECT COUNT(*) FROM "oauthAccessToken" WHERE "authorizationCodeId"=?`, identifier) != 0 || count(`SELECT COUNT(*) FROM "oauthRefreshToken" WHERE "authorizationCodeId"=?`, identifier) != 0 {
				t.Fatal("a failed delete after hook answered", w.Code, w.Body.String(), "and kept the exchange's tokens")
			}
		})
	}
}
