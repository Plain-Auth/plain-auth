package sqlstore

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	auth "github.com/Stonewrit/stonewrit-auth"
	"github.com/Stonewrit/stonewrit-auth/adapters/memory"
	"github.com/Stonewrit/stonewrit-auth/schema"
)

func verificationRequest(a *auth.Auth, token string, headers http.Header) *httptest.ResponseRecorder {
	r := httptest.NewRequest("GET", "https://auth.example.test/api/auth/verify-email?token="+url.QueryEscape(token), nil)
	if headers != nil {
		r.Header = headers.Clone()
	}
	w := httptest.NewRecorder()
	a.ServeHTTP(w, r)
	return w
}

func TestEmailVerificationSessionAcrossStores(t *testing.T) {
	for _, dialect := range []string{"memory", "sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			store, peer := phoneStores(t, dialect)
			ctx := t.Context()
			var proof auth.MailLink
			off := false
			opts := auth.Options{Store: store, BaseURL: "https://auth.example.test", Secret: strings.Repeat("s", 48),
				EmailAndPassword: true, AutoSignInAfterVerification: true, RequireEmailVerification: true, RateLimit: &off,
				SendVerificationEmail: func(_ context.Context, m auth.MailLink) error { proof = m; return nil }}
			a, err := auth.New(opts)
			if err != nil {
				t.Fatal(err)
			}
			opts.Store = peer
			b, err := auth.New(opts)
			if err != nil {
				t.Fatal(err)
			}
			signUp := func(email string) (auth.User, string) {
				t.Helper()
				res, err := a.SignUpEmail(ctx, auth.SignUpInput{Name: "Owner", Email: email, Password: "local-proof-password"}, auth.RequestMeta{})
				if err != nil || res.Token != "" || proof.User.ID != res.User.ID {
					t.Fatal("gated signup", err)
				}
				return res.User, proof.Token
			}
			count := func(id string) int {
				t.Helper()
				list, err := peer.ListSessions(ctx, id)
				if err != nil {
					t.Fatal(err)
				}
				return len(list)
			}
			native, token := signUp("native@example.test")
			if err := b.VerifyEmail(ctx, token); err != nil {
				t.Fatal(err)
			}
			if w := verificationRequest(a, token, nil); w.Code != 200 || len(w.Result().Cookies()) != 0 || count(native.ID) != 0 {
				t.Fatal("native verification created or permitted a replay session", w.Code, w.Body)
			}
			owner, token := signUp("race@example.test")
			var wg sync.WaitGroup
			start := make(chan struct{})
			replies := make(chan *httptest.ResponseRecorder, 8)
			for i := range 8 {
				node := []*auth.Auth{a, b}[i%2]
				wg.Add(1)
				go func() { defer wg.Done(); <-start; replies <- verificationRequest(node, token, nil) }()
			}
			close(start)
			wg.Wait()
			close(replies)
			winners := 0
			for w := range replies {
				var out struct {
					Status bool
					User   *auth.User
				}
				if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &out) != nil || !out.Status || out.User != nil {
					t.Fatal("concurrent verification", w.Code, w.Body)
				}
				for _, c := range w.Result().Cookies() {
					if strings.HasSuffix(c.Name, "session_token") && c.MaxAge >= 0 {
						winners++
						req := httptest.NewRequest("GET", "/", nil)
						req.AddCookie(c)
						live, err := b.GetSession(ctx, req.Header)
						if err != nil || live == nil || live.User.ID != owner.ID || !live.User.EmailVerified {
							t.Fatal("winning browser", err)
						}
					}
				}
			}
			if winners != 1 || count(owner.ID) != 1 {
				t.Fatal("first verification must create exactly one session", winners, count(owner.ID))
			}
			// An application credential may prove a mailbox but cannot become a browser login.
			restricted, token := signUp("application@example.test")
			opts.Plugins = []auth.Plugin{{ID: "fixture-credential", CredentialSessions: &auth.CredentialSessionResolver{
				Matches: func(h http.Header) bool { return h.Get("X-Local-Credential") != "" }, Resolve: func(_ context.Context, _ http.Header, _ auth.RequestMeta, _ time.Duration) (*auth.CredentialSession, error) {
					return &auth.CredentialSession{Identity: auth.SessionResult{User: restricted, Session: auth.Session{ID: "app", Token: "app", UserID: restricted.ID, ExpiresAt: time.Now().Add(time.Hour)}}}, nil
				},
			}}}
			app, err := auth.New(opts)
			if err != nil {
				t.Fatal(err)
			}
			if w := verificationRequest(app, token, http.Header{"X-Local-Credential": {"fixture"}}); w.Code != 200 || len(w.Result().Cookies()) != 0 || count(restricted.ID) != 0 {
				t.Fatal("application credential became a browser login", w.Code, w.Body)
			}
			_, staleBrowserToken := signUp("stale-browser@example.test")
			r := httptest.NewRequest("GET", "/", nil)
			r.AddCookie(a.SessionCookie("revoked-browser", true))
			if w := verificationRequest(b, staleBrowserToken, r.Header); w.Code != 200 || len(w.Result().Cookies()) != 0 {
				t.Fatal("invalidated browser credential issued a session", w.Code)
			}
		})
	}
}

func TestEmailVerificationSessionLivePolicies(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			ctx := t.Context()
			dsn := organizationTestDSN(t, dialect)
			open := func(profiles ...string) *Store {
				t.Helper()
				ddl, err := schema.Generate(dialect, profiles)
				if err != nil {
					t.Fatal(err)
				}
				s, err := OpenWithSchema(ctx, dialect, dsn, ddl)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { s.Close() })
				return s
			}
			cold := open()
			off := false
			var proof string
			a, err := auth.New(auth.Options{BaseURL: "https://auth.example.test", Store: cold, Secret: strings.Repeat("s", 48),
				RateLimit: &off, RequireEmailVerification: true, EmailAndPassword: true, AutoSignInAfterVerification: true,
				SendVerificationEmail: func(_ context.Context, m auth.MailLink) error { proof = m.Token; return nil }})
			if err != nil {
				t.Fatal(err)
			}
			policy := open("admin", "two-factor")
			if dialect == "postgres" {
				tx, err := cold.db.BeginTx(ctx, nil)
				if err != nil {
					t.Fatal(err)
				}
				var path string
				if err := tx.QueryRowContext(ctx, `SELECT pg_catalog.set_config('search_path','pg_catalog,'||pg_catalog.quote_ident(current_schema()),true)`).Scan(&path); err != nil {
					t.Fatal(err)
				}
				found, err := cold.detectFactorSchema(ctx, tx)
				if err != nil || !found {
					t.Fatal("live enrollment fields on second schema were ignored", path, err)
				}
				if err := tx.Rollback(); err != nil {
					t.Fatal(err)
				}
			}
			write := func(q string, args ...any) {
				t.Helper()
				if _, err := policy.db.ExecContext(ctx, policy.bind(q), args...); err != nil {
					t.Fatal(err)
				}
			}
			seed := func(label string) (auth.User, string) {
				t.Helper()
				res, err := a.SignUpEmail(ctx, auth.SignUpInput{Name: "Owner", Email: label + "@example.test", Password: "local-proof-password"}, auth.RequestMeta{})
				if err != nil {
					t.Fatal(err)
				}
				return res.User, proof
			}
			assertResult := func(id, token string, h http.Header, status, wantSessions int) {
				t.Helper()
				w := verificationRequest(a, token, h)
				sessions, err := cold.ListSessions(ctx, id)
				if err != nil || w.Code != status || len(w.Result().Cookies()) != 0 || len(sessions) != wantSessions {
					t.Fatal("restricted proof result", w.Code, w.Body, len(sessions), err)
				}
			}
			for _, policyCase := range []struct{ label, column string }{{"banned", "banned"}, {"factor", "twoFactorEnabled"}} {
				u, token := seed(policyCase.label)
				write(fmt.Sprintf(`UPDATE "user" SET "%s"=? WHERE "id"=?`, policyCase.column), true, u.ID)
				assertResult(u.ID, token, nil, 200, 0)
				got, err := cold.FindAccountUser(ctx, u.Email)
				if err != nil || !got.EmailVerified {
					t.Fatal("policy suppressed mailbox verification", err)
				}
			}
			admin, _ := seed("direct")
			actor, _ := seed("delegate")
			target, claim := seed("target")
			now := time.Now().UTC()
			ss := auth.StoredSession{Session: auth.Session{ID: "fixture-delegated", Token: "fixture-delegated-token", UserID: actor.ID, CreatedAt: now, UpdatedAt: now, ExpiresAt: now.Add(time.Hour)}}
			if err := cold.CreateSession(ctx, ss); err != nil {
				t.Fatal(err)
			}
			write(`UPDATE "session" SET "impersonatedBy"=? WHERE "id"=?`, admin.ID, ss.ID)
			req := httptest.NewRequest("GET", "/", nil)
			req.AddCookie(a.SessionCookie(ss.Token, true))
			assertResult(target.ID, claim, req.Header, 200, 0)
			stale, old := seed("mailbox")
			write(`UPDATE "user" SET "email"=? WHERE "id"=?`, "new@example.test", stale.ID)
			newOwner, _ := seed("mailbox")
			assertResult(newOwner.ID, old, nil, 401, 0)
			acc, err := cold.FindAccountUser(ctx, newOwner.Email)
			if err != nil || acc.EmailVerified {
				t.Fatal("reassigned mailbox accepted old proof", err)
			}
			active, token := seed("replay")
			w := verificationRequest(a, token, nil)
			if w.Code != 200 || len(w.Result().Cookies()) == 0 {
				t.Fatal("initial proof failed", w.Code)
			}
			write(`UPDATE "user" SET "emailVerified"=? WHERE "id"=?`, false, active.ID)
			assertResult(active.ID, token, nil, 401, 1)
			olderClaim, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{"userId": active.ID, "email": active.Email,
				"iat": time.Now().Add(-time.Minute).Unix(), "exp": time.Now().Add(time.Hour).Unix()}).SignedString([]byte(strings.Repeat("s", 48)))
			if err != nil {
				t.Fatal(err)
			}
			assertResult(active.ID, olderClaim, nil, 401, 1)
			changed, newLink := seed("changed-profile")
			write(`UPDATE "user" SET "updatedAt"=? WHERE "id"=?`, policy.date(time.Now().Add(2*time.Second)), changed.ID)
			assertResult(changed.ID, newLink, nil, 200, 0)
			// Issue from a deliberately older profile so two revisions can be
			// distinguished in the same second independently of execution speed.
			for _, versioned := range []bool{true, false} {
				name := fmt.Sprintf("subsecond-%t", versioned)
				sameSecond, _ := seed(name)
				instant := time.Now().UTC().Add(-time.Minute).Truncate(time.Second)
				revision := instant.Add(100 * time.Millisecond)
				mutated := instant.Add(600 * time.Millisecond)
				write(`UPDATE "user" SET "createdAt"=?,"updatedAt"=? WHERE "id"=?`, policy.date(instant.Add(-time.Hour)), policy.date(mutated), sameSecond.ID)
				claims := jwt.MapClaims{"userId": sameSecond.ID, "email": sameSecond.Email, "iat": instant.Unix(), "exp": time.Now().Add(time.Hour).Unix()}
				if versioned {
					claims["profileUpdatedAtMs"] = revision.UnixMilli()
				}
				early, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(strings.Repeat("s", 48)))
				if err != nil {
					t.Fatal(err)
				}
				assertResult(sameSecond.ID, early, nil, 200, 0)
			}
			held, _ := seed("contention")
			hold, err := policy.db.BeginTx(ctx, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer hold.Rollback()
			if err := policy.lockAccount(ctx, hold, held.ID); err != nil {
				t.Fatal(err)
			}
			result := make(chan error, 1)
			entered := make(chan struct{})
			go func() {
				start := time.Now()
				attempt := auth.EmailVerificationAttempt{OwnerID: held.ID, Email: held.Email, Now: start, IssuedAt: start, ExpiresAt: start.Add(100 * time.Millisecond), ProofID: "local-short-lived-verification"}
				close(entered)
				_, err := cold.CompleteEmailVerification(ctx, attempt)
				result <- err
			}()
			<-entered
			timer := time.NewTimer(220 * time.Millisecond)
			<-timer.C
			if err := hold.Commit(); err != nil {
				t.Fatal(err)
			}
			if err := <-result; !errors.Is(err, auth.ErrNotFound) {
				t.Fatal("proof remained valid after waiting beyond expiry for the owner lock", err)
			}
			still, err := cold.FindAccountUser(ctx, held.Email)
			if err != nil || still.EmailVerified {
				t.Fatal("expired contended proof changed mailbox", err)
			}
			future, _ := seed("future")
			notIssued, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{"userId": future.ID, "email": future.Email, "iat": time.Now().Add(time.Minute).Unix(), "exp": time.Now().Add(time.Hour).Unix()}).SignedString([]byte(strings.Repeat("s", 48)))
			if err != nil {
				t.Fatal(err)
			}
			assertResult(future.ID, notIssued, nil, 401, 0)
		})
	}
}

func TestEmailVerificationSessionRequiresOptionalStore(t *testing.T) {
	type older struct {
		auth.Store
		auth.AccountStore
	}
	memoryStore := memory.New()
	store := older{memoryStore, memoryStore}
	var proof string
	opts := auth.Options{BaseURL: "http://auth.localhost", Secret: strings.Repeat("s", 32), Store: store, EmailAndPassword: true, RequireEmailVerification: true,
		SendVerificationEmail: func(_ context.Context, m auth.MailLink) error { proof = m.Token; return nil }}
	old, err := auth.New(opts)
	if err != nil {
		t.Fatal("disabled option rejected older store", err)
	}
	u, err := old.SignUpEmail(t.Context(), auth.SignUpInput{Email: "legacy@example.test", Name: "Legacy", Password: "legacy-test-password"}, auth.RequestMeta{})
	if err != nil || u.Token != "" || proof == "" {
		t.Fatal("legacy signup failed", err)
	}
	if err := old.VerifyEmail(t.Context(), proof); err != nil {
		t.Fatal("verification on older store failed", err)
	}
	row, err := memoryStore.FindAccountUser(t.Context(), u.User.Email)
	if err != nil || !row.EmailVerified {
		t.Fatal("legacy proof did not verify the stored address", err)
	}
	opts.AutoSignInAfterVerification = true
	if _, err := auth.New(opts); err == nil || !strings.Contains(err.Error(), "EmailVerificationSessionStore") {
		t.Fatal("enabled option accepted an incomplete store", err)
	}
}
