package sqlstore

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	auth "github.com/nabuhadba/go-better-auth"
	"github.com/nabuhadba/go-better-auth/plugins/magiclink"
)

func TestMagicLinkMailboxOwnership(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			ctx := t.Context()
			dsn := filepath.Join(t.TempDir(), "mail.db")
			if dialect != "sqlite" {
				dsn = os.Getenv("AUTH_TEST_" + strings.ToUpper(dialect) + "_DSN")
				if dsn == "" {
					t.Skip("requires disposable local database")
				}
			}
			s, err := Open(ctx, dialect, dsn)
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			other, err := Open(ctx, dialect, dsn)
			if err != nil {
				t.Fatal(err)
			}
			defer other.Close()
			const origin = "https://mail.test"
			var delivery magiclink.Message
			config := magiclink.Options{HashTokens: true, Send: func(_ context.Context, m magiclink.Message) error { delivery = m; return nil }}
			makeAuth := func(store *Store, config magiclink.Options, limit bool) *auth.Auth {
				t.Helper()
				p, err := magiclink.New(config)
				if err != nil {
					t.Fatal(err)
				}
				a, err := auth.New(auth.Options{Store: store, BaseURL: origin + "/id", Secret: "private-fixture-magic-link-key-000000", EmailAndPassword: true, RateLimit: &limit, Plugins: []auth.Plugin{p}})
				if err != nil {
					t.Fatal(err)
				}
				return a
			}
			first, second := makeAuth(s, config, false), makeAuth(other, config, false)
			call := func(instance *auth.Auth, method, target string, body map[string]any) *httptest.ResponseRecorder {
				b, _ := json.Marshal(body)
				r := httptest.NewRequest(method, target, strings.NewReader(string(b)))
				r.Header.Set("Origin", origin)
				r.Header.Set("Content-Type", "application/json")
				w := httptest.NewRecorder()
				instance.ServeHTTP(w, r)
				return w
			}
			issue := func(instance *auth.Auth, email string) magiclink.Message {
				t.Helper()
				w := call(instance, "POST", origin+"/id/sign-in/magic-link", map[string]any{"email": email, "name": "Mailbox owner", "metadata": map[string]any{"locale": "en"}, "callbackURL": "/return", "newUserCallbackURL": "/welcome", "errorCallbackURL": "/failed"})
				if w.Code != 200 || strings.Contains(w.Body.String(), delivery.Token) || delivery.Email != strings.ToLower(email) || delivery.Metadata["locale"] != "en" {
					t.Fatalf("mail delivery failed: %d %s", w.Code, w.Body)
				}
				return delivery
			}
			verify := func(instance *auth.Auth, location string) *httptest.ResponseRecorder {
				return call(instance, "GET", location, nil)
			}
			expectRedirect := func(w *httptest.ResponseRecorder, want string) {
				t.Helper()
				if w.Code != 302 || w.Header().Get("Location") != origin+want {
					t.Fatalf("wanted redirect %s got HTTP %d to %q: %s", want, w.Code, w.Header().Get("Location"), w.Body)
				}
			}
			verifyJSON := func(token string) string { return origin + "/id/magic-link/verify?token=" + url.QueryEscape(token) }
			removeAccount := func(id string) {
				for _, q := range []string{`DELETE FROM "session" WHERE "userId"=?`, `DELETE FROM "account" WHERE "userId"=?`, `DELETE FROM "user" WHERE "id"=?`} {
					if _, err := s.db.ExecContext(ctx, s.bind(q), id); err != nil {
						t.Error(err)
					}
				}
			}
			prefix := strings.ToLower(rand.Text())
			email := prefix + "@mail.test"
			msg := issue(first, strings.ToUpper(email))
			verifiedURL, err := url.Parse(msg.URL)
			if err != nil || verifiedURL.Host != "mail.test" || verifiedURL.Path != "/id/magic-link/verify" || verifiedURL.Query().Get("token") != msg.Token {
				t.Fatal("unexpected mailed URL")
			}
			sum := sha256.Sum256([]byte(msg.Token))
			key := "magic-link:" + base64.RawURLEncoding.EncodeToString(sum[:])
			var raw string
			if err := s.db.QueryRowContext(ctx, s.bind(`SELECT "value" FROM "verification" WHERE "identifier"=?`), key).Scan(&raw); err != nil || strings.Contains(raw, msg.Token) {
				t.Fatal("incorrect hashed verification record")
			}
			for _, field := range []string{"callbackURL", "newUserCallbackURL", "errorCallbackURL"} {
				bad := *verifiedURL
				params := bad.Query()
				params.Set(field, "https://external.invalid/target")
				bad.RawQuery = params.Encode()
				if w := verify(first, bad.String()); w.Code != 403 || w.Header().Get("Location") != "" {
					t.Fatalf("untrusted %s accepted", field)
				}
			}
			expectRedirect(verify(second, msg.URL), "/welcome")
			u, err := s.FindAccountUser(ctx, email)
			if err != nil || !u.EmailVerified || u.Name != "Mailbox owner" {
				t.Fatalf("new mailbox account: %v", err)
			}
			defer removeAccount(u.ID)
			expectRedirect(verify(first, msg.URL), "/failed?error=INVALID_TOKEN")
			racing := issue(first, email)
			var wg sync.WaitGroup
			wins := make(chan int, 2)
			for _, instance := range []*auth.Auth{first, second} {
				wg.Add(1)
				go func() { defer wg.Done(); wins <- verify(instance, verifyJSON(racing.Token)).Code }()
			}
			wg.Wait()
			close(wins)
			var accepted, rejected int
			for status := range wins {
				switch status {
				case 200:
					accepted++
				case 302:
					rejected++
				default:
					t.Fatalf("racing verification HTTP %d", status)
				}
			}
			if accepted != 1 || rejected != 1 {
				t.Fatalf("unexpected concurrent result %d/%d", accepted, rejected)
			}
			existing := issue(first, email)
			expectRedirect(verify(second, existing.URL), "/return")
			// Change of account ownership invalidates a delivered link.
			reassigned := issue(first, email)
			if _, err := s.db.ExecContext(ctx, s.bind(`UPDATE "user" SET "email"=? WHERE "id"=?`), prefix+"-moved@mail.test", u.ID); err != nil {
				t.Fatal(err)
			}
			next, err := first.SignUpEmail(ctx, auth.SignUpInput{Email: email, Name: "Pre-verification", Password: "password before proof"}, auth.RequestMeta{})
			if err != nil {
				t.Fatal(err)
			}
			defer removeAccount(next.User.ID)
			expectRedirect(verify(second, reassigned.URL), "/failed?error=INVALID_TOKEN")
			// First proven ownership must drop the prior password, linked accounts and login.
			promotion := issue(first, email)
			w := verify(second, verifyJSON(promotion.Token))
			if w.Code != 200 {
				t.Fatalf("promotion failed: %d %s", w.Code, w.Body)
			}
			var promoted struct {
				User    auth.User
				Session auth.Session
				Token   string
			}
			if err := json.Unmarshal(w.Body.Bytes(), &promoted); err != nil || !promoted.User.EmailVerified || promoted.User.ID != next.User.ID || promoted.Token == "" || promoted.Session.UserID != next.User.ID {
				t.Fatal("verified account/session mismatch")
			}
			if _, _, err := s.Credential(ctx, email); !errors.Is(err, auth.ErrNotFound) {
				t.Fatal("prior password survived ownership proof")
			}
			if _, _, err := s.Session(ctx, next.Token); !errors.Is(err, auth.ErrNotFound) {
				t.Fatal("prior login survived ownership proof")
			}
			config.DisableSignUp = true
			restricted := makeAuth(other, config, false)
			disabled := issue(restricted, prefix+"-unknown@mail.test")
			expectRedirect(verify(restricted, disabled.URL), "/failed?error=new_user_signup_disabled")
			expectRedirect(verify(first, disabled.URL), "/failed?error=INVALID_TOKEN")
			expired := issue(first, email)
			expiredKey := sha256.Sum256([]byte(expired.Token))
			if _, err := s.db.ExecContext(ctx, s.bind(`UPDATE "verification" SET "expiresAt"=? WHERE "identifier"=?`), s.date(time.Now().Add(-time.Hour)), "magic-link:"+base64.RawURLEncoding.EncodeToString(expiredKey[:])); err != nil {
				t.Fatal(err)
			}
			expectRedirect(verify(second, expired.URL), "/failed?error=INVALID_TOKEN")
			// Configurable rule uses the same limiter as core routes.
			config.RateLimit = &auth.RateLimitRule{Max: 1, Window: time.Minute}
			limited := makeAuth(other, config, true)
			issue(limited, email)
			if w := call(limited, "POST", origin+"/id/sign-in/magic-link", map[string]any{"email": email}); w.Code != 429 {
				t.Fatalf("custom limit returned %d", w.Code)
			}
			if w := call(first, "POST", origin+"/id/sign-in/magic-link", map[string]any{"email": email, "callbackURL": "//untrusted.invalid"}); w.Code != 403 {
				t.Fatal("unsafe initiation callback accepted")
			}
		})
	}
}

func TestMagicLinkTokenOptions(t *testing.T) {
	ctx := t.Context()
	s, err := Open(ctx, "sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	const origin = "https://options.test"
	for _, custom := range []bool{false, true} {
		var msg magiclink.Message
		token := rand.Text()
		opt := magiclink.Options{Send: func(_ context.Context, m magiclink.Message) error { msg = m; return nil }, GenerateToken: func(context.Context, string) (string, error) { return token, nil }, ExpiresIn: 2 * time.Minute}
		key := token
		if custom {
			key = "custom-" + token
			opt.HashToken = func(_ context.Context, in string) (string, error) { return "custom-" + in, nil }
		}
		p, err := magiclink.New(opt)
		if err != nil {
			t.Fatal(err)
		}
		a, err := auth.New(auth.Options{BaseURL: origin, Store: s, Secret: "token-option-test-secret-000000000000000", Plugins: []auth.Plugin{p}})
		if err != nil {
			t.Fatal(err)
		}
		r := httptest.NewRequest("POST", origin+"/api/auth/sign-in/magic-link", strings.NewReader(`{"email":"someone@example.test"}`))
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		a.ServeHTTP(w, r)
		if w.Code != 200 || msg.Token != token {
			t.Fatalf("sender or generator: %d %s", w.Code, w.Body)
		}
		var created, expires time.Time
		if err := s.db.QueryRowContext(ctx, `SELECT "createdAt","expiresAt" FROM "verification" WHERE "identifier"=?`, "magic-link:"+key).Scan(&created, &expires); err != nil || expires.Sub(created) != 2*time.Minute {
			t.Fatalf("stored representation or TTL: %v", err)
		}
		w = httptest.NewRecorder()
		a.ServeHTTP(w, httptest.NewRequest("GET", msg.URL, nil))
		if w.Code != 302 || w.Header().Get("Location") != origin+"/" {
			t.Fatal("unable to consume generated link")
		}
	}
}
