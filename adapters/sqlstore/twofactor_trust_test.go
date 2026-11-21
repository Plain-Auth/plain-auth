package sqlstore

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	auth "github.com/Stonewrit/stonewrit-auth"
	"github.com/Stonewrit/stonewrit-auth/plugins/twofactor"
	"github.com/Stonewrit/stonewrit-auth/schema"
	"github.com/pquerna/otp/totp"
)

type factorHarness struct {
	t             *testing.T
	first, second *auth.Auth
	store         *Store
	recovery      *auth.MailLink
}

func withFactorDatabases(t *testing.T, opts twofactor.Options, test func(*factorHarness)) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			dsn := filepath.Join(t.TempDir(), "factor.db")
			if dialect != "sqlite" {
				dsn = os.Getenv("AUTH_FACTOR_" + strings.ToUpper(dialect) + "_DSN")
				if dsn == "" {
					t.Skip("requires a dedicated local database")
				}
			}
			ddl, err := schema.Generate(dialect, []string{"two-factor"})
			if err != nil {
				t.Fatal(err)
			}
			s, err := OpenWithSchema(t.Context(), dialect, dsn, ddl)
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			other, err := OpenWithSchema(t.Context(), dialect, dsn, ddl)
			if err != nil {
				t.Fatal(err)
			}
			defer other.Close()
			off := false
			var reset auth.MailLink
			cfg := auth.Options{EmailAndPassword: true, Secret: "synthetic-factor-secret-0001-0123456789", BaseURL: "https://factor.example", Store: s, Plugins: []auth.Plugin{twofactor.New(opts)}, RateLimit: &off, SendResetPassword: func(_ context.Context, m auth.MailLink) error { reset = m; return nil }}
			a, err := auth.New(cfg)
			if err != nil {
				t.Fatal(err)
			}
			cfg.Store = other
			b, err := auth.New(cfg)
			if err != nil {
				t.Fatal(err)
			}
			test(&factorHarness{t: t, first: a, second: b, store: s, recovery: &reset})
		})
	}
}
func (h *factorHarness) request(a *auth.Auth, path string, body any, status int, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	h.t.Helper()
	data, err := json.Marshal(body)
	if err != nil {
		h.t.Fatal(err)
	}
	r := httptest.NewRequest("POST", "https://factor.example/api/auth/"+path, strings.NewReader(string(data)))
	r.Header.Set("Origin", "https://factor.example")
	r.Header.Set("Content-Type", "application/json")
	for _, c := range cookies {
		if c != nil {
			r.AddCookie(c)
		}
	}
	w := httptest.NewRecorder()
	a.ServeHTTP(w, r)
	if w.Code != status {
		h.t.Fatalf("%s: HTTP %d, wanted %d: %s", path, w.Code, status, w.Body)
	}
	return w
}
func (h *factorHarness) cookie(w *httptest.ResponseRecorder, name string) *http.Cookie {
	h.t.Helper()
	for _, c := range w.Result().Cookies() {
		if strings.HasSuffix(c.Name, "."+name) && c.MaxAge >= 0 {
			return c
		}
	}
	h.t.Fatalf("missing cookie %s", name)
	return nil
}

type enrolledAccount struct {
	input   auth.SignInInput
	userID  string
	backups []string
	session *http.Cookie
}

func (h *factorHarness) enroll() enrolledAccount {
	h.t.Helper()
	in := auth.SignInInput{Email: strings.ToLower(rand.Text()) + "@example.test", Password: "private-fixture-credential"}
	reg, err := h.first.SignUpEmail(h.t.Context(), auth.SignUpInput{Email: in.Email, Password: in.Password, Name: "Mailbox"}, auth.RequestMeta{})
	if err != nil {
		h.t.Fatal(err)
	}
	c := h.first.SessionCookie(reg.Token, true)
	enabled := h.request(h.first, "two-factor/enable", map[string]string{"password": in.Password}, 200, c)
	var body struct {
		TOTPURI     string
		BackupCodes []string
	}
	if err = json.Unmarshal(enabled.Body.Bytes(), &body); err != nil {
		h.t.Fatal(err)
	}
	u, err := url.Parse(body.TOTPURI)
	if err != nil {
		h.t.Fatal(err)
	}
	code, err := totp.GenerateCode(u.Query().Get("secret"), time.Now())
	if err != nil {
		h.t.Fatal(err)
	}
	verified := h.request(h.second, "two-factor/verify-totp", map[string]string{"code": code}, 200, c)
	return enrolledAccount{in, reg.User.ID, body.BackupCodes, h.cookie(verified, "session_token")}
}
func (h *factorHarness) trust(u enrolledAccount, backup string) *http.Cookie {
	h.t.Helper()
	login := h.request(h.first, "sign-in/email", map[string]string{"email": u.input.Email, "password": u.input.Password}, 200)
	challenge := h.cookie(login, "two_factor")
	proved := h.request(h.second, "two-factor/verify-backup-code", map[string]any{"code": backup, "trustDevice": true}, 200, challenge)
	return h.cookie(proved, "trust_device")
}
func TestRememberedFactorDevice(t *testing.T) {
	withFactorDatabases(t, twofactor.Options{Issuer: "Auth", TrustDeviceMaxAge: 42 * time.Minute, ChallengeLifetime: 3 * time.Minute}, func(h *factorHarness) {
		t := h.t
		ctx := t.Context()
		owner, other := h.enroll(), h.enroll()
		grant := h.trust(owner, owner.backups[0])
		if !grant.Secure || !grant.HttpOnly || grant.SameSite != http.SameSiteLaxMode || grant.MaxAge != 42*60 || grant.Name != h.first.TrustedDeviceCookieName() {
			t.Fatalf("invalid trusted-browser cookie attributes: %s", grant.Name)
		}
		ch, err := h.first.SignInEmail(ctx, other.input, auth.RequestMeta{TrustedDeviceCookie: grant.Value})
		if err != nil || ch.Challenge == nil || ch.Token != "" {
			t.Fatal("another account accepted a trusted grant", err)
		}
		marker := h.first.TwoFactorChallengeCookie(*ch.Challenge)
		if marker.MaxAge != 180 {
			t.Fatal("configured challenge lifetime ignored")
		}
		copied := *grant
		copied.Value += "invalid"
		ch, err = h.first.SignInEmail(ctx, owner.input, auth.RequestMeta{TrustedDeviceCookie: copied.Value})
		if err != nil || ch.Challenge == nil {
			t.Fatal("tampered grant authorized login", err)
		}
		if _, err = h.first.SignInEmail(ctx, auth.SignInInput{Email: owner.input.Email, Password: "wrong-credential"}, auth.RequestMeta{TrustedDeviceCookie: grant.Value}); err == nil {
			t.Fatal("trusted device authenticated without password")
		}
		var wg sync.WaitGroup
		results := make(chan auth.AuthResult, 2)
		errs := make(chan error, 2)
		for _, a := range []*auth.Auth{h.first, h.second} {
			wg.Add(1)
			go func() {
				defer wg.Done()
				r, e := a.SignInEmail(ctx, owner.input, auth.RequestMeta{TrustedDeviceCookie: grant.Value})
				results <- r
				errs <- e
			}()
		}
		wg.Wait()
		close(results)
		close(errs)
		for e := range errs {
			if e != nil {
				t.Fatal(e)
			}
		}
		winners, challenges := 0, 0
		var next *http.Cookie
		for r := range results {
			if r.Token != "" {
				winners++
				next = r.TrustedDeviceCookie
			} else if r.Challenge != nil {
				challenges++
			}
		}
		if winners != 1 || challenges != 1 || next == nil || next.Value == grant.Value {
			t.Fatal("one grant did not rotate into exactly one session", winners, challenges)
		}
		if row, err := h.first.GetSession(ctx, http.Header{"Cookie": {next.String()}}); err != nil || row != nil {
			t.Fatal("trusted cookie functioned as a session", err)
		}
		login := h.request(h.first, "sign-in/email", map[string]string{"email": owner.input.Email, "password": owner.input.Password}, 200, next)
		if strings.Contains(login.Body.String(), "twoFactorRedirect") {
			t.Fatal("valid rotated browser did not bypass the MFA prompt")
		}
		replacement := h.cookie(login, "trust_device")
		if replacement.Value == next.Value {
			t.Fatal("successful sign-in failed to rotate the remembered grant")
		}
		if _, err := h.store.db.ExecContext(ctx, h.store.bind(`UPDATE "verification" SET "expiresAt"=? WHERE "identifier" LIKE 'trust-device-%' AND "value"=?`), h.store.date(time.Now().Add(-time.Minute)), owner.userID); err != nil {
			t.Fatal(err)
		}
		ch, err = h.second.SignInEmail(ctx, owner.input, auth.RequestMeta{TrustedDeviceCookie: replacement.Value})
		if err != nil || ch.Challenge == nil || ch.TrustedDeviceCookie.MaxAge >= 0 {
			t.Fatal("expired remembered cookie authenticated", err)
		}
		last := h.trust(owner, owner.backups[1])
		if err = h.first.RequestPasswordReset(ctx, owner.input.Email, "/"); err != nil {
			t.Fatal(err)
		}
		if err = h.first.ResetPassword(ctx, h.recovery.Token, "replacement-password"); err != nil {
			t.Fatal(err)
		}
		ch, err = h.second.SignInEmail(ctx, auth.SignInInput{Email: owner.input.Email, Password: "replacement-password"}, auth.RequestMeta{TrustedDeviceCookie: last.Value})
		if err != nil || ch.Challenge == nil {
			t.Fatal("password recovery retained remembered browser grant", err)
		}
		var count int
		if err = h.store.db.QueryRowContext(ctx, h.store.bind(`SELECT count(*) FROM "verification" WHERE "identifier" LIKE 'trust-device-%' AND "value"=?`), owner.userID).Scan(&count); err != nil || count != 0 {
			t.Fatal(fmt.Sprintf("password reset left %d grants", count), err)
		}
	})
}
