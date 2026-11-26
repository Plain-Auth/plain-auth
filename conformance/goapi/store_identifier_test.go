package goapi_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	authn "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/adapters/memory"
)

// identifierStore records the token form each covered save receives.
type identifierStore struct {
	*memory.Store
	mu    sync.Mutex
	saved []string
}

func (s *identifierStore) note(entry string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.saved = append(s.saved, entry)
}

func (s *identifierStore) entries() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.saved...)
}

func (s *identifierStore) SavePasswordResetToken(ctx context.Context, t authn.PasswordResetToken) error {
	s.note("reset:" + t.Token)
	return s.Store.SavePasswordResetToken(ctx, t)
}

func (s *identifierStore) SaveDeletionToken(ctx context.Context, t authn.PasswordResetToken) error {
	s.note("delete:" + t.Token)
	return s.Store.SaveDeletionToken(ctx, t)
}

func (s *identifierStore) SaveMagicLink(ctx context.Context, ch authn.MagicLinkChallenge) error {
	s.note("magic:" + ch.Key)
	return s.Store.SaveMagicLink(ctx, ch)
}

func (s *identifierStore) SaveOneTimeToken(ctx context.Context, key string, source authn.Session, now, expires time.Time) error {
	s.note("transfer:" + key)
	return s.Store.SaveOneTimeToken(ctx, key, source, now, expires)
}

// New refuses settings that would mix plain and hashed records of one
// purpose or name a record it does not cover; a custom store receives the
// stored form while delivered links keep the token; and a failing hash fails
// a reset request alike for registered and unknown addresses.
func TestStoreVerificationIdentifierOptions(t *testing.T) {
	ctx := t.Context()
	hash := func(context.Context, string) (string, error) { return "x", nil }
	build := func(store authn.Store, storage authn.VerificationIdentifierStorage, overrides map[string]authn.VerificationIdentifierStorage, mail authn.MailSender) (*authn.Auth, error) {
		magic, err := authn.NewMagicLink(authn.MagicLinkOptions{
			Send:          func(context.Context, authn.MagicLinkMessage) error { return nil },
			GenerateToken: func(context.Context, string) (string, error) { return "abc", nil },
		})
		if err != nil {
			t.Fatal(err)
		}
		transfers, err := authn.NewOneTimeToken(authn.OneTimeTokenOptions{GenerateToken: func(context.Context, authn.SessionResult) (string, error) { return "abc", nil }})
		if err != nil {
			t.Fatal(err)
		}
		off := false
		return authn.New(authn.Options{BaseURL: "https://auth.example", Store: store, Secret: strings.Repeat("s", 32), EmailAndPassword: true, RateLimit: &off,
			DeleteUserEnabled: true, SendResetPassword: mail, SendDeleteAccountVerification: mail, Plugins: []authn.Plugin{magic, transfers},
			StoreVerificationIdentifier: storage, StoreVerificationIdentifierOverrides: overrides})
	}
	refuse := func(storage authn.VerificationIdentifierStorage, overrides map[string]authn.VerificationIdentifierStorage, want ...string) {
		t.Helper()
		_, err := build(memory.New(), storage, overrides, nil)
		if err == nil {
			t.Fatal("New accepted", overrides)
		}
		for _, w := range want {
			if !strings.Contains(err.Error(), w) {
				t.Fatalf("the refusal %q does not name %s", err, w)
			}
		}
	}
	both := authn.VerificationIdentifierStorage{Hashed: true, Hash: hash}
	refuse(both, nil, "StoreVerificationIdentifier")
	refuse(authn.VerificationIdentifierStorage{}, map[string]authn.VerificationIdentifierStorage{"reset": both}, `"reset"`)
	for _, key := range []string{"", "auth-state:", "oauth-state:", "sign-in-otp-", "email-verification", "password-reset", "2fa-", "siwe:", "reset-password:ab"} {
		refuse(authn.VerificationIdentifierStorage{}, map[string]authn.VerificationIdentifierStorage{key: {Hashed: true}}, strconv.Quote(key))
	}
	refuse(authn.VerificationIdentifierStorage{}, map[string]authn.VerificationIdentifierStorage{"reset": {}, "reset-password:": {Hashed: true}}, `"reset"`, `"reset-password:"`)
	for _, storage := range []authn.VerificationIdentifierStorage{{}, {Hashed: true}, {Hash: hash}} {
		if _, err := build(memory.New(), storage, nil, nil); err != nil {
			t.Fatal(err)
		}
	}
	for _, key := range []string{"r", "reset", "reset-password", "reset-password:", "delete-account-", "magic-link", "magic-link:", "one-time-token", "one-time-token:"} {
		if _, err := build(memory.New(), authn.VerificationIdentifierStorage{Hashed: true}, map[string]authn.VerificationIdentifierStorage{key: {}}, nil); err != nil {
			t.Fatalf("New refused %q: %v", key, err)
		}
	}

	b64 := func(s string) string {
		sum := sha256.Sum256([]byte(s))
		return base64.RawURLEncoding.EncodeToString(sum[:])
	}
	var mu sync.Mutex
	var links []authn.MailLink
	mail := func(_ context.Context, l authn.MailLink) error {
		mu.Lock()
		defer mu.Unlock()
		links = append(links, l)
		return nil
	}
	lastLink := func() authn.MailLink {
		mu.Lock()
		defer mu.Unlock()
		return links[len(links)-1]
	}
	call := func(a *authn.Auth, method, path, body, cookie string, status int) []byte {
		t.Helper()
		headers := http.Header{"Origin": {"https://auth.example"}, "Content-Type": {"application/json"}}
		if cookie != "" {
			headers.Set("Cookie", cookie)
		}
		r := serve(t, a, method, "/api/auth"+path, body, headers, status)
		out, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	for _, hashed := range []bool{false, true} {
		store := &identifierStore{Store: memory.New()}
		a, err := build(store, authn.VerificationIdentifierStorage{Hashed: hashed}, nil, mail)
		if err != nil {
			t.Fatal(err)
		}
		form := func(prefix, token string) string {
			if hashed {
				return b64(prefix + token)
			}
			return token
		}
		signed, err := a.SignUpEmail(ctx, authn.SignUpInput{Name: "Owner", Email: "owner@example.test", Password: "initial password"}, authn.RequestMeta{})
		if err != nil {
			t.Fatal(err)
		}
		c := a.SessionCookie(signed.Token, true)
		cookie := c.Name + "=" + c.Value

		call(a, "POST", "/request-password-reset", `{"email":"owner@example.test"}`, "", 200)
		reset := lastLink()
		if !strings.Contains(reset.URL, "/reset-password/"+reset.Token+"?") || store.entries()[0] != "reset:"+form("reset-password:", reset.Token) {
			t.Fatal("the reset link or its stored form is wrong:", reset.URL, store.entries())
		}
		call(a, "POST", "/reset-password", `{"token":"`+reset.Token+`","newPassword":"another password"}`, "", 200)
		call(a, "POST", "/reset-password", `{"token":"`+reset.Token+`","newPassword":"third password"}`, "", 400)

		call(a, "GET", "/one-time-token/generate", "", cookie, 200)
		call(a, "POST", "/one-time-token/verify", `{"token":"abc"}`, "", 200)
		call(a, "POST", "/one-time-token/verify", `{"token":"abc"}`, "", 400)

		call(a, "POST", "/sign-in/magic-link", `{"email":"owner@example.test"}`, "", 200)
		verify := func() string {
			r := serve(t, a, "GET", "/api/auth/magic-link/verify?"+url.Values{"token": {"abc"}, "callbackURL": {"/done"}}.Encode(), "", nil, 302)
			return r.Header.Get("Location")
		}
		if to := verify(); strings.Contains(to, "error") {
			t.Fatal("the magic link redirected to", to)
		}
		if to := verify(); !strings.Contains(to, "error=INVALID_TOKEN") {
			t.Fatal("a replayed magic link redirected to", to)
		}

		signed, err = a.SignUpEmail(ctx, authn.SignUpInput{Name: "Leaver", Email: "leaver@example.test", Password: "initial password"}, authn.RequestMeta{})
		if err != nil {
			t.Fatal(err)
		}
		c = a.SessionCookie(signed.Token, true)
		call(a, "POST", "/delete-user", `{}`, c.Name+"="+c.Value, 200)
		deletion := lastLink()
		want := []string{"reset:" + form("reset-password:", reset.Token), "transfer:abc", "magic:abc", "delete:" + form("delete-account-", deletion.Token)}
		if hashed {
			// Fixed vectors: the SHA-256 of "one-time-token:abc" and of
			// "magic-link:abc" as unpadded URL-safe Base64.
			want[1], want[2] = "transfer:wKZunQYdoTelfY_I8ELBMMNoUTj857VPsRbjt6QyH0U", "magic:IHbWQFSav13FcmAhKTvARfvFfG1ORbMyMwmXSDHWvEw"
		}
		if got := store.entries(); strings.Join(got, " ") != strings.Join(want, " ") {
			t.Fatalf("the store received %q, want %q", got, want)
		}
		if !strings.Contains(deletion.URL, "token="+deletion.Token) {
			t.Fatal("the deletion link lacks its token:", deletion.URL)
		}
		call(a, "GET", "/delete-user/callback?token="+deletion.Token, "", c.Name+"="+c.Value, 200)
	}

	// A failing or unusable hash answers 500 for a registered address and an
	// unknown one alike, and stores nothing.
	for _, broken := range []func(context.Context, string) (string, error){
		func(context.Context, string) (string, error) { return "", errors.New("key service down") },
		func(context.Context, string) (string, error) { return "", nil },
		func(context.Context, string) (string, error) { return strings.Repeat("x", 241), nil },
		func(context.Context, string) (string, error) { return "\xff", nil },
	} {
		store := &identifierStore{Store: memory.New()}
		a, err := build(store, authn.VerificationIdentifierStorage{Hash: broken}, nil, mail)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := a.SignUpEmail(ctx, authn.SignUpInput{Name: "Owner", Email: "owner@example.test", Password: "initial password"}, authn.RequestMeta{}); err != nil {
			t.Fatal(err)
		}
		for _, email := range []string{"owner@example.test", "nobody@example.test"} {
			var body struct{ Code string }
			if err := json.Unmarshal(call(a, "POST", "/request-password-reset", `{"email":"`+email+`"}`, "", 500), &body); err != nil || body.Code != "INTERNAL_SERVER_ERROR" {
				t.Fatal("the reset request answered", body.Code, err)
			}
		}
		if len(store.entries()) != 0 {
			t.Fatal("a broken hash stored", store.entries())
		}
	}
}
