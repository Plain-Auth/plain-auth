package sqlstore

import (
	"bytes"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	auth "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/client"
	"github.com/Plain-Org/plain-auth/schema"
)

type lockedLog struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (l *lockedLog) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.Write(p)
}
func (l *lockedLog) count(s string) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return strings.Count(l.buf.String(), s)
}

// UpdateUserInfoOnLink copies the provider's writable user fields when a new
// identity links by email, skips server-only fields and a profile that fails
// validation, and leaves a returning sign-in alone.
func TestOAuthLinkProfileUserFields(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			ctx := t.Context()
			fields := userFieldFixture()
			store, err := OpenWithAdditionalFields(ctx, dialect, organizationTestDSN(t, dialect), nil, schema.AdditionalFields{User: fields})
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			issuer := newProfileIssuer(t)
			app := httptest.NewUnstartedServer(nil)
			base := "http://" + app.Listener.Addr().String()
			off := false
			logs := &lockedLog{}
			server, err := auth.New(auth.Options{Store: store, BaseURL: base, Secret: strings.Repeat("s", 40), RateLimit: &off, UserAdditionalFields: fields, Logger: slog.New(slog.NewTextHandler(logs, nil)),
				UpdateUserInfoOnLink: true, SocialProviders: map[string]auth.OAuthProvider{"work": issuer.provider()}})
			if err != nil {
				t.Fatal(err)
			}
			app.Config.Handler = server
			app.Start()
			defer app.Close()
			jar, _ := cookiejar.New(nil)
			transport := &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
			c, err := client.New(base, transport)
			if err != nil {
				t.Fatal(err)
			}
			// login signs in with the issuer's current identity and returns the user.
			login := func(subject string, claims map[string]any) auth.User {
				t.Helper()
				issuer.mu.Lock()
				issuer.identity = profileIdentity{Subject: subject, Email: "ada@social.test", Claims: claims}
				issuer.mu.Unlock()
				start, err := c.SignInSocial(ctx, client.SocialSignInRequest{Provider: "work", DisableRedirect: true, CallbackURL: "/done", ErrorCallbackURL: "/failed"})
				if err != nil {
					t.Fatal(err)
				}
				approval, err := transport.Get(start.URL)
				if err != nil {
					t.Fatal(err)
				}
				approval.Body.Close()
				callback, err := approval.Location()
				if err != nil {
					t.Fatal(err)
				}
				res, err := transport.Get(callback.String())
				if err != nil {
					t.Fatal(err)
				}
				res.Body.Close()
				if landing, _ := res.Location(); landing == nil || landing.Path != "/done" {
					t.Fatal("sign-in did not complete", landing)
				}
				current, err := c.GetSession(ctx)
				if err != nil || current == nil {
					t.Fatal(err)
				}
				return current.User
			}
			first := login("ada", map[string]any{"locale": "en"})
			// A new identity linking by email copies its writable fields only.
			linked := login("second", map[string]any{"locale": "fr", "accountClass": "forged", "secretNote": "linked"})
			if linked.ID != first.ID || linked.Email != "ada@social.test" {
				t.Fatal("the second identity did not link to the same user", linked)
			}
			checkUserField(t, linked, "locale", "fr")
			checkUserField(t, linked, "accountClass", "basic")
			var note string
			if err := store.db.QueryRowContext(ctx, store.bind(`SELECT "secretNote" FROM "user" WHERE "id"=?`), first.ID).Scan(&note); err != nil || note != "linked" {
				t.Fatal("the hidden writable field was not copied", note, err)
			}
			// A profile that fails validation still links, copies nothing and
			// warns once. A returning sign-in neither copies nor warns.
			checkUserField(t, login("third", map[string]any{"locale": false}), "locale", "fr")
			checkUserField(t, login("ada", map[string]any{"locale": "de"}), "locale", "fr")
			checkUserField(t, login("ada", map[string]any{"locale": false}), "locale", "fr")
			if n := logs.count("Could not update user info on account link"); n != 1 {
				t.Fatalf("logged the link warning %d times", n)
			}
		})
	}
}
