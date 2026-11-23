package sqlstore

import (
	"context"
	"errors"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	auth "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/client"
	"github.com/Plain-Org/plain-auth/schema"
)

func TestOAuthVerifiedEmailBeforeSession(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			ctx := t.Context()
			var defaults atomic.Int32
			fields := schema.AdditionalFields{
				User:    map[string]auth.UserField{"locale": {Type: auth.FieldString, Required: true}},
				Session: map[string]auth.SessionField{"sequence": {Type: auth.FieldNumber, Default: func() int32 { return defaults.Add(1) }}},
			}
			store, err := OpenWithAdditionalFields(ctx, dialect, organizationTestDSN(t, dialect), nil, fields)
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			provider := newProfileIssuer(t).provider()
			provider.RequireEmailVerification = true
			provider.VerifyIDToken = func(_ context.Context, raw, nonce string) (auth.OAuthProfile, time.Time, error) {
				label, signedNonce, _ := strings.Cut(raw, "/")
				subject, assertion, _ := strings.Cut(label, ":")
				if nonce == "" || signedNonce != nonce {
					return auth.OAuthProfile{}, time.Time{}, errors.New("invalid fixture credential")
				}
				p := auth.OAuthProfile{Subject: subject, Name: "Owner", Email: subject + "@issuer.test", EmailVerified: strings.HasPrefix(assertion, "verified"), AdditionalFields: map[string]any{"locale": "es"}}
				if strings.HasSuffix(assertion, "-changed") {
					p.Email = "changed-" + p.Email
				}
				return p, time.Now().Add(time.Minute), nil
			}
			synced := provider
			synced.OverrideUserInfoOnSignIn = true
			ungated := provider
			ungated.RequireEmailVerification = false
			app := httptest.NewUnstartedServer(nil)
			base := "http://" + app.Listener.Addr().String()
			off := false
			mail := make(chan auth.MailLink, 8)
			api, err := auth.New(auth.Options{BaseURL: base, Store: store, Secret: strings.Repeat("s", 40), RateLimit: &off,
				RequireEmailVerification: true, SendVerificationOnSignIn: true,
				UserAdditionalFields: fields.User, SessionAdditionalFields: fields.Session,
				SocialProviders: map[string]auth.OAuthProvider{"google": provider, "synced": synced, "ungated": ungated},
				Plugins:         []auth.Plugin{auth.NewOneTap(auth.OneTapOptions{}, auth.OAuthProvider{})},
				SendVerificationEmail: func(ctx context.Context, msg auth.MailLink) error {
					owner, err := store.FindAccountUser(ctx, msg.User.Email)
					if err != nil || owner.ID != msg.User.ID || owner.EmailVerified {
						t.Errorf("delivery did not observe the committed owner: %v", err)
					}
					mail <- msg
					return nil
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			app.Config.Handler = api
			app.Start()
			defer app.Close()
			c, err := client.New(base, nil)
			if err != nil {
				t.Fatal(err)
			}
			grant := func(providerID, identity, nonce string) (*client.SocialSignInResult, error) {
				return c.SignInSocial(ctx, client.SocialSignInRequest{Provider: providerID, CallbackURL: "/welcome?mail=1", IDToken: &client.SocialIDToken{Token: identity + "/" + nonce, Nonce: nonce}})
			}
			checkBlocked := func(err error) {
				t.Helper()
				var api *auth.APIError
				if !errors.As(err, &api) || api.Status != 403 || api.Code != "EMAIL_NOT_VERIFIED" {
					t.Fatalf("expected mailbox verification, got %v", err)
				}
			}
			readMail := func(owner, callback string) auth.MailLink {
				t.Helper()
				select {
				case msg := <-mail:
					u, err := url.Parse(msg.URL)
					if err != nil || msg.User.Email != owner || u.Query().Get("callbackURL") != callback || u.Query().Get("token") != msg.Token {
						t.Fatal("verification delivery has the wrong owner or callback", err)
					}
					return msg
				default:
					t.Fatal("missing verification delivery")
					return auth.MailLink{}
				}
			}
			_, err = grant("google", "one:unverified", "first")
			checkBlocked(err)
			initial := readMail("one@issuer.test", "/welcome?mail=1")
			if session, err := c.GetSession(ctx); err != nil || session != nil {
				t.Fatal("unverified browser acquired a session", err)
			}
			var identities, sessions int
			if err := store.db.QueryRowContext(ctx, store.bind(`SELECT (SELECT count(*) FROM "account" WHERE "userId"=?),(SELECT count(*) FROM "session" WHERE "userId"=?)`), initial.User.ID, initial.User.ID).Scan(&identities, &sessions); err != nil || identities != 1 || sessions != 0 || defaults.Load() != 0 {
				t.Fatal("unverified identity and session counts", identities, sessions, defaults.Load(), err)
			}

			_, err = grant("google", "one:unverified", "first")
			checkUserFieldError(t, err, "INVALID_TOKEN")
			// An unrelated verified address cannot verify the owner's local mailbox.
			_, err = grant("google", "one:verified-changed", "second")
			checkBlocked(err)
			readMail(initial.User.Email, "/welcome?mail=1")

			var nonce struct{ Nonce string }
			if err := c.Do(ctx, "POST", "/one-tap/nonce", struct{}{}, &nonce); err != nil {
				t.Fatal(err)
			}
			oneTap := map[string]string{"idToken": "one:unverified/" + nonce.Nonce}
			checkBlocked(c.Do(ctx, "POST", "/one-tap/callback", oneTap, nil))
			readMail(initial.User.Email, "/")
			checkUserFieldError(t, c.Do(ctx, "POST", "/one-tap/callback", oneTap, nil), "INVALID_TOKEN")
			if err := c.VerifyEmail(ctx, initial.Token); err != nil {
				t.Fatal(err)
			}
			result, err := grant("google", "one:unverified", "after-mail")
			if err != nil || result.User == nil || !result.User.EmailVerified || result.User.ID != initial.User.ID || defaults.Load() != 1 {
				t.Fatal("confirmed local mailbox did not admit the original subject", err)
			}
			checkUserField(t, *result.User, "locale", "es")
			_, err = grant("google", "two:unverified", "start")
			checkBlocked(err)
			second := readMail("two@issuer.test", "/welcome?mail=1")
			result, err = grant("google", "two:verified", "later")
			if err != nil || result.User.ID != second.User.ID || !result.User.EmailVerified {
				t.Fatal("authenticated proof for the same mailbox did not satisfy the gate", err)
			}

			result, err = grant("synced", "three:verified", "start")
			if err != nil || !result.User.EmailVerified {
				t.Fatal("verified signup was withheld", err)
			}
			_, err = grant("synced", "three:unverified-changed", "later")
			checkBlocked(err)
			current := readMail("changed-three@issuer.test", "/welcome?mail=1")
			if current.User.ID != result.User.ID || defaults.Load() != 3 {
				t.Fatal("profile refresh issued a new session for an unverified address")
			}
			result, err = grant("ungated", "four:unverified", "start")
			if err != nil || result.User.EmailVerified || result.Token == "" || defaults.Load() != 4 || len(mail) != 0 {
				t.Fatal("provider inherited the password gate or sent unexpected mail", err)
			}
		})
	}
}

func TestOAuthVerifiedEmailStoreContract(t *testing.T) {
	db := openTestStore(t, ":memory:")
	provider := newProfileIssuer(t).provider()
	provider.RequireEmailVerification = true
	provider.DisableSignUp = true
	opts := auth.Options{Store: legacySocialProfileStore{Store: db, OAuthStore: db}, BaseURL: "http://app.localhost", Secret: strings.Repeat("s", 40), SocialProviders: map[string]auth.OAuthProvider{"work": provider}}
	if _, err := auth.New(opts); err == nil || !strings.Contains(err.Error(), "OAuthVerifiedEmailStore") {
		t.Fatal("sign-in-only provider accepted a store without atomic verification", err)
	}
}
