package sqlstore

import (
	"context"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	auth "github.com/Plain-Auth/plain-auth"
	"github.com/Plain-Auth/plain-auth/client"
	"github.com/Plain-Auth/plain-auth/schema"
)

func TestOAuthProfileSync(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			ctx := t.Context()
			fields := userFieldFixture()
			store, err := OpenWithAdditionalFields(ctx, dialect, organizationTestDSN(t, dialect), nil, schema.AdditionalFields{User: fields})
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			image := "https://images.example.test/original"
			first := auth.OAuthProfile{Subject: "one", Email: "a@issuer.test", EmailVerified: true, Name: "First", Image: &image, AdditionalFields: map[string]any{"locale": "fr", "activeFlag": true}}
			profiles := map[string]auth.OAuthProfile{
				"register":  first,
				"explicit":  {Subject: "one", Email: first.Email, EmailVerified: true, Name: "Explicit link"},
				"return":    {Subject: "one", Email: "A@ISSUER.TEST", Name: "Returning", AdditionalFields: map[string]any{"score": 0, "activeFlag": nil, "accountClass": "other", "role": "admin", "secretNote": "mapped"}},
				"move":      {Subject: "one", Email: "Moved@issuer.test"},
				"verify":    {Subject: "one", Email: "moved@issuer.test", EmailVerified: true, Name: "Verified"},
				"two":       {Subject: "two", Email: "b@issuer.test", Name: "Other", EmailVerified: true, AdditionalFields: map[string]any{"locale": "de"}},
				"collision": {Subject: "one", Email: "B@ISSUER.TEST", EmailVerified: true, Name: "Wrong owner"},
				"invalid":   {Subject: "one", Email: "fail@issuer.test", Name: "Invalid", AdditionalFields: map[string]any{"score": "not a number"}},
				"untrusted": {Subject: "three", Email: "moved@issuer.test", Name: "Unverified link"},
				"implicit":  {Subject: "three", Email: "moved@issuer.test", EmailVerified: true, Name: "Implicit link", AdditionalFields: map[string]any{"score": 2}},
			}
			provider := newProfileIssuer(t).provider()
			provider.DisableImplicitSignUp = true
			provider.OverrideUserInfoOnSignIn = true
			provider.VerifyIDToken = func(_ context.Context, raw, nonce string) (auth.OAuthProfile, time.Time, error) {
				key, boundNonce, _ := strings.Cut(raw, "/")
				p, ok := profiles[key]
				if !ok || boundNonce != nonce || nonce == "" {
					return auth.OAuthProfile{}, time.Time{}, errors.New("invalid fixture credential")
				}
				return p, time.Now().Add(time.Hour), nil
			}
			app := httptest.NewUnstartedServer(nil)
			base := "http://" + app.Listener.Addr().String()
			off := false
			api, err := auth.New(auth.Options{BaseURL: base, Secret: strings.Repeat("s", 40), Store: store, RateLimit: &off,
				SocialProviders: map[string]auth.OAuthProvider{"google": provider}, UserAdditionalFields: fields, Plugins: []auth.Plugin{auth.NewOneTap(auth.OneTapOptions{}, auth.OAuthProvider{})}})
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
			grant := func(key string) client.SocialSignInRequest {
				return client.SocialSignInRequest{Provider: "google", IDToken: &client.SocialIDToken{Token: key + "/mobile", Nonce: "mobile"}, RequestSignUp: key == "register" || key == "two"}
			}
			signIn := func(key string) auth.User {
				t.Helper()
				result, err := c.SignInSocial(ctx, grant(key))
				if err != nil || result.User == nil || result.Token == "" {
					t.Fatalf("%s sign-in: %v", key, err)
				}
				return *result.User
			}
			owner := signIn("register")
			if _, err := c.LinkSocial(ctx, grant("explicit")); err != nil {
				t.Fatal(err)
			}
			original, err := store.FindAccountUser(ctx, first.Email)
			if err != nil || original.Name != first.Name || original.ID != owner.ID {
				t.Fatal("explicit linking changed the owner's profile", err)
			}
			returned := signIn("return")
			if returned.ID != owner.ID || returned.Email != first.Email || !returned.EmailVerified || returned.Name != "Returning" || returned.Image == nil || *returned.Image != image || !returned.CreatedAt.Equal(owner.CreatedAt) {
				t.Fatal("returning grant did not update its original owner")
			}
			checkUserField(t, returned, "locale", "fr")
			checkUserField(t, returned, "accountClass", "basic")
			checkUserField(t, returned, "score", int64(0))
			checkUserField(t, returned, "activeFlag", nil)
			if _, ok := returned.AdditionalField("secretNote"); ok {
				t.Fatal("hidden field disclosed")
			}
			moved := signIn("move")
			if moved.ID != owner.ID || moved.Email != "moved@issuer.test" || moved.EmailVerified || moved.Name != returned.Name {
				t.Fatal("changed address inherited verification or lost its display name")
			}
			if _, err := store.FindAccountUser(ctx, first.Email); !errors.Is(err, auth.ErrNotFound) {
				t.Fatal("old address still resolves", err)
			}
			var challenge struct{ Nonce string }
			if err := c.Do(ctx, "POST", "/one-tap/nonce", struct{}{}, &challenge); err != nil {
				t.Fatal(err)
			}
			var tapped client.SocialSignInResult
			if err := c.Do(ctx, "POST", "/one-tap/callback", map[string]string{"idToken": "verify/" + challenge.Nonce}, &tapped); err != nil || tapped.User == nil || tapped.User.Name != "Verified" || !tapped.User.EmailVerified || tapped.User.ID != owner.ID {
				t.Fatal("One Tap profile update", err)
			}
			other := signIn("two")
			for _, rejected := range []struct{ grant, code string }{{"collision", "OAUTH_PROFILE_CONFLICT"}, {"invalid", "VALIDATION_ERROR"}, {"untrusted", "ACCOUNT_NOT_LINKED"}} {
				_, err := c.SignInSocial(ctx, grant(rejected.grant))
				checkUserFieldError(t, err, rejected.code)
			}
			persisted, err := store.FindAccountUser(ctx, moved.Email)
			if err != nil || persisted.Name != "Verified" || persisted.ID != owner.ID || !persisted.EmailVerified {
				t.Fatal("failed sign-in modified the owner", err)
			}
			persisted, err = store.FindAccountUser(ctx, other.Email)
			if err != nil || persisted.Name != "Other" || persisted.ID != other.ID {
				t.Fatal("failed sign-in modified the other user", err)
			}
			var sessions, identities, claims int
			var credential, note string
			err = store.db.QueryRowContext(ctx, store.bind(`SELECT
				(SELECT count(*) FROM "session" WHERE "userId"=?),
				(SELECT count(*) FROM "account" WHERE "userId"=?),
				(SELECT count(*) FROM "verification" WHERE "identifier"='consumed-id-token'),
				(SELECT "idToken" FROM "account" WHERE "userId"=?),
				(SELECT "secretNote" FROM "user" WHERE "id"=?)`), owner.ID, owner.ID, owner.ID, owner.ID).Scan(&sessions, &identities, &claims, &credential, &note)
			// The One Tap grant consumes both a token and a browser nonce.
			if err != nil || sessions != 4 || identities != 1 || claims != 7 || credential != "verify/"+challenge.Nonce || note != "mapped" {
				t.Fatalf("atomic profile and credential writes: sessions=%d identities=%d claims=%d note=%q err=%v", sessions, identities, claims, note, err)
			}
			linked := signIn("implicit")
			if linked.ID != owner.ID || linked.Name != "Implicit link" || !linked.EmailVerified {
				t.Fatal("verified email link selected a different owner")
			}
			checkUserField(t, linked, "score", int64(2))
		})
	}
}

func TestOAuthProfileSyncRequiresAtomicStore(t *testing.T) {
	store := openTestStore(t, ":memory:")
	provider := newProfileIssuer(t).provider()
	provider.DisableSignUp = true
	provider.OverrideUserInfoOnSignIn = true
	opts := auth.Options{BaseURL: "http://app.localhost", Secret: strings.Repeat("s", 40), Store: legacySocialProfileStore{Store: store, OAuthStore: store},
		SocialProviders: map[string]auth.OAuthProvider{"work": provider}}
	if _, err := auth.New(opts); err == nil || !strings.Contains(err.Error(), "OAuthProfileSyncStore") {
		t.Fatal("store silently ignored profile updates on a sign-in-only deployment", err)
	}
}

func TestOAuthConcurrentProfileEmailChange(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			ctx := t.Context()
			dsn := organizationTestDSN(t, dialect)
			const destination = "shared@issuer.test"
			ready := make(chan struct{})
			type outcome struct {
				id  string
				err error
			}
			results := make(chan outcome, 2)
			stores := make([]*Store, 2)
			users := []auth.User{testUser("first"), testUser("second")}
			noFields := func() (auth.UserFieldValues, error) { return auth.UserFieldValues{}, nil }
			policy := auth.OAuthProfileFields{Create: noFields, Update: noFields}
			for i, user := range users {
				s, err := Open(ctx, dialect, dsn)
				if err != nil {
					t.Fatal(err)
				}
				stores[i] = s
				defer s.Close()
				_, _, err = s.CompleteOAuth(ctx, "work", user.ID, auth.OAuthTokens{AccessToken: "initial"}, user, testSession(user, user.ID), auth.OAuthLoginOptions{})
				if err != nil {
					t.Fatal(err)
				}
			}
			for i, user := range users {
				go func() {
					<-ready
					candidate := user
					candidate.Email, candidate.EmailVerified = destination, true
					_, _, err := stores[i].CompleteOAuthProfile(ctx, "work", user.ID, auth.OAuthTokens{AccessToken: "updated"}, candidate, testSession(user, "new-"+user.ID), auth.OAuthLoginOptions{}, policy)
					results <- outcome{user.ID, err}
				}()
			}
			close(ready)
			accepted, rejected := <-results, <-results
			if accepted.err != nil {
				accepted, rejected = rejected, accepted
			}
			if accepted.err != nil || !errors.Is(rejected.err, auth.ErrOAuthProfileConflict) {
				t.Fatalf("concurrent sign-in results: %v and %v", accepted.err, rejected.err)
			}
			winner, err := stores[0].FindAccountUser(ctx, destination)
			if err != nil || winner.ID != accepted.id || !winner.EmailVerified {
				t.Fatal("wrong mailbox owner", err)
			}
			for _, user := range users {
				wantToken, wantSessions := "updated", 2
				if user.ID == rejected.id {
					wantToken, wantSessions = "initial", 1
					saved, err := stores[0].FindAccountUser(ctx, user.Email)
					if err != nil || saved.ID != user.ID || saved.EmailVerified {
						t.Fatal("conflict modified the other account", err)
					}
				}
				var token string
				var sessions int
				err := stores[0].db.QueryRowContext(ctx, stores[0].bind(`SELECT "accessToken", (SELECT count(*) FROM "session" WHERE "userId"=?) FROM "account" WHERE "userId"=?`), user.ID, user.ID).Scan(&token, &sessions)
				if err != nil || token != wantToken || sessions != wantSessions {
					t.Fatal("credentials and sessions did not commit together", user.ID, sessions, err)
				}
			}
		})
	}
}
