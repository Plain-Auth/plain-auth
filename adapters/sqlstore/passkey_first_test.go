package sqlstore

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	auth "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/client"
	pk "github.com/Plain-Org/plain-auth/plugins/passkey"
	"github.com/Plain-Org/plain-auth/schema"
)

func TestPasskeyFirstRegistrationAcrossEngines(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			ctx := t.Context()
			must := func(err error) {
				t.Helper()
				if err != nil {
					t.Fatal(err)
				}
			}
			ddl, err := schema.Generate(dialect, []string{"passkey"})
			must(err)
			dsn := organizationTestDSN(t, dialect)
			store, err := OpenWithSchema(ctx, dialect, dsn, ddl)
			must(err)
			defer store.Close()
			const rp = "localhost"
			srv := httptest.NewUnstartedServer(nil)
			origin := "http://" + strings.Replace(srv.Listener.Addr().String(), "127.0.0.1", "localhost", 1)
			var calls atomic.Int32
			plugin, err := pk.New(pk.Options{RPID: rp, RPName: "Local", Origins: []string{origin}, RequireUserVerification: true, Registration: pk.RegistrationOptions{
				AllowWithoutSession: true,
				ResolveUser: func(_ auth.EndpointContext, v *string) (pk.RegistrationUser, error) {
					if v == nil || !strings.HasPrefix(*v, "fixture-") {
						return pk.RegistrationUser{}, errors.New("unknown fixture enrollment")
					}
					return pk.RegistrationUser{ID: "pending", Name: "registration", DisplayName: "New owner"}, nil
				},
				AfterVerification: func(_ auth.EndpointContext, proof pk.VerifiedRegistration) (pk.RegistrationDecision, error) {
					calls.Add(1)
					if proof.Context == nil {
						return pk.RegistrationDecision{}, nil
					}
					if *proof.Context == "fixture-redirect" {
						return pk.RegistrationDecision{UserID: "quiet"}, nil
					}
					if *proof.Context == "fixture-existing" || *proof.Context == "fixture-unapproved" {
						return pk.RegistrationDecision{UserID: "first", AllowExistingAccount: *proof.Context == "fixture-existing"}, nil
					}
					if proof.User.ID != "pending" || proof.User.DisplayName != "New owner" || len(proof.Credential.ID) == 0 || len(proof.Response) == 0 {
						return pk.RegistrationDecision{}, errors.New("missing verified enrollment context")
					}
					target := strings.TrimPrefix(*proof.Context, "fixture-")
					return pk.RegistrationDecision{UserID: target, Name: "Device label", NewAccount: &pk.RegistrationAccount{Name: "New owner", Email: target + "@passkey.test"}}, nil
				},
			}})
			must(err)
			off := false
			a, err := auth.New(auth.Options{BaseURL: origin, Secret: strings.Repeat("k", 48), Store: store, Plugins: []auth.Plugin{plugin}, EmailAndPassword: true, RateLimit: &off,
				ValidateUserInfo: func(_ context.Context, v auth.UserInfoValidation) error {
					if v.Method == "passkey" && v.User.Email == "blocked@passkey.test" {
						return &auth.APIError{Code: "passkey_blocked", Message: "Not allowed"}
					}
					return nil
				}})
			must(err)
			srv.Config.Handler = a
			srv.Start()
			defer srv.Close()
			browser := func() *client.Client { c, err := client.New(origin, nil); must(err); return c }
			begin := func(c *client.Client, key *softwareKey, id string) json.RawMessage {
				t.Helper()
				intent := "fixture-" + id
				creation, err := c.BeginPasskeyRegistration(ctx, client.PasskeyRegistrationRequest{Context: &intent, Name: "User label"})
				must(err)
				if creation.User.Name != "User label" || creation.User.DisplayName != "New owner" {
					t.Fatal("WebAuthn registration user labels were lost")
				}
				key.handle = creation.User.ID.(string)
				raw, err := json.Marshal(key.response(t, base64.RawURLEncoding.EncodeToString(creation.Challenge), origin, rp, 0, true))
				must(err)
				return raw
			}
			c := browser()
			key := newSoftwareKey(t)
			raw := begin(c, key, "first")
			result, err := c.FinishPasskeyRegistration(ctx, raw, "", true)
			must(err)
			if result.User == nil || result.User.ID != "first" || result.Session == nil || result.UserID != result.User.ID || result.Name == nil || *result.Name != "Device label" {
				t.Fatal("passkey-first registration did not atomically return its resolved account, credential and session")
			}
			session, err := c.GetSession(ctx)
			must(err)
			if session == nil || session.Session.ID != result.Session.ID {
				t.Fatal("registration cookie does not authenticate")
			}
			_, err = c.FinishPasskeyRegistration(ctx, raw, "", true)
			phoneError(t, err, 400, "CHALLENGE_NOT_FOUND")
			must(c.SignOut(ctx))
			login, err := c.BeginPasskeyLogin(ctx)
			must(err)
			assertion, err := json.Marshal(key.response(t, base64.RawURLEncoding.EncodeToString(login.Challenge), origin, rp, 1, false))
			must(err)
			signed, err := c.FinishPasskeyLogin(ctx, assertion)
			must(err)
			if signed.User.ID != "first" {
				t.Fatal("credential lost its opaque handle after the final account ID changed")
			}
			fresh := browser()
			quietKey := newSoftwareKey(t)
			quiet, err := fresh.FinishPasskeyRegistration(ctx, begin(fresh, quietKey, "quiet"), "Client label", false)
			must(err)
			current, err := fresh.GetSession(ctx)
			must(err)
			if current != nil || quiet.Session != nil || quiet.User != nil || quiet.Name == nil || *quiet.Name != "Client label" {
				t.Fatal("credential-only registration issued a session or replaced a client label")
			}
			// ValidateUserInfo refuses a new passkey account with the app's code.
			gated := browser()
			_, err = gated.FinishPasskeyRegistration(ctx, begin(gated, newSoftwareKey(t), "blocked"), "", true)
			phoneError(t, err, 403, "passkey_blocked")
			if _, err := store.FindAccountUser(ctx, "blocked@passkey.test"); err == nil {
				t.Fatal("a refused passkey account was stored")
			}
			// Knowing a public account identifier or providing it in a form cannot enroll an existing account.
			stranger := browser()
			candidate := newSoftwareKey(t)
			unauthorized := begin(stranger, candidate, "unapproved")
			_, err = stranger.FinishPasskeyRegistration(ctx, unauthorized, "", true)
			phoneError(t, err, 401, "YOU_ARE_NOT_ALLOWED_TO_REGISTER_THIS_PASSKEY")
			approved := begin(stranger, candidate, "existing")
			restored, err := stranger.FinishPasskeyRegistration(ctx, approved, "", true)
			must(err)
			if restored.User.ID != "first" {
				t.Fatal("explicit existing-account enrollment returned the wrong owner")
			}
			// A trusted callback may never redirect an existing signed-in source to another user.
			redirect := "fixture-redirect"
			signedOptions, err := stranger.BeginPasskeyRegistration(ctx, client.PasskeyRegistrationRequest{Context: &redirect})
			must(err)
			attempt, err := json.Marshal(newSoftwareKey(t).response(t, base64.RawURLEncoding.EncodeToString(signedOptions.Challenge), origin, rp, 0, true))
			must(err)
			_, err = stranger.FinishPasskeyRegistration(ctx, attempt, "", false)
			phoneError(t, err, 401, "YOU_ARE_NOT_ALLOWED_TO_REGISTER_THIS_PASSKEY")

			// Signed-in enrollments stay bound to that login exactly, even when resolver-backed enrollment is enabled.
			options, err := c.BeginPasskeyRegistration(ctx, client.PasskeyRegistrationRequest{})
			must(err)
			must(c.SignOut(ctx))
			another := newSoftwareKey(t)
			raw, err = json.Marshal(another.response(t, base64.RawURLEncoding.EncodeToString(options.Challenge), origin, rp, 0, true))
			must(err)
			_, err = c.FinishPasskeyRegistration(ctx, raw, "", true)
			phoneError(t, err, 401, "SESSION_REQUIRED")
			before := calls.Load()
			begin(fresh, another, "invalid")
			_, err = fresh.FinishPasskeyRegistration(ctx, json.RawMessage(`{"id":"bad"}`), "", true)
			phoneError(t, err, 400, "FAILED_TO_VERIFY_REGISTRATION")
			if calls.Load() != before {
				t.Fatal("unverified response reached account provisioning")
			}
			duplicate := browser()
			raw = begin(duplicate, key, "orphan")
			_, err = duplicate.FinishPasskeyRegistration(ctx, raw, "", true)
			phoneError(t, err, 400, "PREVIOUSLY_REGISTERED")
			if _, err = store.FindAccountUser(ctx, "orphan@passkey.test"); !errors.Is(err, auth.ErrNotFound) {
				t.Fatal("duplicate credential committed an orphan account", err)
			}
			both := newSoftwareKey(t)
			left, right := browser(), browser()
			x, y := begin(left, both, "left"), begin(right, both, "right")
			start := make(chan struct{})
			results := make(chan error, 2)
			finish := func(c *client.Client, raw json.RawMessage) {
				<-start
				_, err := c.FinishPasskeyRegistration(ctx, raw, "", true)
				results <- err
			}
			go finish(left, x)
			go finish(right, y)
			close(start)
			wins := 0
			for range 2 {
				if e := <-results; e == nil {
					wins++
				} else {
					phoneError(t, e, 400, "PREVIOUSLY_REGISTERED")
				}
			}
			if wins != 1 {
				t.Fatal("simultaneous trusted registrations reused the same credential")
			}
			var n int
			must(store.db.QueryRowContext(ctx, store.bind(`SELECT count(*) FROM "user" WHERE "id" IN (?,?)`), "left", "right").Scan(&n))
			if n != 1 {
				t.Fatal("concurrent enrollment committed an orphan user")
			}
			disabledSrv := httptest.NewUnstartedServer(nil)
			// Only the HTTP transport changes; the authenticator is still serving the original trusted origin.
			disabledBase := "http://" + strings.Replace(disabledSrv.Listener.Addr().String(), "127.0.0.1", "localhost", 1)
			disabled, err := auth.New(auth.Options{BaseURL: disabledBase, Secret: strings.Repeat("s", 48), Store: store, DisableSignUp: true, Plugins: []auth.Plugin{plugin}, RateLimit: &off})
			must(err)
			disabledSrv.Config.Handler = disabled
			disabledSrv.Start()
			defer disabledSrv.Close()
			blocked, err := client.New(disabledBase, nil)
			must(err)
			_, err = blocked.FinishPasskeyRegistration(ctx, begin(blocked, newSoftwareKey(t), "disabled"), "", true)
			phoneError(t, err, 403, "SIGN_UP_DISABLED")
			if _, err = store.FindAccountUser(ctx, "disabled@passkey.test"); !errors.Is(err, auth.ErrNotFound) {
				t.Fatal("disabled signup created an account")
			}

		})
	}
}
