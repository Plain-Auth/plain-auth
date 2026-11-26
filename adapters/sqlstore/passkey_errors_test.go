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

// passkeyError fails unless err is the API error with this status, code
// and message.
func passkeyError(t *testing.T, err error, status int, code, message string) {
	t.Helper()
	var p *auth.APIError
	if !errors.As(err, &p) || p.Status != status || p.Code != code || p.Message != message {
		t.Fatalf("expected %d %s %q, got %v", status, code, message, err)
	}
}

// The passkey endpoints answer each server error with its status, code and
// message.
func TestPasskeyErrorCodesAcrossEngines(t *testing.T) {
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
			store, err := OpenWithSchema(ctx, dialect, organizationTestDSN(t, dialect), ddl)
			must(err)
			defer store.Close()
			const rp = "localhost"
			serve := func(o pk.Options, hooks auth.DatabaseHooks) (string, func()) {
				t.Helper()
				srv := httptest.NewUnstartedServer(nil)
				origin := "http://" + strings.Replace(srv.Listener.Addr().String(), "127.0.0.1", "localhost", 1)
				o.RPID, o.RPName, o.Origins = rp, "Local", []string{origin}
				plugin, err := pk.New(o)
				must(err)
				off := false
				a, err := auth.New(auth.Options{BaseURL: origin, Secret: strings.Repeat("e", 48), Store: store, Plugins: []auth.Plugin{plugin}, EmailAndPassword: true, RateLimit: &off, DatabaseHooks: hooks})
				must(err)
				srv.Config.Handler = a
				srv.Start()
				return origin, srv.Close
			}
			var skip atomic.Bool
			origin, stop := serve(pk.Options{Registration: pk.RegistrationOptions{
				AllowWithoutSession: true,
				ResolveUser: func(_ auth.EndpointContext, v *string) (pk.RegistrationUser, error) {
					switch {
					case v == nil:
						return pk.RegistrationUser{}, &auth.APIError{Status: 403, Code: "ENROLLMENT_REQUIRED", Message: "Enrollment required"}
					case *v == "no-id":
						return pk.RegistrationUser{Name: "nameless@passkey.test"}, nil
					case *v == "no-name":
						return pk.RegistrationUser{ID: "pending"}, nil
					}
					return pk.RegistrationUser{ID: "pending", Name: *v + "@passkey.test"}, nil
				},
				AfterVerification: func(_ auth.EndpointContext, proof pk.VerifiedRegistration) (pk.RegistrationDecision, error) {
					switch {
					case proof.Context == nil:
						return pk.RegistrationDecision{}, nil
					case *proof.Context == "ghost":
						return pk.RegistrationDecision{UserID: "ghost", AllowExistingAccount: true}, nil
					case *proof.Context == "unapproved":
						return pk.RegistrationDecision{UserID: "owner"}, nil
					case *proof.Context == "again":
						return pk.RegistrationDecision{UserID: "owner", AllowExistingAccount: true}, nil
					}
					return pk.RegistrationDecision{UserID: *proof.Context, NewAccount: &pk.RegistrationAccount{Name: "New owner", Email: *proof.Context + "@passkey.test"}}, nil
				},
			}}, auth.DatabaseHooks{Session: auth.ModelHooks[auth.SessionRecord]{Create: auth.OperationHooks[auth.SessionRecord]{
				Before: func(context.Context, *auth.SessionRecord, *auth.HookContext) error {
					if skip.Load() {
						return auth.ErrSkipWrite
					}
					return nil
				},
			}}})
			defer stop()
			browser := func(origin string) *client.Client { c, err := client.New(origin, nil); must(err); return c }
			count := func(query string, args ...any) int {
				t.Helper()
				var n int
				must(store.db.QueryRowContext(ctx, store.bind(query), args...).Scan(&n))
				return n
			}
			challenges := func() int { return count(`SELECT COUNT(*) FROM "verification" WHERE "identifier" LIKE 'passkey:%'`) }
			rows := func(userID string) int { return count(`SELECT COUNT(*) FROM "passkey" WHERE "userId"=?`, userID) }
			attest := func(c *client.Client, key *softwareKey, context *string) json.RawMessage {
				t.Helper()
				creation, err := c.BeginPasskeyRegistration(ctx, client.PasskeyRegistrationRequest{Context: context})
				must(err)
				key.handle = creation.User.ID.(string)
				raw, err := json.Marshal(key.response(t, base64.RawURLEncoding.EncodeToString(creation.Challenge), origin, rp, 0, true))
				must(err)
				return raw
			}
			named := func(s string) *string { return &s }

			c := browser(origin)
			before := challenges()
			_, err = c.BeginPasskeyRegistration(ctx, client.PasskeyRegistrationRequest{})
			phoneError(t, err, 403, "ENROLLMENT_REQUIRED")
			for _, v := range []string{"no-id", "no-name"} {
				_, err = c.BeginPasskeyRegistration(ctx, client.PasskeyRegistrationRequest{Context: named(v)})
				passkeyError(t, err, 400, "RESOLVED_USER_INVALID", "Resolved user is invalid")
			}
			if challenges() != before {
				t.Fatal("a refused resolver stored a challenge")
			}
			for _, session := range []bool{true, false} {
				_, err = c.FinishPasskeyRegistration(ctx, attest(c, newSoftwareKey(t), named("ghost")), "", session)
				passkeyError(t, err, 500, "USER_NOT_FOUND", "User not found")
			}
			if rows("ghost") != 0 {
				t.Fatal("a registration for a missing account stored a passkey")
			}
			skip.Store(true)
			_, err = c.FinishPasskeyRegistration(ctx, attest(c, newSoftwareKey(t), named("skipped")), "", true)
			passkeyError(t, err, 500, "UNABLE_TO_CREATE_SESSION", "Unable to create session")
			if _, err := store.FindAccountUser(ctx, "skipped@passkey.test"); !errors.Is(err, auth.ErrNotFound) || rows("skipped") != 0 {
				t.Fatal("a registration whose session was skipped stored its account or passkey", err)
			}
			skip.Store(false)

			key := newSoftwareKey(t)
			raw := attest(c, key, named("owner"))
			enrolled, err := c.FinishPasskeyRegistration(ctx, raw, "", true)
			must(err)
			_, err = c.FinishPasskeyRegistration(ctx, raw, "", true)
			passkeyError(t, err, 400, "CHALLENGE_NOT_FOUND", "Challenge not found")
			if _, err := c.BeginPasskeyRegistration(ctx, client.PasskeyRegistrationRequest{}); err != nil {
				t.Fatal("the resolver ran for a signed-in registration", err)
			}
			signedIn := attest(c, newSoftwareKey(t), nil)
			must(c.SignOut(ctx))
			_, err = c.FinishPasskeyRegistration(ctx, signedIn, "", false)
			passkeyError(t, err, 401, "SESSION_REQUIRED", "Passkey registration requires an authenticated session")
			bad, err := json.Marshal(map[string]any{"id": "bad"})
			must(err)
			_, err = c.BeginPasskeyRegistration(ctx, client.PasskeyRegistrationRequest{Context: named("bad")})
			must(err)
			_, err = c.FinishPasskeyRegistration(ctx, bad, "", false)
			passkeyError(t, err, 400, "FAILED_TO_VERIFY_REGISTRATION", "Failed to verify registration")
			copied := *key
			_, err = c.FinishPasskeyRegistration(ctx, attest(c, &copied, named("again")), "", false)
			passkeyError(t, err, 400, "PREVIOUSLY_REGISTERED", "Previously registered")
			_, err = c.FinishPasskeyRegistration(ctx, attest(c, newSoftwareKey(t), named("unapproved")), "", false)
			passkeyError(t, err, 401, "YOU_ARE_NOT_ALLOWED_TO_REGISTER_THIS_PASSKEY", "You are not allowed to register this passkey")

			login := func(k *softwareKey, reported string, n uint32) (*auth.SessionResult, error) {
				t.Helper()
				options, err := c.BeginPasskeyLogin(ctx)
				must(err)
				assertion, err := json.Marshal(k.response(t, base64.RawURLEncoding.EncodeToString(options.Challenge), reported, rp, n, false))
				must(err)
				return c.FinishPasskeyLogin(ctx, assertion)
			}
			skip.Store(true)
			_, err = login(key, origin, 1)
			passkeyError(t, err, 500, "UNABLE_TO_CREATE_SESSION", "Unable to create session")
			skip.Store(false)
			if s, err := c.GetSession(ctx); err != nil || s != nil {
				t.Fatal("a skipped passkey session signed the browser in", err)
			}
			_, err = login(key, "https://elsewhere.test", 1)
			passkeyError(t, err, 400, "AUTHENTICATION_FAILED", "Authentication failed")
			impostor := newSoftwareKey(t)
			impostor.id, impostor.handle = key.id, key.handle
			_, err = login(impostor, origin, 1)
			passkeyError(t, err, 401, "AUTHENTICATION_FAILED", "Authentication failed")
			_, err = login(newSoftwareKey(t), origin, 1)
			passkeyError(t, err, 401, "PASSKEY_NOT_FOUND", "Passkey not found")
			// The counter and the session commit together, so the skipped
			// sign-in left the counter where it was.
			if _, err := login(key, origin, 1); err != nil {
				t.Fatal("the counter a skipped sign-in carried was not accepted later", err)
			}

			signedOut := browser(origin)
			for _, path := range []string{"/passkey/update-passkey", "/passkey/delete-passkey"} {
				passkeyError(t, signedOut.Do(ctx, "POST", path, map[string]any{"id": enrolled.ID, "name": "Renamed"}, nil), 401, "UNAUTHORIZED", "Unauthorized")
			}
			passkeyError(t, signedOut.Do(ctx, "GET", "/passkey/list-user-passkeys", nil, nil), 401, "UNAUTHORIZED", "Unauthorized")
			other := browser(origin)
			_, err = other.SignUpEmail(ctx, client.SignUpRequest{Name: "Other", Email: "other@passkey.test", Password: "passkey-errors-password"})
			must(err)
			for _, path := range []string{"/passkey/update-passkey", "/passkey/delete-passkey"} {
				for _, attempt := range []struct {
					c  *client.Client
					id string
				}{{c, "unknown"}, {other, enrolled.ID}} {
					passkeyError(t, attempt.c.Do(ctx, "POST", path, map[string]any{"id": attempt.id, "name": "Renamed"}, nil), 404, "PASSKEY_NOT_FOUND", "Passkey not found")
				}
			}
			if rows("owner") != 1 {
				t.Fatal("a refused update or delete changed the owner's passkey")
			}

			plain, stopPlain := serve(pk.Options{Registration: pk.RegistrationOptions{AllowWithoutSession: true}}, auth.DatabaseHooks{})
			defer stopPlain()
			fresh := browser(plain)
			_, err = fresh.BeginPasskeyRegistration(ctx, client.PasskeyRegistrationRequest{})
			passkeyError(t, err, 400, "RESOLVE_USER_REQUIRED", "Passkey registration requires either an authenticated session or a resolveUser callback when requireSession is false")
			_, err = fresh.SignUpEmail(ctx, client.SignUpRequest{Name: "Plain", Email: "plain@passkey.test", Password: "passkey-errors-password"})
			must(err)
			if _, err := fresh.BeginPasskeyRegistration(ctx, client.PasskeyRegistrationRequest{}); err != nil {
				t.Fatal("a signed-in registration needed a resolver", err)
			}
		})
	}
}
