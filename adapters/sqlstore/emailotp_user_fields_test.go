package sqlstore

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	auth "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/adapters/memory"
	"github.com/Plain-Org/plain-auth/client"
	"github.com/Plain-Org/plain-auth/plugins/emailotp"
	"github.com/Plain-Org/plain-auth/schema"
)

func emailOTPFieldPlugin(t *testing.T, closed bool) auth.Plugin {
	t.Helper()
	p, err := emailotp.New(emailotp.Options{DisableSignUp: closed, StoreOTP: "hashed", Send: func(context.Context, auth.EmailOTPMessage) error { return nil }})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestEmailOTPRegistrationUserFields(t *testing.T) {
	for _, dialect := range []string{"memory", "sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			ctx := t.Context()
			fields := userFieldFixture()
			// A profile column can be given this name, but the actual verification code
			// is an authentication credential and can never become registration metadata.
			fields["otp"] = auth.UserField{Type: auth.FieldString, Column: "application_otp"}
			var store, peer auth.Store
			if dialect == "memory" {
				store = memory.New()
				peer = store
			} else {
				dsn := organizationTestDSN(t, dialect)
				open := func() *Store {
					s, err := OpenWithAdditionalFields(ctx, dialect, dsn, nil, schema.AdditionalFields{User: fields})
					if err != nil {
						t.Fatal(err)
					}
					t.Cleanup(func() { s.Close() })
					return s
				}
				store = open()
				peer = open()
			}
			server := httptest.NewUnstartedServer(nil)
			off := false
			opts := auth.Options{Store: store, BaseURL: "http://" + server.Listener.Addr().String(), Secret: strings.Repeat("s", 40), UserAdditionalFields: fields, RateLimit: &off, Plugins: []auth.Plugin{emailOTPFieldPlugin(t, false)}}
			node, err := auth.New(opts)
			if err != nil {
				t.Fatal(err)
			}
			server.Config.Handler = node
			server.Start()
			defer server.Close()
			c, err := client.New(opts.BaseURL, &http.Client{})
			if err != nil {
				t.Fatal(err)
			}
			opts.Store = peer
			other, err := auth.New(opts)
			if err != nil {
				t.Fatal(err)
			}
			email := "mailbox@profile.test"
			code := func(address string) string {
				t.Helper()
				otp, err := node.CreateEmailOTP(ctx, address, auth.OTPSignIn)
				if err != nil {
					t.Fatal(err)
				}
				return otp
			}
			signin := func(otp string, m map[string]any) (*auth.AuthResult, error) {
				return c.SignInEmailOTP(ctx, auth.EmailOTPSignInInput{Email: email, OTP: otp, Name: "Registration", AdditionalFields: m})
			}

			first := code(email)
			_, err = signin("invalid", nil)
			checkUserFieldError(t, err, "INVALID_OTP")
			_, err = signin(first, nil)
			checkUserFieldError(t, err, "MISSING_FIELD")
			_, err = signin(first, map[string]any{"locale": "en"})
			checkUserFieldError(t, err, "INVALID_OTP")
			if _, err := store.(auth.AccountStore).FindAccountUser(ctx, email); !errors.Is(err, auth.ErrNotFound) {
				t.Fatal("invalid field registration created a user", err)
			}
			wrong := code(email)
			_, err = signin(wrong, map[string]any{"locale": "en", "score": json.Number("4.0000000000001")})
			checkUserFieldError(t, err, "VALIDATION_ERROR")
			_, err = signin(wrong, map[string]any{"locale": "en"})
			checkUserFieldError(t, err, "INVALID_OTP")
			issued := code(email)
			result, err := signin(issued, map[string]any{"locale": "fr", "score": 0, "activeFlag": false, "accountClass": "supplied", "secretNote": "mailbox-private"})
			if err != nil || result.Token == "" || !result.User.EmailVerified {
				t.Fatal(result, err)
			}
			checkUserField(t, result.User, "locale", "fr")
			checkUserField(t, result.User, "score", int64(0))
			checkUserField(t, result.User, "activeFlag", false)
			checkUserField(t, result.User, "accountClass", "basic")
			checkUserField(t, result.User, "otp", nil)
			if _, ok := result.User.AdditionalField("secretNote"); ok {
				t.Fatal("OTP registration returned hidden profile information")
			}
			if s, ok := store.(*Store); ok {
				var secret string
				var rank int
				var mistakenlyStored *string
				err := s.db.QueryRowContext(ctx, s.bind(`SELECT "secretNote","privateRank","application_otp" FROM "user" WHERE "id"=?`), result.User.ID).Scan(&secret, &rank, &mistakenlyStored)
				if err != nil || secret != "mailbox-private" || rank != 9 || mistakenlyStored != nil {
					t.Fatal("stored OTP signup profile", err)
				}
			}
			if err := other.UpdateTrustedUserFields(ctx, result.User.ID, map[string]any{"accountClass": "owner-class"}); err != nil {
				t.Fatal(err)
			}
			// Returning callers can omit every required field. Invalid attempted rewrites
			// of normal and host fields are ignored once the mailbox exists.
			for _, patch := range []map[string]any{nil, {"locale": false, "score": "wrong", "accountClass": "forged", "secretNote": "overwrite"}} {
				login, err := other.SignInEmailOTP(ctx, auth.EmailOTPSignInInput{Email: email, OTP: code(email), Name: "Overwritten", AdditionalFields: patch}, auth.RequestMeta{})
				if err != nil || login.User.ID != result.User.ID || login.User.Name != "Registration" {
					t.Fatal("existing account", err)
				}
				checkUserField(t, login.User, "locale", "fr")
				checkUserField(t, login.User, "accountClass", "owner-class")
			}
			session, err := c.GetSession(ctx)
			if err != nil || session == nil {
				t.Fatal(err)
			}
			checkUserField(t, session.User, "accountClass", "owner-class")
			if s, ok := store.(*Store); ok {
				var secret string
				if err := s.db.QueryRowContext(ctx, s.bind(`SELECT "secretNote" FROM "user" WHERE "id"=?`), result.User.ID).Scan(&secret); err != nil || secret != "mailbox-private" {
					t.Fatal("returning sign-in rewrote hidden field", err)
				}
			}

			opts.Plugins = []auth.Plugin{emailOTPFieldPlugin(t, true)}
			closed, err := auth.New(opts)
			if err != nil {
				t.Fatal(err)
			}
			fresh := "closed@profile.test"
			proof := code(fresh)
			_, err = closed.SignInEmailOTP(ctx, auth.EmailOTPSignInInput{Email: fresh, OTP: proof}, auth.RequestMeta{})
			checkUserFieldError(t, err, "INVALID_OTP")
			_, err = node.SignInEmailOTP(ctx, auth.EmailOTPSignInInput{Email: fresh, OTP: proof, AdditionalFields: map[string]any{"locale": "en"}}, auth.RequestMeta{})
			checkUserFieldError(t, err, "INVALID_OTP")
			login, err := closed.SignInEmailOTP(ctx, auth.EmailOTPSignInInput{Email: email, OTP: code(email)}, auth.RequestMeta{})
			if err != nil || login.User.ID != result.User.ID {
				t.Fatal("existing account on closed node", err)
			}

			raceEmail := "race@profile.test"
			claim := code(raceEmail)
			var wg sync.WaitGroup
			results := make(chan error, 2)
			for _, n := range []*auth.Auth{node, other} {
				wg.Go(func() {
					_, err := n.SignInEmailOTP(ctx, auth.EmailOTPSignInInput{Email: raceEmail, OTP: claim, AdditionalFields: map[string]any{"locale": "winner"}}, auth.RequestMeta{})
					results <- err
				})
			}
			wg.Wait()
			close(results)
			success := 0
			for err := range results {
				if err == nil {
					success++
				} else {
					checkUserFieldError(t, err, "INVALID_OTP")
				}
			}
			if success != 1 {
				t.Fatalf("registrations committed for one proof: %d", success)
			}
		})
	}
}

func TestEmailOTPProfileSignupRollsBackSessionFailure(t *testing.T) {
	for _, dialect := range []string{"memory", "sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			ctx := t.Context()
			fields := map[string]auth.UserField{"locale": {Type: auth.FieldString, Required: true}}
			sessions := map[string]auth.SessionField{"clientFamily": {Type: auth.FieldString, Required: true}}
			var store auth.Store
			if dialect == "memory" {
				store = memory.New()
			} else {
				s, err := OpenWithAdditionalFields(ctx, dialect, organizationTestDSN(t, dialect), nil, schema.AdditionalFields{User: fields, Session: sessions})
				if err != nil {
					t.Fatal(err)
				}
				defer s.Close()
				store = s
			}
			opts := auth.Options{Store: store, BaseURL: "http://email-otp.localhost", Secret: strings.Repeat("s", 40), UserAdditionalFields: fields, SessionAdditionalFields: sessions, Plugins: []auth.Plugin{emailOTPFieldPlugin(t, false)}}
			node, err := auth.New(opts)
			if err != nil {
				t.Fatal(err)
			}
			const email = "rollback@otp-profile.test"
			code, err := node.CreateEmailOTP(ctx, email, auth.OTPSignIn)
			if err != nil {
				t.Fatal(err)
			}
			input := auth.EmailOTPSignInInput{Email: email, OTP: code, AdditionalFields: map[string]any{"locale": "fr"}}
			if _, err = node.SignInEmailOTP(ctx, input, auth.RequestMeta{}); err == nil {
				t.Fatal("account committed without its required session field")
			}
			if _, err = store.(auth.AccountStore).FindAccountUser(ctx, email); !errors.Is(err, auth.ErrNotFound) {
				t.Fatal("failed issuance left a user and profile behind", err)
			}
			opts.SessionAdditionalFields = map[string]auth.SessionField{"clientFamily": {Type: auth.FieldString, Required: true, Default: "browser"}}
			repaired, err := auth.New(opts)
			if err != nil {
				t.Fatal(err)
			}
			result, err := repaired.SignInEmailOTP(ctx, input, auth.RequestMeta{})
			if err != nil || result.Token == "" {
				t.Fatal("storage rollback lost the verified proof", err)
			}
			checkUserField(t, result.User, "locale", "fr")
		})
	}
}

type legacyEmailOTPFieldsStore struct {
	auth.Store
	auth.EmailOTPStore
	auth.UserFieldStore
}

func TestEmailOTPRegistrationStoreContract(t *testing.T) {
	mem := memory.New()
	store := legacyEmailOTPFieldsStore{Store: mem, EmailOTPStore: mem, UserFieldStore: mem}
	opts := auth.Options{BaseURL: "http://email-otp.localhost", Store: store, Secret: strings.Repeat("s", 40), UserAdditionalFields: map[string]auth.UserField{"locale": {Type: auth.FieldString}}, Plugins: []auth.Plugin{emailOTPFieldPlugin(t, false)}}
	if _, err := auth.New(opts); err == nil || !strings.Contains(err.Error(), "EmailOTPRegistrationStore") {
		t.Fatal("custom adapter silently ignored registration fields", err)
	}
	opts.Plugins = []auth.Plugin{emailOTPFieldPlugin(t, true)}
	if _, err := auth.New(opts); err != nil {
		t.Fatal("closed registration required the new adapter contract", err)
	}
	opts.Plugins = []auth.Plugin{emailOTPFieldPlugin(t, false)}
	opts.UserAdditionalFields = nil
	if _, err := auth.New(opts); err != nil {
		t.Fatal("existing email OTP adapter configuration regressed", err)
	}
}
