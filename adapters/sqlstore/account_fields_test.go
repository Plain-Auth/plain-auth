package sqlstore

import (
	"context"
	"errors"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	auth "github.com/Plain-Auth/plain-auth"
	"github.com/Plain-Auth/plain-auth/client"
	"github.com/Plain-Auth/plain-auth/schema"
)

func TestMappedAccountFields(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			ctx := t.Context()
			var sequence, transforms atomic.Int32
			fields := map[string]auth.AccountField{
				"department":  {Type: auth.FieldString, Column: "dept_name"},
				"lastConsent": {Type: auth.FieldDate, Hidden: true},
				"sequence":    {Type: auth.FieldNumber, ServerOnly: true, Required: true, Default: func() int32 { return sequence.Add(1) }},
			}
			store, err := OpenWithAdditionalFields(ctx, dialect, organizationTestDSN(t, dialect), nil, schema.AdditionalFields{Account: fields})
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			if sequence.Load() != 0 {
				t.Fatal("migration evaluated an application default")
			}
			p := newProfileIssuer(t).provider()
			p.VerifyIDToken = func(_ context.Context, raw, nonce string) (auth.OAuthProfile, time.Time, error) {
				stage, signedNonce, ok := strings.Cut(raw, "/")
				if !ok || signedNonce != nonce {
					return auth.OAuthProfile{}, time.Time{}, errors.New("invalid fixture token")
				}
				return auth.OAuthProfile{Subject: "worker", Name: stage, EmailVerified: true, Email: "employee@example.test"}, time.Now().Add(time.Hour), nil
			}
			p.GetAccountFields = func(_ context.Context, input auth.OAuthAccountFieldInput) (map[string]any, error) {
				if input.Tokens.AccessToken != "" || input.ClientAccessToken != "client-string" || input.ClientRefreshToken != "client-refresh" {
					t.Error("direct hook confused submitted strings and verified credentials")
				}
				out := map[string]any{"department": input.Profile.Name, "sequence": 99, "userId": "foreign", "dept_name": "wrong", "lastConsent": "2026-02-02T01:02:03-05:00"}
				switch input.Profile.Name {
				case "invalid":
					out["lastConsent"] = "invalid date"
				case "failure":
					return nil, errors.New("private upstream detail")
				case "clear":
					out["department"] = nil
				}
				return out, nil
			}
			app := httptest.NewUnstartedServer(nil)
			base := "http://" + app.Listener.Addr().String()
			opts := auth.Options{Store: store, BaseURL: base, Secret: strings.Repeat("s", 40), EmailAndPassword: true,
				RateLimit: new(bool), AccountAdditionalFields: fields, EncryptOAuthTokens: true, SocialProviders: map[string]auth.OAuthProvider{"work": p}}
			opts.AccountFieldRules = map[string]auth.AccountFieldRule{"department": {
				ValidateInput: func(v any) error {
					if v == "reject" {
						return errors.New("private validation detail")
					}
					return nil
				},
				TransformInput: func(v any) (any, error) {
					transforms.Add(1)
					if v == nil {
						return nil, nil
					}
					if v == "transform-error" {
						return nil, errors.New("private transform detail")
					}
					return "unit-" + v.(string), nil
				},
			}}
			instance, err := auth.New(opts)
			if err != nil {
				t.Fatal(err)
			}
			app.Config.Handler = instance
			app.Start()
			defer app.Close()
			actor := func() *client.Client {
				t.Helper()
				c, err := client.New(base, nil)
				if err != nil {
					t.Fatal(err)
				}
				return c
			}
			visitor := actor()
			grant := func(who *client.Client, stage string) error {
				_, err := who.SignInSocial(ctx, client.SocialSignInRequest{Provider: "work", IDToken: &client.SocialIDToken{
					Token: stage + "/nonce", Nonce: "nonce", AccessToken: "client-string", RefreshToken: "client-refresh",
				}})
				return err
			}
			for _, stage := range []string{"invalid", "failure", "reject"} {
				err := grant(visitor, stage)
				var api *auth.APIError
				if !errors.As(err, &api) || strings.Contains(api.Message, "private") {
					t.Fatal("unexpected mapping failure", err)
				}
			}
			var count int
			if err := store.db.QueryRowContext(ctx, store.bind(`SELECT COUNT(*) FROM "user"`)).Scan(&count); err != nil || count != 0 || sequence.Load() != 0 {
				t.Fatal("failed mapping created an owner or evaluated a default", count, err)
			}
			login := func(stage string, expected any) auth.LinkedAccount {
				t.Helper()
				if err := grant(visitor, stage); err != nil {
					t.Fatal(err)
				}
				accounts, err := visitor.ListAccounts(ctx)
				if err != nil || len(accounts) != 1 {
					t.Fatal("account list", err)
				}
				a := accounts[0]
				if v, ok := a.AdditionalFields["department"]; !ok || v != expected || a.AdditionalFields["sequence"] != int64(1) || len(a.AdditionalFields) != 2 {
					t.Fatalf("unexpected public account fields %#v", a.AdditionalFields)
				}
				return a
			}
			first := login("engineering", "unit-engineering")
			if transforms.Load() != 1 {
				t.Fatal("mapped value was transformed more than once")
			}
			if err := grant(visitor, "transform-error"); err == nil {
				t.Fatal("accepted a failed account field transform")
			}
			if err := grant(visitor, "invalid"); err == nil {
				t.Fatal("invalid returning update succeeded")
			}
			var department, sealed string
			var instant time.Time
			if err := store.db.QueryRowContext(ctx, store.bind(`SELECT "dept_name","lastConsent","idToken" FROM "account" WHERE "id"=? AND "userId"=? AND "accessToken" IS NULL AND "refreshToken" IS NULL`), first.ID, first.UserID).Scan(&department, &instant, &sealed); err != nil || department != "unit-engineering" || instant.UTC().Format(time.RFC3339) != "2026-02-02T06:02:03Z" || !strings.HasPrefix(sealed, "authn.v1.") {
				t.Fatal("stored mapping or verified credentials", err)
			}
			if a := login("clear", nil); a.ID != first.ID || a.UserID != first.UserID || sequence.Load() != 1 {
				t.Fatal("returning account identity or default changed")
			}
			passwordOwner := actor()
			if _, err := passwordOwner.SignUpEmail(ctx, client.SignUpRequest{Name: "Owner", Email: "password@example.test", Password: "local-test-password"}); err != nil {
				t.Fatal(err)
			}
			accounts, err := passwordOwner.ListAccounts(ctx)
			if err != nil || len(accounts) != 1 || accounts[0].ProviderID != "credential" || accounts[0].AdditionalFields["sequence"] != int64(2) || accounts[0].AdditionalFields["department"] != nil {
				t.Fatal("password account defaults or ownership isolation", accounts, err)
			}
			if _, err := actor().ListAccounts(ctx); err == nil {
				t.Fatal("anonymous account read")
			}
			opts.AccountAdditionalFields = map[string]auth.AccountField{"unmigrated": {Type: auth.FieldBoolean}}
			opts.AccountFieldRules = nil
			if _, err := auth.New(opts); err == nil {
				t.Fatal("accepted missing account column")
			}
		})
	}
}
