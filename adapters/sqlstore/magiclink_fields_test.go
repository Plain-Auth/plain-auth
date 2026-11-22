package sqlstore

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	auth "github.com/Plain-Auth/plain-auth"
	"github.com/Plain-Auth/plain-auth/adapters/memory"
	"github.com/Plain-Auth/plain-auth/client"
	"github.com/Plain-Auth/plain-auth/plugins/magiclink"
	"github.com/Plain-Auth/plain-auth/schema"
)

func TestMagicLinkProfileOwnership(t *testing.T) {
	for _, dialect := range []string{"memory", "sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			ctx := t.Context()
			fields := schema.AdditionalFields{User: userFieldFixture(), Session: fixtureSessionFields()}
			var shared auth.Store
			var sqlDB *Store
			if dialect == "memory" {
				shared = memory.New()
			} else {
				store, err := OpenWithAdditionalFields(ctx, dialect, organizationTestDSN(t, dialect), nil, fields)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { store.Close() })
				sqlDB = store
				shared = store
			}

			const origin = "https://mail.example.test"
			var delivered string
			makeClient := func(locale string, closed bool, extra ...auth.Plugin) (*client.Client, *auth.Auth) {
				t.Helper()
				decl := userFieldFixture()
				field := decl["locale"]
				if locale != "" {
					field.Default = locale
				}
				decl["locale"] = field
				p, err := magiclink.New(magiclink.Options{DisableSignUp: closed, Send: func(_ context.Context, msg magiclink.Message) error { delivered = msg.Token; return nil }})
				if err != nil {
					t.Fatal(err)
				}
				off := false
				a, err := auth.New(auth.Options{
					Store: shared, BaseURL: origin, Secret: strings.Repeat("m", 40), RateLimit: &off, EmailAndPassword: true,
					UserAdditionalFields: decl, SessionAdditionalFields: fields.Session, Plugins: append([]auth.Plugin{p}, extra...),
				})
				if err != nil {
					t.Fatal(err)
				}
				c, err := client.New(origin, &http.Client{Transport: guestTransport{a}})
				if err != nil {
					t.Fatal(err)
				}
				return c, a
			}
			first, host := makeClient("first-default", false)
			second, _ := makeClient("second-default", false)
			issue := func(c *client.Client, email string) string {
				t.Helper()
				delivered = ""
				err := c.SignInMagicLink(ctx, client.MagicLinkRequest{Email: email, Name: "New", Metadata: map[string]any{"locale": "delivery-only", "secretNote": "private-input"}})
				if err != nil || delivered == "" {
					t.Fatal("link was not delivered", err)
				}
				return delivered
			}
			const email = "owner@fields.test"
			original, err := second.VerifyMagicLink(ctx, issue(first, email))
			if err != nil {
				t.Fatal(err)
			}
			checkUserField(t, original.User, "locale", "second-default")
			if value, ok := original.Session.AdditionalField("label"); !ok || value != "en" {
				t.Fatal("issued session fields missing")
			}
			// A peer's configuration can change after the profile was already created.
			existing, err := first.VerifyMagicLink(ctx, issue(second, email))
			if err != nil {
				t.Fatal(err)
			}
			checkUserField(t, existing.User, "locale", "second-default")
			if err := host.UpdateTrustedUserFields(ctx, original.User.ID, map[string]any{"locale": "saved-owner", "accountClass": "provisioned", "secretNote": "retained-private"}); err != nil {
				t.Fatal(err)
			}
			requiresInput, _ := makeClient("", false)
			repeated, err := requiresInput.VerifyMagicLink(ctx, issue(first, email))
			if err != nil || repeated.User.ID != original.User.ID {
				t.Fatal("existing owner required a registration default", err)
			}
			checkUserField(t, repeated.User, "locale", "saved-owner")
			checkUserField(t, repeated.User, "accountClass", "provisioned")
			if _, found := repeated.User.AdditionalField("secretNote"); found {
				t.Fatal("hidden profile value reached the Go client")
			}
			if sqlDB != nil {
				var value string
				if err := sqlDB.db.QueryRowContext(ctx, sqlDB.bind(`SELECT "secretNote" FROM "user" WHERE "id"=?`), original.User.ID).Scan(&value); err != nil || value != "retained-private" {
					t.Fatal("private value changed on returning login", err)
				}
			}

			// Two separate mailbox proofs can race while different nodes use different
			// defaults. The winner creates one profile, and both sessions read that profile.
			type verification struct {
				result *client.MagicLinkResult
				err    error
			}
			results := make(chan verification, 2)
			start := make(chan struct{})
			for _, browser := range []*client.Client{first, second} {
				proof := issue(browser, "contended@fields.test")
				go func() {
					<-start
					result, err := browser.VerifyMagicLink(ctx, proof)
					results <- verification{result, err}
				}()
			}
			close(start)
			winner, follower := <-results, <-results
			if winner.err != nil || follower.err != nil || winner.result.User.ID != follower.result.User.ID {
				t.Fatal("concurrent links did not resolve the same profile", winner.err, follower.err)
			}
			value, ok := winner.result.User.AdditionalField("locale")
			if !ok || (value != "first-default" && value != "second-default") {
				t.Fatal("invalid winning registration default", value)
			}
			checkUserField(t, follower.result.User, "locale", value)

			proof := issue(first, "new@fields.test")
			failHeaders, err := requiresInput.DoWithHeaders(ctx, http.MethodGet, "/magic-link/verify?token="+proof, nil, nil)
			var api *auth.APIError
			if !errors.As(err, &api) || api.Status != 500 || len(failHeaders.Values("Set-Cookie")) != 0 {
				t.Fatal("missing registration default issued a credential", err)
			}
			if _, err := second.VerifyMagicLink(ctx, proof); err == nil {
				t.Fatal("failed registration proof was reusable")
			}
			// A failed public profile projection must not replace the browser's login.
			block := auth.Plugin{ID: "reject-profile", OnReadSession: func(context.Context, *auth.SessionResult) error { return errors.New("fixture projection rejected") }}
			reject, _ := makeClient("", true, block)
			headers, err := reject.DoWithHeaders(ctx, http.MethodGet, "/magic-link/verify?token="+issue(first, email), nil, nil)
			if !errors.As(err, &api) || api.Status != 500 || len(headers.Values("Set-Cookie")) != 0 {
				t.Fatal("failed profile projection published a session cookie", err)
			}

			if dialect == "mysql" {
				// Imported mailboxes can contain non-ASCII characters which a database
				// collation considers equal to the delivered ASCII mailbox.
				if _, err := sqlDB.db.ExecContext(ctx, sqlDB.bind(`UPDATE "user" SET "email"=? WHERE "id"=?`), "ównér@fields.test", original.User.ID); err != nil {
					t.Fatal(err)
				}
				closed, _ := makeClient("", true)
				if _, err := closed.VerifyMagicLink(ctx, issue(first, email)); err == nil {
					t.Fatal("noncanonical mailbox received another profile")
				}
			}
		})
	}
}

// This adapter knows the original magic-link and profile interfaces, while
// field-aware magic-link registration is deliberately absent.
type legacyProfileMailStore struct {
	auth.Store
	auth.UserFieldStore
	auth.MagicLinkStore
}

func TestMagicLinkFieldStoreCompatibility(t *testing.T) {
	db := memory.New()
	legacy := legacyProfileMailStore{db, db, db}
	for _, tc := range []struct{ fields, closed, wantError bool }{{false, false, false}, {true, true, false}, {true, false, true}} {
		p, err := magiclink.New(magiclink.Options{DisableSignUp: tc.closed, Send: func(context.Context, magiclink.Message) error { return nil }})
		if err != nil {
			t.Fatal(err)
		}
		opts := auth.Options{Store: legacy, BaseURL: "https://mail.example.test", Secret: strings.Repeat("s", 40), Plugins: []auth.Plugin{p}}
		if tc.fields {
			opts.UserAdditionalFields = userFieldFixture()
		}
		_, err = auth.New(opts)
		if (err != nil) != tc.wantError {
			t.Fatalf("fields=%t closed=%t: %v", tc.fields, tc.closed, err)
		}
	}
}
