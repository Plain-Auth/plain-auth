package sqlstore

import (
	"net/http"
	"strings"
	"testing"
	"time"

	auth "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/adapters/memory"
	"github.com/Plain-Org/plain-auth/client"
	"github.com/Plain-Org/plain-auth/plugins/onetimetoken"
	"github.com/Plain-Org/plain-auth/schema"
)

func TestTransferredPublicFields(t *testing.T) {
	for _, dialect := range []string{"memory", "sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			ctx := t.Context()
			fields := schema.AdditionalFields{User: userFieldFixture(), Session: fixtureSessionFields()}
			var shared auth.Store
			if dialect == "memory" {
				shared = memory.New()
			}
			var dsn string
			if shared == nil {
				dsn = organizationTestDSN(t, dialect)
			}
			plugin, err := onetimetoken.New(onetimetoken.Options{SetHeaderOnNewSession: true})
			if err != nil {
				t.Fatal(err)
			}
			newClient := func() *client.Client {
				t.Helper()
				store := shared
				if store == nil {
					s, err := OpenWithAdditionalFields(ctx, dialect, dsn, nil, fields)
					if err != nil {
						t.Fatal(err)
					}
					t.Cleanup(func() { s.Close() })
					store = s
				}
				const origin = "https://transfer.example.test"
				var everyRead time.Duration
				engine, err := auth.New(auth.Options{
					Store: store, BaseURL: origin, Secret: strings.Repeat("t", 40), EmailAndPassword: true,
					UserAdditionalFields: fields.User, SessionAdditionalFields: fields.Session,
					SessionUpdateAge: &everyRead, SessionCookieCache: &auth.SessionCookieCacheOptions{},
					Plugins: []auth.Plugin{plugin},
				})
				if err != nil {
					t.Fatal(err)
				}
				c, err := client.New(origin, &http.Client{Transport: guestTransport{engine}})
				if err != nil {
					t.Fatal(err)
				}
				return c
			}
			issuer, receiver := newClient(), newClient()
			signup := func(c *client.Client, name string) *client.EmailResult {
				t.Helper()
				account, err := c.SignUpEmail(ctx, client.SignUpRequest{
					Name: name, Email: name + "@example.test", Password: "local-transfer-password",
					AdditionalFields: map[string]any{"locale": name + "-user", "secretNote": name + "-private-profile"},
				})
				if err != nil {
					t.Fatal(err)
				}
				if _, err = c.UpdateSession(ctx, map[string]any{"label": name + "-session", "internalNote": name + "-private-session"}); err != nil {
					t.Fatal(err)
				}
				return account
			}
			owner := signup(issuer, "owner")
			visitor := signup(receiver, "visitor")
			proof, err := issuer.GenerateOneTimeToken(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if err := issuer.UpdateUser(ctx, auth.ProfileUpdate{AdditionalFields: map[string]any{"locale": "edited-owner"}}); err != nil {
				t.Fatal(err)
			}
			if _, err := issuer.UpdateSession(ctx, map[string]any{"label": "edited-device"}); err != nil {
				t.Fatal(err)
			}
			check := func(view *auth.SessionResult, sessionLabel string) {
				t.Helper()
				if view == nil || view.User.ID != owner.User.ID || view.User.ID == visitor.User.ID || view.Session.UserID != owner.User.ID || view.Session.Token != *owner.Token {
					t.Fatal("transfer returned the wrong owner")
				}
				checkUserField(t, view.User, "locale", "edited-owner")
				if value, ok := view.Session.AdditionalField("label"); !ok || value != sessionLabel {
					t.Fatalf("device label %v, want %s", value, sessionLabel)
				}
				for _, name := range []string{"secretNote", "privateRank", "preferred_locale", "internalNote", "internalRisk", "display_label"} {
					_, userField := view.User.AdditionalField(name)
					_, sessionField := view.Session.AdditionalField(name)
					if userField || sessionField {
						t.Fatal("private or physical transfer field present", name)
					}
				}
			}
			transferred, err := receiver.VerifyOneTimeToken(ctx, proof)
			if err != nil {
				t.Fatal(err)
			}
			check(transferred, "edited-device")
			if _, err := issuer.UpdateSession(ctx, map[string]any{"label": "renewed-device"}); err != nil {
				t.Fatal(err)
			}
			var renewed auth.SessionResult
			headers, err := receiver.DoWithHeaders(ctx, http.MethodGet, "/get-session", nil, &renewed)
			if err != nil || headers.Get("Set-Ott") == "" {
				t.Fatal("sliding renewal omitted replacement proof", err)
			}
			check(&renewed, "renewed-device")
			next, err := newClient().VerifyOneTimeToken(ctx, headers.Get("Set-Ott"))
			if err != nil {
				t.Fatal(err)
			}
			check(next, "renewed-device")
		})
	}
}
