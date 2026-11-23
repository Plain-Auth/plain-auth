package sqlstore

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	auth "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/adapters/memory"
	"github.com/Plain-Org/plain-auth/authtest"
)

func TestFixtureSessionFieldOptions(t *testing.T) {
	for _, dialect := range []string{"memory", "sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			ctx := t.Context()
			fields := map[string]auth.SessionField{
				"station": {Type: auth.FieldString, Required: true, ServerOnly: true, Column: "fixture_station"},
				"label":   {Type: auth.FieldString, Default: "office"},
				"secret":  {Type: auth.FieldNumber, Hidden: true, ServerOnly: true},
			}
			var store, replica auth.Store
			if dialect == "memory" {
				store = memory.New()
				replica = store
			} else {
				dsn := organizationTestDSN(t, dialect)
				for _, dst := range []*auth.Store{&store, &replica} {
					s, err := OpenWithSessionFields(ctx, dialect, dsn, nil, fields)
					if err != nil {
						t.Fatal(err)
					}
					t.Cleanup(func() { s.Close() })
					*dst = s
				}
			}
			opts := auth.Options{Store: store, BaseURL: "https://auth.example.test", Secret: strings.Repeat("s", 40), SessionAdditionalFields: fields}
			server, err := authtest.New(opts)
			if err != nil {
				t.Fatal(err)
			}
			opts.Store = replica
			peer, err := auth.New(opts)
			if err != nil {
				t.Fatal(err)
			}
			user, err := server.SaveUser(ctx, authtest.NewUser())
			if err != nil {
				t.Fatal(err)
			}

			check := func(s auth.Session, label string) {
				t.Helper()
				station, ok := s.AdditionalField("station")
				actual, present := s.AdditionalField("label")
				if !ok || !present || station != "west" || actual != label {
					t.Fatal("fixture field or default was lost", station, actual)
				}
				if _, ok := s.AdditionalField("secret"); ok {
					t.Fatal("hidden fixture field was exposed")
				}
				payload, err := json.Marshal(s)
				if err != nil || strings.Contains(string(payload), `"secret"`) || strings.Contains(string(payload), "fixture_station") {
					t.Fatal("session JSON exposed internal fields", err)
				}
				if s.UserID != user.ID || s.ID == "supplied" || s.Token == "supplied" || s.IPAddress != "" || s.UserAgent != "" || s.CreatedAt.IsZero() || s.UpdatedAt.IsZero() || !s.ExpiresAt.After(time.Now()) {
					t.Fatal("fixture changed generated session attributes")
				}
			}
			options := authtest.LoginOptions{UserID: user.ID, Fields: map[string]any{
				"station": "west", "secret": 13, "label": "", "id": "supplied", "userId": "other", "token": "supplied",
				"createdAt": time.Time{}, "updatedAt": time.Time{}, "expiresAt": time.Time{}, "ipAddress": "192.0.2.1", "userAgent": "supplied",
			}}
			login, err := server.LoginWithOptions(ctx, options)
			if err != nil {
				t.Fatal(err)
			}
			check(login.Session, "")
			headers, err := server.GetAuthHeadersWithOptions(ctx, options)
			if err != nil {
				t.Fatal(err)
			}
			delete(options.Fields, "label")
			cookies, err := server.GetCookiesWithOptions(ctx, options, ".example.test")
			if err != nil || len(cookies) != 1 || cookies[0].Domain != ".example.test" {
				t.Fatal("cookie fixture did not apply domain", err)
			}
			browser := httptest.NewRequest(http.MethodGet, "https://auth.example.test", nil)
			browser.AddCookie(cookies[0])
			for i, h := range []http.Header{login.Headers, headers, browser.Header} {
				result, err := peer.GetSession(ctx, h)
				if err != nil || result == nil {
					t.Fatal("peer could not read fixture session", err)
				}
				label := ""
				if i == 2 {
					label = "office"
				}
				check(result.Session, label)
				// Inspect the persisted value independently of the public projection.
				rawColumn := map[string]auth.SessionField{"secret": {Type: auth.FieldNumber}}
				rows, err := replica.(auth.SessionFieldStore).ReadSessionFields(ctx, []auth.Session{result.Session}, rawColumn)
				if err != nil || rows[result.Session.Token]["secret"] != int64(13) {
					t.Fatal("server-only value was not persisted", err)
				}
			}
			for _, invalid := range []map[string]any{nil, {"station": true}, {"station": "west", "activeOrganizationId": "other"}, {"station": "west", "unknown": 4}} {
				if _, err := server.LoginWithOptions(ctx, authtest.LoginOptions{UserID: user.ID, Fields: invalid}); err == nil {
					t.Fatal("invalid trusted attributes accepted")
				}
			}
			sessions, err := store.ListSessions(ctx, user.ID)
			if err != nil || len(sessions) != 3 {
				t.Fatal("failed fixture wrote a session", len(sessions), err)
			}
		})
	}
}
