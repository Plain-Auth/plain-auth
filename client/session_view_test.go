package client_test

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Plain-Auth/plain-auth"
	"github.com/Plain-Auth/plain-auth/adapters/memory"
	"github.com/Plain-Auth/plain-auth/client"
	"github.com/Plain-Auth/plain-auth/plugins/customsession"
	"github.com/Plain-Auth/plain-auth/plugins/multisession"
)

func TestTypedSessionViews(t *testing.T) {
	type viewer struct {
		Email string `json:"email"`
		ID    string `json:"id"`
	}
	type view struct {
		Viewer viewer   `json:"viewer"`
		Flags  []string `json:"flags"`
	}

	for _, mode := range []string{"standard", "projected", "projected-list"} {
		t.Run(mode, func(t *testing.T) {
			ctx := t.Context()
			must := func(err error) {
				t.Helper()
				if err != nil {
					t.Fatal(err)
				}
			}
			multi, err := multisession.New(multisession.Options{})
			must(err)
			plugins := []plainauth.Plugin{multi}
			fail := false
			if mode != "standard" {
				projection, err := customsession.NewWithOptions(func(_ plainauth.EndpointContext, s plainauth.SessionResult) (any, error) {
					if fail && s.User.Name == "Alice" {
						return nil, errors.New("private account lookup failed")
					}
					return view{Viewer: viewer{Email: s.User.Email, ID: s.User.ID}, Flags: []string{"member"}}, nil
				}, customsession.Options{ProjectDeviceSessions: mode == "projected-list"})
				must(err)
				plugins = append(plugins, projection)
			}
			const origin = "https://session-view.test"
			immediate := time.Duration(0)
			auth, err := plainauth.New(plainauth.Options{BaseURL: origin, Store: memory.New(), Secret: strings.Repeat("x", 32), EmailAndPassword: true, Plugins: plugins, SessionUpdateAge: &immediate})
			must(err)
			var last *http.Response
			c, err := client.New(origin, &http.Client{Transport: transport(func(r *http.Request) (*http.Response, error) {
				w := httptest.NewRecorder()
				auth.ServeHTTP(w, r)
				last = w.Result()
				return last, nil
			})})
			must(err)
			anonymous, err := client.GetSessionView[view](ctx, c)
			must(err)
			if anonymous != nil {
				t.Fatal("an unauthenticated view must be nil")
			}
			empty, err := client.ListDeviceSessionViews[view](ctx, c)
			must(err)
			if empty == nil || len(empty) != 0 {
				t.Fatal("expected an empty device list", empty)
			}
			login := func(name string) *client.EmailResult {
				account, err := c.SignUpEmail(ctx, client.SignUpRequest{Name: name, Email: strings.ToLower(name) + "@example.test", Password: "fixture-password"})
				must(err)
				return account
			}
			alice := login("Alice")
			bob := login("Bob")
			active, err := c.SetActiveSession(ctx, *alice.Token)
			must(err)
			if active.User.ID != alice.User.ID {
				t.Fatal("remembered account selection returned a different user")
			}
			if mode == "standard" {
				standard, err := client.GetSessionView[plainauth.SessionResult](ctx, c)
				must(err)
				ordinary, err := c.GetSession(ctx)
				must(err)
				if standard == nil || ordinary == nil || standard.User.ID != alice.User.ID || ordinary.Session.Token != standard.Session.Token {
					t.Fatal("default session shape changed")
				}
			} else {
				seen, err := client.GetSessionView[view](ctx, c)
				must(err)
				if seen == nil || seen.Viewer != (viewer{alice.User.Email, alice.User.ID}) || !slices.Equal(seen.Flags, []string{"member"}) {
					t.Fatal("nested projection lost", seen)
				}
				expected := auth.SessionCookie(*alice.Token, true)
				refreshed := slices.ContainsFunc(last.Cookies(), func(c *http.Cookie) bool { return c.Name == expected.Name && c.Value == expected.Value })
				if !refreshed || last.Header.Get("Cache-Control") != "no-store" {
					t.Fatal("session refresh changed the signed cookie or lost cache control")
				}
				decode, err := client.GetSessionView[struct{ Viewer int }](ctx, c)
				if err == nil || decode != nil {
					t.Fatal("failed decoding returned a partial view")
				}
			}
			if mode == "projected-list" {
				rows, err := client.ListDeviceSessionViews[view](ctx, c)
				must(err)
				if len(rows) != 2 {
					t.Fatal("expected two remembered views", len(rows))
				}
				emails := []string{rows[0].Viewer.Email, rows[1].Viewer.Email}
				slices.Sort(emails)
				if !slices.Equal(emails, []string{alice.User.Email, bob.User.Email}) {
					t.Fatal("unexpected projected device accounts", emails)
				}
				fail = true
				assertRedacted := func(err error) {
					t.Helper()
					var public *plainauth.APIError
					if !errors.As(err, &public) || public.Status != 500 || strings.Contains(err.Error(), "private") {
						t.Fatal("expected a redacted server failure", err)
					}
				}
				one, err := client.GetSessionView[view](ctx, c)
				assertRedacted(err)
				many, err := client.ListDeviceSessionViews[view](ctx, c)
				assertRedacted(err)
				if one != nil || many != nil {
					t.Fatal("projection failure returned partial account data")
				}
			} else {
				rows, err := client.ListDeviceSessionViews[plainauth.SessionResult](ctx, c)
				must(err)
				if len(rows) != 2 || rows[0].User.ID == rows[1].User.ID || rows[0].Session.Token == "" {
					t.Fatal("device list must retain its standard shape by default")
				}
			}
		})
	}
}

func TestProjectedSessionReadOptions(t *testing.T) {
	type view struct {
		Viewer string `json:"viewer"`
	}
	plugin, err := customsession.New(func(_ plainauth.EndpointContext, data plainauth.SessionResult) (any, error) {
		return view{data.User.Email}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	const origin = "https://view.example"
	immediate := time.Duration(0)
	host, err := plainauth.New(plainauth.Options{BaseURL: origin, Store: memory.New(), Secret: strings.Repeat("x", 32), EmailAndPassword: true, SessionUpdateAge: &immediate, Plugins: []plainauth.Plugin{plugin}})
	if err != nil {
		t.Fatal(err)
	}
	var query string
	var cookies []*http.Cookie
	c, err := client.New(origin+"/api/auth", &http.Client{Transport: transport(func(r *http.Request) (*http.Response, error) {
		w := httptest.NewRecorder()
		host.ServeHTTP(w, r)
		response := w.Result()
		query = r.URL.RawQuery
		cookies = response.Cookies()
		return response, nil
	})})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = c.SignUpEmail(t.Context(), client.SignUpRequest{Name: "View", Email: "view@example.test", Password: "valid-fixture-password"}); err != nil {
		t.Fatal(err)
	}
	got, err := client.GetSessionViewWithOptions[view](t.Context(), c, client.SessionReadOptions{DisableRefresh: true, DisableCookieCache: true})
	if err != nil || got == nil || got.Viewer != "view@example.test" || query != "disableCookieCache=true&disableRefresh=true" || len(cookies) != 0 {
		t.Fatal("requested a non-refreshing database view", err, query, len(cookies))
	}
	got, err = client.GetSessionViewWithOptions[view](t.Context(), c, client.SessionReadOptions{})
	if err != nil || got == nil || query != "" || len(cookies) == 0 {
		t.Fatal("false query flags changed refresh behavior", err, query, len(cookies))
	}
}
