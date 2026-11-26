package sqlstore

import (
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	authn "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/plugins/admin"
	"github.com/Plain-Org/plain-auth/plugins/magiclink"
	"github.com/Plain-Org/plain-auth/schema"
)

// BannedUserMessageFunc builds the BANNED_USER message from the stored
// account after the store call returns, for the HTTP answer, endpoint after
// hooks and magic-link redirects; an empty result or a panic keeps the
// configured message, as native Go calls do.
func TestBannedUserMessageFuncAcrossEngines(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			ctx := t.Context()
			must := func(err error) {
				t.Helper()
				if err != nil {
					t.Fatal(err)
				}
			}
			ddl, err := schema.Generate(dialect, []string{"admin"})
			must(err)
			store, err := OpenWithSchema(ctx, dialect, organizationTestDSN(t, dialect), ddl)
			must(err)
			defer store.Close()
			p, err := admin.New(admin.Options{BannedUserMessage: "Account closed", BannedUserMessageFunc: func(_ context.Context, u authn.User) string {
				switch u.Name {
				case "Quiet":
					return ""
				case "Broken":
					panic("message builder failed")
				}
				return "Banned for " + *u.BanReason + " (" + u.Role + ")"
			}})
			must(err)
			var link magiclink.Message
			links, err := magiclink.New(magiclink.Options{Send: func(_ context.Context, m magiclink.Message) error { link = m; return nil }})
			must(err)
			var hooked []string
			const origin = "https://banned.example"
			off := false
			a, err := authn.New(authn.Options{Store: store, BaseURL: origin, Secret: strings.Repeat("b", 32), EmailAndPassword: true, RateLimit: &off, Plugins: []authn.Plugin{p, links},
				Hooks: authn.EndpointHooks{After: []authn.EndpointHook{{Run: func(c *authn.HookContext) error {
					var api *authn.APIError
					if errors.As(c.Err, &api) && api.Code == "BANNED_USER" {
						hooked = append(hooked, api.Message)
					}
					return nil
				}}}}})
			must(err)
			ban := func(name, reason string) string {
				t.Helper()
				email := strings.ToLower(name) + "@banned.example"
				res, err := a.SignUpEmail(ctx, authn.SignUpInput{Name: name, Email: email, Password: "banned-password"}, authn.RequestMeta{})
				must(err)
				_, err = store.db.ExecContext(ctx, store.bind(`UPDATE "user" SET "banned"=?,"banReason"=? WHERE "id"=?`), true, reason, res.User.ID)
				must(err)
				return email
			}
			signIn := func(email string) map[string]any {
				t.Helper()
				r := httptest.NewRequest("POST", origin+"/api/auth/sign-in/email", strings.NewReader(`{"email":"`+email+`","password":"banned-password"}`))
				r.Header.Set("Origin", origin)
				r.Header.Set("Content-Type", "application/json")
				w := httptest.NewRecorder()
				a.ServeHTTP(w, r)
				var body map[string]any
				_ = json.Unmarshal(w.Body.Bytes(), &body)
				if w.Code != 403 || body["code"] != "BANNED_USER" {
					t.Fatal("a banned account was not refused", w.Code, w.Body)
				}
				return body
			}
			spammer := ban("Spammer", "spam")
			if body := signIn(spammer); body["message"] != "Banned for spam (user)" || len(hooked) != 1 || hooked[0] != "Banned for spam (user)" {
				t.Fatal("the banned message was not built from the account", body, hooked)
			}
			for _, name := range []string{"Quiet", "Broken"} {
				if body := signIn(ban(name, "other")); body["message"] != "Account closed" {
					t.Fatal("an empty or failing message builder did not keep the configured message", name, body)
				}
			}
			var api *authn.APIError
			if _, err := a.SignInEmail(ctx, authn.SignInInput{Email: spammer, Password: "banned-password"}, authn.RequestMeta{}); !errors.As(err, &api) || api.Message != "Account closed" {
				t.Fatal("a native sign-in did not keep the configured message", err)
			}
			r := httptest.NewRequest("POST", origin+"/api/auth/sign-in/magic-link", strings.NewReader(`{"email":"`+spammer+`","errorCallbackURL":"/failed"}`))
			r.Header.Set("Origin", origin)
			r.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			a.ServeHTTP(w, r)
			if w.Code != 200 || link.URL == "" {
				t.Fatal("the magic link was not sent", w.Code, w.Body)
			}
			w = httptest.NewRecorder()
			a.ServeHTTP(w, httptest.NewRequest("GET", link.URL, nil))
			target, err := url.Parse(w.Header().Get("Location"))
			must(err)
			if w.Code != 302 || target.Query().Get("error") != "BANNED_USER" || target.Query().Get("error_description") != "Banned for spam (user)" {
				t.Fatal("a magic-link redirect did not carry the built message", w.Code, w.Header().Get("Location"))
			}
		})
	}
}

// AdminUserHasPermission reads the stored account's current role and
// honours AdminUserIDs, for server code without a session.
func TestAdminUserHasPermissionAcrossEngines(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			ctx := t.Context()
			must := func(err error) {
				t.Helper()
				if err != nil {
					t.Fatal(err)
				}
			}
			ddl, err := schema.Generate(dialect, []string{"admin"})
			must(err)
			store, err := OpenWithSchema(ctx, dialect, organizationTestDSN(t, dialect), ddl)
			must(err)
			defer store.Close()
			roles := admin.DefaultRoles()
			roles["support"] = admin.Permissions{"user": {"get", "list"}}
			p, err := admin.New(admin.Options{Roles: roles, AdminUserIDs: []string{"explicit-owner"}})
			must(err)
			off := false
			a, err := authn.New(authn.Options{Store: store, BaseURL: "https://permission.example", Secret: strings.Repeat("h", 32), EmailAndPassword: true, RateLimit: &off, Plugins: []authn.Plugin{p}})
			must(err)
			agent, err := a.AdminCreateUser(ctx, authn.AdminCreateUserRequest{Name: "Agent", Email: "agent@permission.example", Role: []string{"support"}})
			must(err)
			check := func(id string, want authn.AdminPermissions) bool {
				t.Helper()
				ok, err := a.AdminUserHasPermission(ctx, id, want)
				must(err)
				return ok
			}
			if !check(agent.ID, authn.AdminPermissions{"user": {"get", "list"}}) || check(agent.ID, authn.AdminPermissions{"user": {"ban"}}) {
				t.Fatal("the server check did not use the stored role")
			}
			_, err = store.db.ExecContext(ctx, store.bind(`UPDATE "user" SET "role"=? WHERE "id"=?`), "admin", agent.ID)
			must(err)
			if !check(agent.ID, authn.AdminPermissions{"user": {"ban"}}) {
				t.Fatal("the server check used a stale role")
			}
			must(store.SaveFixtureUser(ctx, testUser("explicit-owner")))
			if !check("explicit-owner", authn.AdminPermissions{"user": {"impersonate-admins"}}) {
				t.Fatal("the server check ignored AdminUserIDs")
			}
			var api *authn.APIError
			for _, refused := range []struct {
				id   string
				want authn.AdminPermissions
				code string
			}{{"missing-account", authn.AdminPermissions{"user": {"get"}}, "USER_NOT_FOUND"}, {"", authn.AdminPermissions{"user": {"get"}}, "VALIDATION_ERROR"}, {agent.ID, nil, "VALIDATION_ERROR"}} {
				if _, err := a.AdminUserHasPermission(ctx, refused.id, refused.want); !errors.As(err, &api) || api.Status != 400 || api.Code != refused.code {
					t.Fatal("a server permission check was not refused", refused.id, err)
				}
			}
		})
	}
}
