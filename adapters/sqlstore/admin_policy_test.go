package sqlstore

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"strings"
	"testing"
	"time"

	authn "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/client"
	"github.com/Plain-Org/plain-auth/plugins/admin"
	"github.com/Plain-Org/plain-auth/schema"
)

// Every administrative operation refuses an operator without its grant and
// a missing account, the option defaults apply, and a role map built from
// the default roles serves over HTTP.
func TestAdminRefusalsAndDefaultsAcrossEngines(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			ctx := t.Context()
			must := func(err error) {
				t.Helper()
				if err != nil {
					t.Fatal(err)
				}
			}
			expect := func(err error, status int, code string) {
				t.Helper()
				var api *authn.APIError
				if !errors.As(err, &api) || api.Status != status || api.Code != code {
					t.Fatalf("expected %d %q, got %v", status, code, err)
				}
			}
			ddl, err := schema.Generate(dialect, []string{"admin"})
			must(err)
			store, err := OpenWithSchema(ctx, dialect, organizationTestDSN(t, dialect), ddl)
			must(err)
			defer store.Close()
			roles := admin.DefaultRoles()
			roles["member"] = admin.Permissions{}
			roles["steward"] = admin.Permissions{"user": {"get"}}
			roles["editor"] = admin.Permissions{"user": {"create", "update"}}
			roles["warden"] = admin.Permissions{"user": {"impersonate", "impersonate-admins"}}
			policy := admin.Options{DefaultRole: "member", AdminRoles: []string{"steward"}, DefaultBanDuration: 2 * time.Hour, Roles: roles}
			const origin = "https://admin.example"
			off := false
			serve := func(opts admin.Options) *authn.Auth {
				p, err := admin.New(opts)
				must(err)
				a, err := authn.New(authn.Options{Store: store, BaseURL: origin, Secret: strings.Repeat("p", 32), EmailAndPassword: true, RateLimit: &off, Plugins: []authn.Plugin{p}})
				must(err)
				return a
			}
			strict := serve(policy)
			lenientPolicy := policy
			lenientPolicy.AllowImpersonatingAdmins = true
			lenient := serve(lenientPolicy)
			newJar := func() http.CookieJar {
				jar, err := cookiejar.New(nil)
				must(err)
				return jar
			}
			browser := func(svc *authn.Auth, jar http.CookieJar) *client.Client {
				c, err := client.New(origin, &http.Client{Jar: jar, Transport: guestTransport{svc}})
				must(err)
				return c
			}
			count := func(query string, args ...any) int {
				t.Helper()
				var n int
				must(store.db.QueryRowContext(ctx, store.bind(query), args...).Scan(&n))
				return n
			}
			column := func(query, id string) string {
				t.Helper()
				var v string
				must(store.db.QueryRowContext(ctx, store.bind(query), id).Scan(&v))
				return v
			}

			chiefUser, err := strict.BootstrapAdmin(ctx, "Chief", "chief@example.test", "chief-password-phrase")
			must(err)
			chiefJar := newJar()
			chief := browser(strict, chiefJar)
			_, err = chief.SignInEmail(ctx, client.SignInRequest{Email: "chief@example.test", Password: "chief-password-phrase"})
			must(err)
			member := browser(strict, newJar())
			memberAccount, err := member.SignUpEmail(ctx, client.SignUpRequest{Name: "Member", Email: "member@example.test", Password: "member-password"})
			must(err)
			plain, err := chief.AdminCreateUser(ctx, client.AdminCreateUserRequest{Name: "Plain", Email: "plain@example.test"})
			must(err)
			editorAccount, err := chief.AdminCreateUser(ctx, client.AdminCreateUserRequest{Name: "Editor", Email: "editor@example.test", Password: "editor-password", Role: []string{"editor"}})
			must(err)
			editor := browser(strict, newJar())
			_, err = editor.SignInEmail(ctx, client.SignInRequest{Email: "editor@example.test", Password: "editor-password"})
			must(err)
			steward, err := chief.AdminCreateUser(ctx, client.AdminCreateUserRequest{Name: "Steward", Email: "steward@example.test", Role: []string{"member", "steward"}})
			must(err)
			deputy, err := chief.AdminCreateUser(ctx, client.AdminCreateUserRequest{Name: "Deputy", Email: "deputy@example.test", Role: []string{"admin"}})
			must(err)
			guest := browser(strict, newJar())
			const missing = "missing-account"

			// Sign-up and administrator-created accounts store the configured default role.
			for _, id := range []string{memberAccount.User.ID, plain.ID} {
				if column(`SELECT "role" FROM "user" WHERE "id"=?`, id) != "member" {
					t.Fatal("a new account did not store the configured default role", id)
				}
			}
			if memberAccount.User.Role != "member" || plain.Role != "member" {
				t.Fatal("a new account did not return the configured default role")
			}

			// An account with only the default role is refused every administrative operation.
			_, err = member.AdminSetRole(ctx, steward.ID, "admin")
			expect(err, 403, "YOU_ARE_NOT_ALLOWED_TO_CHANGE_USERS_ROLE")
			if column(`SELECT "role" FROM "user" WHERE "id"=?`, steward.ID) != "member,steward" {
				t.Fatal("a refused role change changed the account")
			}
			_, err = member.AdminListUsers(ctx, authn.AdminQuery{})
			expect(err, 403, "YOU_ARE_NOT_ALLOWED_TO_LIST_USERS")
			_, err = member.AdminListUserSessions(ctx, chiefUser.ID)
			expect(err, 403, "YOU_ARE_NOT_ALLOWED_TO_LIST_USERS_SESSIONS")
			_, err = member.AdminUnbanUser(ctx, deputy.ID)
			expect(err, 403, "YOU_ARE_NOT_ALLOWED_TO_BAN_USERS")
			_, err = member.AdminBanUser(ctx, deputy.ID, "", 0)
			expect(err, 403, "YOU_ARE_NOT_ALLOWED_TO_BAN_USERS")
			_, err = member.AdminImpersonate(ctx, plain.ID)
			expect(err, 403, "YOU_ARE_NOT_ALLOWED_TO_IMPERSONATE_USERS")
			expect(member.AdminRevokeUserSessions(ctx, chiefUser.ID), 403, "YOU_ARE_NOT_ALLOWED_TO_REVOKE_USERS_SESSIONS")
			if s, err := chief.GetSession(ctx); err != nil || s == nil || s.User.ID != chiefUser.ID {
				t.Fatal("a refused revocation signed the operator out", err)
			}
			expect(member.AdminRemoveUser(ctx, plain.ID), 403, "YOU_ARE_NOT_ALLOWED_TO_DELETE_USERS")
			expect(member.AdminSetPassword(ctx, plain.ID, "replacement-password"), 403, "YOU_ARE_NOT_ALLOWED_TO_SET_USERS_PASSWORD")

			// An authorized operator naming an account that does not exist is answered USER_NOT_FOUND.
			_, err = chief.AdminSetRole(ctx, missing, "member")
			expect(err, 404, "USER_NOT_FOUND")
			_, err = chief.AdminUnbanUser(ctx, missing)
			expect(err, 404, "USER_NOT_FOUND")
			_, err = chief.AdminBanUser(ctx, missing, "", 0)
			expect(err, 404, "USER_NOT_FOUND")
			_, err = chief.AdminImpersonate(ctx, missing)
			expect(err, 404, "USER_NOT_FOUND")
			expect(chief.AdminRemoveUser(ctx, missing), 404, "USER_NOT_FOUND")
			expect(chief.AdminSetPassword(ctx, missing, "replacement-password"), 404, "USER_NOT_FOUND")
			expect(chief.AdminSetPassword(ctx, missing, "short"), 400, "PASSWORD_TOO_SHORT")
			_, err = chief.AdminUpdateUser(ctx, missing, map[string]any{"name": "Nobody"})
			expect(err, 404, "USER_NOT_FOUND")

			// Creation checks the role's type and name and the address, and stores the address in lower case.
			_, err = chief.AdminCreateUser(ctx, client.AdminCreateUserRequest{Name: "Typed", Email: "typed@example.test", Data: map[string]any{"role": []any{"member", 7}}})
			expect(err, 400, "INVALID_ROLE_TYPE")
			expect(chief.Do(ctx, http.MethodPost, "/admin/create-user", map[string]any{"name": "Typed", "email": "typed@example.test", "role": 7}, nil), 400, "VALIDATION_ERROR")
			_, err = chief.AdminCreateUser(ctx, client.AdminCreateUserRequest{Name: "Ghost", Email: "ghost@example.test", Role: []string{"ghost"}})
			expect(err, 400, "YOU_ARE_NOT_ALLOWED_TO_SET_NON_EXISTENT_VALUE")
			_, err = chief.AdminCreateUser(ctx, client.AdminCreateUserRequest{Name: "Invalid", Email: "not-an-email"})
			expect(err, 400, "INVALID_EMAIL")
			_, err = editor.AdminCreateUser(ctx, client.AdminCreateUserRequest{Name: "Typed", Email: "not-an-email", Data: map[string]any{"role": 7}})
			expect(err, 403, "YOU_ARE_NOT_ALLOWED_TO_CHANGE_USERS_ROLE")
			_, err = editor.AdminCreateUser(ctx, client.AdminCreateUserRequest{Name: "Banned", Email: "not-an-email", Data: map[string]any{"banned": true}})
			expect(err, 403, "YOU_ARE_NOT_ALLOWED_TO_BAN_USERS")
			mixed, err := chief.AdminCreateUser(ctx, client.AdminCreateUserRequest{Name: "Mixed", Email: "Mixed.Case@Example.TEST"})
			must(err)
			if mixed.Email != "mixed.case@example.test" || column(`SELECT "email" FROM "user" WHERE "id"=?`, mixed.ID) != "mixed.case@example.test" {
				t.Fatal("an administrator-created address was not stored in lower case")
			}
			_, err = chief.AdminCreateUser(ctx, client.AdminCreateUserRequest{Name: "Mixed", Email: "MIXED.case@example.test"})
			expect(err, 400, "USER_ALREADY_EXISTS_USE_ANOTHER_EMAIL")
			nameless, err := chief.AdminCreateUser(ctx, client.AdminCreateUserRequest{Name: "", Email: "nameless@example.test"})
			must(err)
			if nameless.Name != "" {
				t.Fatal("an empty name was not stored")
			}
			if count(`SELECT COUNT(*) FROM "user" WHERE "email" IN (?,?,?)`, "typed@example.test", "ghost@example.test", "not-an-email") != 0 {
				t.Fatal("a refused creation stored an account")
			}

			// Profile updates refuse empty data, unauthorized or malformed roles, self-bans and taken or malformed addresses.
			_, err = chief.AdminUpdateUser(ctx, plain.ID, map[string]any{})
			expect(err, 400, "NO_DATA_TO_UPDATE")
			_, err = editor.AdminUpdateUser(ctx, plain.ID, map[string]any{"role": "admin"})
			expect(err, 403, "YOU_ARE_NOT_ALLOWED_TO_CHANGE_USERS_ROLE")
			_, err = editor.AdminUpdateUser(ctx, plain.ID, map[string]any{"role": 7})
			expect(err, 403, "YOU_ARE_NOT_ALLOWED_TO_CHANGE_USERS_ROLE")
			_, err = chief.AdminUpdateUser(ctx, plain.ID, map[string]any{"role": 7})
			expect(err, 400, "INVALID_ROLE_TYPE")
			_, err = chief.AdminUpdateUser(ctx, chiefUser.ID, map[string]any{"banned": true})
			expect(err, 400, "YOU_CANNOT_BAN_YOURSELF")
			_, err = chief.AdminUpdateUser(ctx, plain.ID, map[string]any{"email": editorAccount.Email})
			expect(err, 400, "USER_ALREADY_EXISTS_USE_ANOTHER_EMAIL")
			_, err = chief.AdminUpdateUser(ctx, plain.ID, map[string]any{"email": "not-an-email"})
			expect(err, 400, "INVALID_EMAIL")
			must(chief.Do(ctx, http.MethodPost, "/admin/update-user", map[string]any{"userId": plain.ID, "role": "admin", "data": map[string]any{"name": "Plain"}}, nil))
			if column(`SELECT "role" FROM "user" WHERE "id"=?`, plain.ID) != "member" {
				t.Fatal("a top-level role changed the account on update-user")
			}
			if stored, err := chief.AdminGetUser(ctx, plain.ID); err != nil || stored.Email != "plain@example.test" || stored.Role != "member" {
				t.Fatal("a refused update changed the account", err)
			}
			banned, err := chief.AdminUpdateUser(ctx, memberAccount.User.ID, map[string]any{"banned": true})
			must(err)
			if active, err := member.GetSession(ctx); err != nil || !banned.Banned || active != nil || count(`SELECT COUNT(*) FROM "session" WHERE "userId"=?`, memberAccount.User.ID) != 0 {
				t.Fatal("a ban set through update-user left the account signed in", err)
			}
			_, err = chief.AdminUnbanUser(ctx, memberAccount.User.ID)
			must(err)

			// The default page holds 100 accounts and echoes no limit or offset; explicit bounds are echoed.
			for i := range 101 {
				must(store.SaveFixtureUser(ctx, testUser(fmt.Sprintf("bulk-%03d", i))))
			}
			total := count(`SELECT COUNT(*) FROM "user"`)
			var raw map[string]json.RawMessage
			must(chief.Do(ctx, http.MethodGet, "/admin/list-users", nil, &raw))
			var listed []authn.User
			var reported int
			must(json.Unmarshal(raw["users"], &listed))
			must(json.Unmarshal(raw["total"], &reported))
			_, limit := raw["limit"]
			_, offset := raw["offset"]
			if len(listed) != 100 || reported != total || limit || offset {
				t.Fatal("default user page", len(listed), reported, total, limit, offset)
			}
			page, err := chief.AdminListUsers(ctx, authn.AdminQuery{Limit: 2, Offset: 3})
			must(err)
			if page.Limit != 2 || page.Offset != 3 || page.Total != total || len(page.Users) != 2 || page.Users[0].ID != listed[3].ID {
				t.Fatal("explicit page bounds were not applied and echoed", page.Limit, page.Offset, len(page.Users))
			}

			// A ban without a reason or duration stores the default reason and the configured duration.
			var out struct {
				User authn.User `json:"user"`
			}
			must(chief.Do(ctx, http.MethodPost, "/admin/ban-user", map[string]string{"userId": deputy.ID}, &out))
			stored, err := chief.AdminGetUser(ctx, deputy.ID)
			must(err)
			for _, u := range []authn.User{out.User, *stored} {
				if !u.Banned || u.BanReason == nil || *u.BanReason != "No reason" || u.BanExpires == nil {
					t.Fatal("a ban without a reason did not store the default reason", u.BanReason)
				}
				if d := u.BanExpires.Sub(u.UpdatedAt); d < 2*time.Hour-time.Second || d > 2*time.Hour+time.Second {
					t.Fatal("a ban without a duration did not use the configured default", d)
				}
			}
			_, err = chief.AdminUnbanUser(ctx, deputy.ID)
			must(err)

			// Impersonation lasts one hour by default and protects only the configured roles.
			_, err = chief.AdminImpersonate(ctx, steward.ID)
			expect(err, 403, "YOU_CANNOT_IMPERSONATE_ADMINS")
			var mask authn.SessionResult
			headers, err := chief.DoWithHeaders(ctx, http.MethodPost, "/admin/impersonate-user", map[string]string{"userId": deputy.ID}, &mask)
			must(err)
			live, marked := 0, false
			for _, c := range (&http.Response{Header: headers}).Cookies() {
				if c.Name == strict.SessionCookie("x", false).Name && c.Value != "" && c.MaxAge >= 0 {
					live++
					if c.MaxAge != 0 || !c.Expires.IsZero() {
						t.Fatal("impersonation cookie outlives the browser session", c)
					}
				}
				marked = marked || strings.HasSuffix(c.Name, "dont_remember") && c.Value != ""
			}
			if live != 1 || !marked {
				t.Fatal("impersonation did not mark the browser session", live, marked)
			}
			if mask.Session.ImpersonatedBy == nil || *mask.Session.ImpersonatedBy != chiefUser.ID {
				t.Fatal("the impersonation session did not name the operator")
			}
			if d := mask.Session.ExpiresAt.Sub(mask.Session.CreatedAt); d < time.Hour-time.Second || d > time.Hour+time.Second {
				t.Fatal("an impersonation did not last the default hour", d)
			}
			restored, err := chief.AdminStopImpersonating(ctx)
			if err != nil || restored.User.ID != chiefUser.ID {
				t.Fatal("stopping the impersonation did not restore the operator", err)
			}
			// With AllowImpersonatingAdmins, the same operator impersonates a protected holder.
			permissive := browser(lenient, chiefJar)
			held, err := permissive.AdminImpersonate(ctx, steward.ID)
			if err != nil || held.User.ID != steward.ID || held.Session.ImpersonatedBy == nil || *held.Session.ImpersonatedBy != chiefUser.ID {
				t.Fatal("AllowImpersonatingAdmins did not admit a protected account", err)
			}
			_, err = permissive.AdminStopImpersonating(ctx)
			must(err)
			_, err = chief.AdminCreateUser(ctx, client.AdminCreateUserRequest{Name: "Warden", Email: "warden@example.test", Password: "warden-password", Role: []string{"warden"}})
			must(err)
			warden := browser(strict, newJar())
			_, err = warden.SignInEmail(ctx, client.SignInRequest{Email: "warden@example.test", Password: "warden-password"})
			must(err)
			if held, err := warden.AdminImpersonate(ctx, steward.ID); err != nil || held.User.ID != steward.ID {
				t.Fatal("a role granted impersonate-admins could not impersonate an administrator", err)
			}
			_, err = warden.AdminStopImpersonating(ctx)
			must(err)

			// Stopping from a direct session is refused, and stopping without a session is unauthorized.
			_, err = chief.AdminStopImpersonating(ctx)
			expect(err, 400, "")
			if err.Error() != "You are not impersonating anyone" {
				t.Fatal("a direct session's stop was not refused with its message", err)
			}
			_, err = guest.AdminStopImpersonating(ctx)
			expect(err, 401, "UNAUTHORIZED")

			// A permission check needs a permission set and a session.
			expect(guest.Do(ctx, http.MethodPost, "/admin/has-permission", map[string]any{}, nil), 400, "VALIDATION_ERROR")
			var single *authn.APIError
			if !errors.As(chief.Do(ctx, http.MethodPost, "/admin/has-permission", map[string]any{"permission": map[string][]string{"user": {"get"}}}, nil), &single) || single.Status != 400 {
				t.Fatal("a singular permission key was not refused", single)
			}
			_, err = guest.AdminHasPermission(ctx, authn.AdminPermissions{"user": {"get"}})
			expect(err, 401, "UNAUTHORIZED")
			if both, err := chief.AdminHasPermission(ctx, authn.AdminPermissions{"user": {"list"}, "session": {"list"}}); err != nil || !both {
				t.Fatal("a check of two granted resources failed", err)
			}
			if mixed, err := chief.AdminHasPermission(ctx, authn.AdminPermissions{"user": {"list"}, "session": {"impersonate"}}); err != nil || mixed {
				t.Fatal("a check with an undefined action on one resource passed", err)
			}

			// Password replacement enforces the length bounds and adds a credential to an account without one.
			expect(chief.AdminSetPassword(ctx, plain.ID, "short"), 400, "PASSWORD_TOO_SHORT")
			expect(chief.AdminSetPassword(ctx, plain.ID, strings.Repeat("p", 129)), 400, "PASSWORD_TOO_LONG")
			if count(`SELECT COUNT(*) FROM "account" WHERE "userId"=? AND "providerId"='credential'`, plain.ID) != 0 {
				t.Fatal("an account created without a password has a credential")
			}
			must(chief.AdminSetPassword(ctx, plain.ID, "plain-account-password"))
			login, err := browser(strict, newJar()).SignInEmail(ctx, client.SignInRequest{Email: plain.Email, Password: "plain-account-password"})
			if err != nil || login.User.ID != plain.ID || count(`SELECT COUNT(*) FROM "account" WHERE "userId"=? AND "providerId"='credential'`, plain.ID) != 1 {
				t.Fatal("an account without a credential did not receive one", err)
			}

			// Removing an account deletes its live sessions without a prior revocation.
			if active, err := editor.GetSession(ctx); err != nil || active == nil {
				t.Fatal("the editor is not signed in", err)
			}
			must(chief.AdminRemoveUser(ctx, editorAccount.ID))
			gone, err := editor.GetSession(ctx)
			if err != nil || gone != nil || count(`SELECT COUNT(*) FROM "session" WHERE "userId"=?`, editorAccount.ID) != 0 ||
				count(`SELECT COUNT(*) FROM "account" WHERE "userId"=?`, editorAccount.ID) != 0 || count(`SELECT COUNT(*) FROM "user" WHERE "id"=?`, editorAccount.ID) != 0 {
				t.Fatal("removing a signed-in account left its sessions or records", err)
			}
		})
	}
}
