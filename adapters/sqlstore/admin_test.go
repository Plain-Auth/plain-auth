package sqlstore

import (
	"errors"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	authn "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/client"
	"github.com/Plain-Org/plain-auth/plugins/admin"
	"github.com/Plain-Org/plain-auth/plugins/bearer"
	"github.com/Plain-Org/plain-auth/schema"
)

func TestAdminLifecycleAcrossEngines(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			ctx := t.Context()
			must := func(err error) {
				t.Helper()
				if err != nil {
					t.Fatal(err)
				}
			}
			expect := func(err error, code string) {
				t.Helper()
				var api *authn.APIError
				if !errors.As(err, &api) || api.Code != code {
					t.Fatalf("expected %s, got %v", code, err)
				}
			}
			dsn := organizationTestDSN(t, dialect)
			ddl, err := schema.Generate(dialect, []string{"admin"})
			must(err)
			store, err := OpenWithSchema(ctx, dialect, dsn, ddl)
			must(err)
			defer store.Close()
			other, err := Open(ctx, dialect, dsn)
			must(err)
			defer other.Close()
			makeOptions := func() admin.Options {
				return admin.Options{AdminUserIDs: []string{"bootstrap-admin"}, DefaultBanReason: "Account review", BannedUserMessage: "Account access suspended", ImpersonationSessionDuration: 5 * time.Minute,
					Roles: map[string]authn.AdminPermissions{"user": {}, "admin": {"user": {"list", "get", "create", "update", "set-email", "set-role", "ban", "delete", "set-password", "impersonate"}, "session": {"list", "revoke"}},
						"operator": {"user": {"create", "update", "list"}}, "reader": {"user": {"get"}, "session": {"list"}}},
				}
			}
			p, err := admin.New(makeOptions())
			must(err)
			srv := httptest.NewUnstartedServer(nil)
			origin := "http://" + srv.Listener.Addr().String()
			immediate := time.Duration(0)
			limit := false
			service, err := authn.New(authn.Options{BaseURL: origin, Secret: strings.Repeat("a", 32), Store: store, Plugins: []authn.Plugin{p, bearer.New(bearer.Options{})}, EmailAndPassword: true, RateLimit: &limit, SessionUpdateAge: &immediate})
			must(err)
			srv.Config.Handler = service
			srv.Start()
			defer srv.Close()
			makeBrowser := func() (*client.Client, http.CookieJar) {
				jar, err := cookiejar.New(nil)
				must(err)
				c, err := client.New(origin, &http.Client{Jar: jar})
				must(err)
				return c, jar
			}
			bootstrap, jar := makeBrowser()
			// The configured bootstrap ID can administer users without first granting a database role.
			u := testUser("bootstrap-admin")
			ss := testSession(u, "bootstrap-session")
			ss.ExpiresAt = time.Now().Add(time.Hour)
			must(store.CreateUser(ctx, u, "unused", &ss))
			base, err := url.Parse(origin)
			must(err)
			jar.SetCookies(base, []*http.Cookie{service.SessionCookie(ss.Token, true)})
			grant, err := bootstrap.AdminHasPermission(ctx, authn.AdminPermissions{"user": {"get", "impersonate-admins"}})
			must(err)
			if !grant {
				t.Fatal("configured admin ID lacks grants")
			}
			guest, _ := makeBrowser()
			_, err = guest.AdminListUsers(ctx, authn.AdminQuery{})
			expect(err, "UNAUTHORIZED")
			userBrowser, _ := makeBrowser()
			registered, err := userBrowser.SignUpEmail(ctx, client.SignUpRequest{Name: "Ordinary", Email: "member@example.test", Password: "sample-ordinary-password"})
			must(err)
			if registered.User.AdminUserFields == nil || registered.User.Role != "user" || registered.User.Banned {
				t.Fatal("regular signup did not receive its default role")
			}
			target := registered.User.ID
			_, err = userBrowser.AdminGetUser(ctx, u.ID)
			expect(err, "YOU_ARE_NOT_ALLOWED_TO_GET_USER")
			check, err := userBrowser.AdminHasPermission(ctx, authn.AdminPermissions{"user": {"list"}})
			must(err)
			if check {
				t.Fatal("public role received user listing")
			}
			officer, err := bootstrap.AdminCreateUser(ctx, client.AdminCreateUserRequest{Name: "Officer", Email: "officer@example.test", Role: []string{"admin"}, Password: "officer-password-sample"})
			must(err)
			operator, err := bootstrap.AdminCreateUser(ctx, client.AdminCreateUserRequest{Name: "Operator", Email: "operator@example.test", Role: []string{"operator", "reader"}, Password: "operator-password-sample"})
			must(err)
			adminBrowser, officerJar := makeBrowser()
			remember := false
			authenticated, err := adminBrowser.SignInEmail(ctx, client.SignInRequest{Email: officer.Email, Password: "officer-password-sample", RememberMe: &remember})
			must(err)
			staff, _ := makeBrowser()
			_, err = staff.SignInEmail(ctx, client.SignInRequest{Email: operator.Email, Password: "operator-password-sample"})
			must(err)
			protectedSessions, err := staff.AdminListUserSessions(ctx, officer.ID)
			must(err)
			if len(protectedSessions) != 1 || protectedSessions[0].Token == "" || protectedSessions[0].Token == *authenticated.Token {
				t.Fatal("administrative listing exposed a protected account credential")
			}
			handle := protectedSessions[0].Token
			headers := http.Header{"Authorization": []string{"Bearer " + handle}}
			identity, err := service.GetSession(ctx, headers)
			must(err)
			if identity != nil {
				t.Fatal("revocation handle authenticated as a bearer credential")
			}
			expect(staff.AdminRevokeSession(ctx, handle), "YOU_ARE_NOT_ALLOWED_TO_REVOKE_USERS_SESSIONS")
			expect(bootstrap.AdminRevokeSession(ctx, handle), "VALIDATION_ERROR")
			stillActive, err := adminBrowser.GetSession(ctx)
			must(err)
			if stillActive == nil || stillActive.User.ID != officer.ID {
				t.Fatal("revocation handle escaped its operator binding")
			}
			_, err = staff.AdminGetUser(ctx, target)
			must(err)
			both, err := staff.AdminHasPermission(ctx, authn.AdminPermissions{"user": {"create", "get"}})
			must(err)
			if both {
				t.Fatal("partial role grants combined unexpectedly")
			}
			emptyResource, err := staff.AdminHasPermission(ctx, authn.AdminPermissions{"user": {"get"}, "session": {}})
			must(err)
			if emptyResource {
				t.Fatal("empty resource requirement granted administrative access")
			}
			_, err = staff.AdminCreateUser(ctx, client.AdminCreateUserRequest{Name: "Limited", Email: "limited@example.test", Data: map[string]any{"role": "admin"}})
			expect(err, "YOU_ARE_NOT_ALLOWED_TO_CHANGE_USERS_ROLE")
			_, err = staff.AdminUpdateUser(ctx, target, map[string]any{"emailVerified": true})
			expect(err, "YOU_ARE_NOT_ALLOWED_TO_SET_USERS_EMAIL")
			_, err = staff.AdminUpdateUser(ctx, target, map[string]any{"banned": true})
			expect(err, "YOU_ARE_NOT_ALLOWED_TO_BAN_USERS")
			_, err = staff.AdminUpdateUser(ctx, target, map[string]any{"id": "bootstrap-admin"})
			expect(err, "USER_ID_CANNOT_BE_UPDATED")
			_, err = staff.AdminUpdateUser(ctx, target, map[string]any{"password": "example"})
			expect(err, "PASSWORD_CANNOT_BE_UPDATED_VIA_UPDATE_USER")
			_, err = adminBrowser.AdminSetRole(ctx, target, "unknown")
			expect(err, "YOU_ARE_NOT_ALLOWED_TO_SET_NON_EXISTENT_VALUE")
			profile, err := adminBrowser.AdminUpdateUser(ctx, target, map[string]any{"name": "Renamed", "email": "MEMBER@example.test", "image": "https://example.test/image", "emailVerified": true})
			must(err)
			if profile.Name != "Renamed" || profile.Email != "member@example.test" || !profile.EmailVerified {
				t.Fatal("admin profile fields not updated")
			}
			page, err := adminBrowser.AdminListUsers(ctx, authn.AdminQuery{SearchField: "email", SearchValue: "@example.test", FilterField: "role", FilterValues: []string{"operator,reader", "admin"}, FilterOperator: "in", SortBy: "name", SortDirection: "desc", Limit: 1, Offset: 1})
			must(err)
			if page.Total != 2 || len(page.Users) != 1 || page.Users[0].ID != officer.ID {
				t.Fatal("admin search/filter/pagination", page)
			}
			_, err = adminBrowser.AdminBanUser(ctx, officer.ID, "", time.Hour)
			expect(err, "YOU_CANNOT_BAN_YOURSELF")
			banned, err := adminBrowser.AdminBanUser(ctx, target, "", time.Hour)
			must(err)
			if !banned.Banned || banned.BanExpires == nil || banned.BanReason == nil || *banned.BanReason != "Account review" {
				t.Fatal("temporary ban fields")
			}
			active, err := userBrowser.GetSession(ctx)
			must(err)
			if active != nil {
				t.Fatal("existing session survived ban")
			}
			_, err = userBrowser.SignInEmail(ctx, client.SignInRequest{Email: profile.Email, Password: "sample-ordinary-password"})
			expect(err, "BANNED_USER")
			if err.Error() != "Account access suspended" {
				t.Fatal("expected configured ban message", err)
			}
			_, err = userBrowser.SignInEmail(ctx, client.SignInRequest{Email: profile.Email, Password: "arbitrary-invalid-password"})
			expect(err, "INVALID_EMAIL_OR_PASSWORD")
			raw := testSession(*profile, "direct-denied")
			raw.ExpiresAt = time.Now().Add(time.Hour)
			expect(other.CreateSession(ctx, raw), "BANNED_USER")
			banned, err = adminBrowser.AdminBanUser(ctx, target, "Permanent", 0)
			must(err)
			if banned.BanExpires != nil {
				t.Fatal("permanent ban retained previous expiry")
			}
			_, err = adminBrowser.AdminUnbanUser(ctx, target)
			must(err)
			must(adminBrowser.AdminSetPassword(ctx, target, "replacement-password"))
			signed, err := userBrowser.SignInEmail(ctx, client.SignInRequest{Email: profile.Email, Password: "replacement-password"})
			must(err)
			found, err := adminBrowser.AdminListUserSessions(ctx, target)
			must(err)
			if len(found) != 1 || found[0].Token == "" || found[0].Token == *signed.Token {
				t.Fatal("admin session listing")
			}
			expect(adminBrowser.AdminRevokeSession(ctx, found[0].Token+"x"), "VALIDATION_ERROR")
			must(adminBrowser.AdminRevokeSession(ctx, found[0].Token))
			active, err = userBrowser.GetSession(ctx)
			must(err)
			if active != nil {
				t.Fatal("revoked target still signed in")
			}
			_, err = adminBrowser.AdminImpersonate(ctx, u.ID)
			expect(err, "YOU_CANNOT_IMPERSONATE_ADMINS")
			mask, err := adminBrowser.AdminImpersonate(ctx, target)
			must(err)
			if mask.Session.ImpersonatedBy == nil || *mask.Session.ImpersonatedBy != officer.ID {
				t.Fatal("delegated session has no owner")
			}
			if delta := mask.Session.ExpiresAt.Sub(mask.Session.CreatedAt); delta < 5*time.Minute-time.Second || delta > 5*time.Minute+time.Second {
				t.Fatal("delegated session duration differs from policy", delta)
			}
			held, err := adminBrowser.GetSession(ctx)
			must(err)
			if held.Session.Token != mask.Session.Token || !held.Session.ExpiresAt.Equal(mask.Session.ExpiresAt) {
				t.Fatal("impersonation extended on session refresh")
			}
			_, err = adminBrowser.ListSessions(ctx)
			expect(err, "OWNER_SESSION_REQUIRED")
			_, err = adminBrowser.AdminGetUser(ctx, officer.ID)
			expect(err, "FORBIDDEN")
			restored, err := adminBrowser.AdminStopImpersonating(ctx)
			must(err)
			if restored.User.ID != officer.ID || restored.Session.Token != *authenticated.Token {
				t.Fatal("failed to restore original login")
			}
			if _, _, err = store.Session(ctx, mask.Session.Token); !errors.Is(err, authn.ErrNotFound) {
				t.Fatal("stopped delegated login still usable")
			}
			hasShort := false
			for _, cookie := range officerJar.Cookies(base) {
				if cookie.Name == "authn.dont_remember" {
					hasShort = true
				}
				if cookie.Name == "authn.admin_session" {
					t.Fatal("return cookie not cleared")
				}
			}
			if !hasShort {
				t.Fatal("original login persistence lost")
			}
			// An explicitly authorized operator can impersonate another administrator.
			adminMask, err := bootstrap.AdminImpersonate(ctx, officer.ID)
			must(err)
			if adminMask.User.ID != officer.ID {
				t.Fatal("wrong administrator impersonated")
			}
			delegatedGrant, err := bootstrap.AdminHasPermission(ctx, authn.AdminPermissions{"user": {"get"}})
			must(err)
			if delegatedGrant {
				t.Fatal("delegation inherited administrative grants")
			}
			_, err = bootstrap.AdminStopImpersonating(ctx)
			must(err)
			// Revoking the original session on another browser invalidates its delegated login.
			_, err = adminBrowser.AdminImpersonate(ctx, target)
			must(err)
			must(bootstrap.AdminRevokeSession(ctx, *authenticated.Token))
			abandoned, err := adminBrowser.GetSession(ctx)
			must(err)
			if abandoned != nil {
				t.Fatal("delegated login survived revocation of its original session")
			}
			// A concurrent normal session creation either precedes the ban and is revoked, or observes the ban and fails.
			start := make(chan struct{})
			var group sync.WaitGroup
			group.Go(func() {
				<-start
				_, err := bootstrap.AdminBanUser(ctx, target, "Concurrent", time.Minute)
				if err != nil {
					t.Error(err)
				}
			})
			group.Go(func() {
				<-start
				err := other.CreateSession(ctx, raw)
				if err != nil {
					expect(err, "BANNED_USER")
				}
			})
			close(start)
			group.Wait()
			var n int
			must(other.db.QueryRowContext(ctx, other.bind(`SELECT COUNT(*) FROM "session" WHERE "userId"=?`), target).Scan(&n))
			if n != 0 {
				t.Fatal("new session survived concurrent ban")
			}
			past := time.Now().Add(-time.Hour)
			_, err = other.db.ExecContext(ctx, other.bind(`UPDATE "user" SET "banExpires"=? WHERE "id"=?`), other.date(past), target)
			must(err)
			_, err = userBrowser.SignInEmail(ctx, client.SignInRequest{Email: profile.Email, Password: "replacement-password"})
			must(err)
			unbanned, err := bootstrap.AdminGetUser(ctx, target)
			must(err)
			if unbanned.Banned || unbanned.BanExpires != nil || unbanned.BanReason != nil {
				t.Fatal("expired ban not cleared during login")
			}
			must(bootstrap.AdminRevokeUserSessions(ctx, target))
			must(bootstrap.AdminRemoveUser(ctx, target))
			_, err = bootstrap.AdminGetUser(ctx, target)
			expect(err, "USER_NOT_FOUND")
			expect(bootstrap.AdminRemoveUser(ctx, u.ID), "YOU_CANNOT_REMOVE_YOURSELF")
		})
	}
}

func TestFirstAdminProvisioningRace(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			ctx := t.Context()
			dsn := organizationTestDSN(t, dialect)
			ddl, err := schema.Generate(dialect, []string{"admin"})
			if err != nil {
				t.Fatal(err)
			}
			a, err := OpenWithSchema(ctx, dialect, dsn, ddl)
			if err != nil {
				t.Fatal(err)
			}
			defer a.Close()
			b, err := OpenForAdminBootstrap(ctx, dialect, dsn)
			if err != nil {
				t.Fatal(err)
			}
			defer b.Close()
			existing := testUser("member")
			if err := a.CreateUser(ctx, existing, "hash", nil); err != nil {
				t.Fatal(err)
			}
			_, err = authn.BootstrapAdmin(ctx, a, "Existing", existing.Email, "initial-admin-password-phrase")
			if !errors.Is(err, authn.ErrEmailTaken) {
				t.Fatal("existing account was eligible for promotion", err)
			}
			start := make(chan struct{})
			results := make(chan error, 2)
			for i, store := range []*Store{a, b} {
				go func() {
					<-start
					_, err := authn.BootstrapAdmin(ctx, store, "Operations", []string{"one@example.test", "two@example.test"}[i], "initial-admin-password-phrase")
					results <- err
				}()
			}
			close(start)
			winners := 0
			for range 2 {
				err := <-results
				if err == nil {
					winners++
				} else if !errors.Is(err, authn.ErrAdminExists) {
					t.Fatal(err)
				}
			}
			if winners != 1 {
				t.Fatalf("concurrent bootstrap created %d administrators", winners)
			}
			var admins, locks, accounts int
			if err := a.db.QueryRowContext(ctx, a.bind(`SELECT COUNT(*) FROM "user" WHERE "role"='admin'`)).Scan(&admins); err != nil {
				t.Fatal(err)
			}
			if err := a.db.QueryRowContext(ctx, a.bind(`SELECT COUNT(*) FROM "verification" WHERE "id"='authn-create-first-admin'`)).Scan(&locks); err != nil {
				t.Fatal(err)
			}
			if err := a.db.QueryRowContext(ctx, a.bind(`SELECT COUNT(*) FROM "account"`)).Scan(&accounts); err != nil {
				t.Fatal(err)
			}
			if admins != 1 || locks != 0 || accounts != 2 {
				t.Fatal("bootstrap left partial or duplicate records")
			}
		})
	}
}
