package sqlstore

import (
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	auth "github.com/Plain-Auth/plain-auth"
	"github.com/Plain-Auth/plain-auth/client"
	"github.com/Plain-Auth/plain-auth/plugins/customsession"
	jwtplugin "github.com/Plain-Auth/plain-auth/plugins/jwt"
	"github.com/Plain-Auth/plain-auth/plugins/multisession"
	"github.com/Plain-Auth/plain-auth/schema"
)

func TestCustomSessionLiveSQLVisibility(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			ctx := t.Context()
			must := func(err error) {
				t.Helper()
				if err != nil {
					t.Fatal(err)
				}
			}
			dsn := organizationTestDSN(t, dialect)
			open := func(profiles ...string) *Store {
				ddl, err := schema.Generate(dialect, profiles)
				must(err)
				store, err := OpenWithSchema(ctx, dialect, dsn, ddl)
				must(err)
				t.Cleanup(func() { store.Close() })
				return store
			}
			cold := open("jwt")
			jwt, err := jwtplugin.New(jwtplugin.Options{})
			must(err)
			multi, err := multisession.New(multisession.Options{})
			must(err)
			type projection struct{ Viewer, Role string }
			view, err := customsession.NewWithOptions(func(c auth.EndpointContext, data auth.SessionResult) (any, error) {
				c.ResponseHeader.Set("Set-Auth-Jwt", "application-placeholder")
				c.ResponseHeader.Set("Access-Control-Expose-Headers", "application-placeholder")
				role := ""
				if data.User.AdminUserFields != nil {
					role = data.User.Role
				}
				return projection{data.User.Email, role}, nil
			}, customsession.Options{ProjectDeviceSessions: true})
			must(err)
			const origin = "https://project.example"
			options := auth.Options{BaseURL: origin, Secret: strings.Repeat("s", 32), Store: cold, EmailAndPassword: true, Plugins: []auth.Plugin{view, multi, jwt}}
			host, err := auth.New(options)
			must(err)
			jar, err := cookiejar.New(nil)
			must(err)
			browser, err := client.New(origin+"/api/auth", &http.Client{Transport: guestTransport{host}, Jar: jar})
			must(err)
			options.Plugins = []auth.Plugin{multi, jwt}
			ordinary, err := auth.New(options)
			must(err)
			plain, err := client.New(origin+"/api/auth", &http.Client{Transport: guestTransport{ordinary}, Jar: jar})
			must(err)
			signup := func(name string) *client.EmailResult {
				account, err := browser.SignUpEmail(ctx, client.SignUpRequest{Name: name, Email: name + "@example.test", Password: "valid-fixture-password"})
				must(err)
				return account
			}
			alice, bob := signup("alice"), signup("bob")
			for _, handler := range []*auth.Auth{ordinary, host} {
				req := httptest.NewRequest("GET", origin+"/api/auth/get-session", nil)
				req.AddCookie(handler.SessionCookie(*alice.Token, true))
				rec := httptest.NewRecorder()
				rec.Header().Set("X-Deployment", "public-auth")
				rec.Header().Set("Access-Control-Expose-Headers", "ETag")
				handler.ServeHTTP(rec, req)
				if rec.Code != 200 || strings.Count(rec.Header().Get("Set-Auth-Jwt"), ".") != 2 || strings.Join(rec.Header().Values("Access-Control-Expose-Headers"), ",") != "ETag,set-auth-jwt" || rec.Header().Get("X-Deployment") != "public-auth" {
					t.Fatal("authoritative JWT or deployment headers changed by the session view")
				}
			}
			before, err := client.ListDeviceSessionViews[projection](ctx, browser)
			must(err)
			if len(before) != 2 {
				t.Fatal("two remembered accounts missing before migration")
			}
			managed := open("admin")
			update := func(query string, args ...any) {
				_, err := managed.db.ExecContext(ctx, managed.bind(query), args...)
				must(err)
			}
			update(`UPDATE "user" SET "role"=? WHERE "id"=?`, "editor", alice.User.ID)
			update(`UPDATE "user" SET "banned"=? WHERE "id"=?`, true, bob.User.ID)
			ordinaryList, err := plain.ListDeviceSessions(ctx)
			must(err)
			if len(ordinaryList) != 1 || ordinaryList[0].User.ID != alice.User.ID || ordinaryList[0].User.AdminUserFields == nil || ordinaryList[0].User.Role != "editor" {
				t.Fatal("ordinary device list ignored live SQL visibility", ordinaryList)
			}
			removed, err := client.GetSessionView[projection](ctx, browser)
			must(err)
			if removed != nil {
				t.Fatal("the banned active account still had a projection")
			}
			remaining, err := client.ListDeviceSessionViews[projection](ctx, browser)
			must(err)
			if len(remaining) != 1 || remaining[0] != (projection{alice.User.Email, "editor"}) {
				t.Fatal("remembered projection ignored live SQL visibility", remaining)
			}
			// A bound delegated login becomes invisible when its original session disappears.
			now := time.Now().UTC().Truncate(time.Millisecond)
			delegated := auth.StoredSession{Session: auth.Session{ID: "delegated", Token: "delegate-token", UserID: alice.User.ID, CreatedAt: now, UpdatedAt: now, ExpiresAt: now.Add(time.Hour)}}
			must(managed.CreateSession(ctx, delegated))
			var sourceID string
			must(managed.db.QueryRowContext(ctx, managed.bind(`SELECT "id" FROM "session" WHERE "token"=?`), *alice.Token).Scan(&sourceID))
			update(`UPDATE "session" SET "impersonatedBy"=? WHERE "id"=?`, alice.User.ID, delegated.ID)
			update(`INSERT INTO "verification" ("id","identifier","value","expiresAt","createdAt","updatedAt") VALUES (?,?,?,?,?,?)`, adminDelegationKey(delegated.ID), "admin-delegation", sourceID, managed.date(now.Add(time.Hour)), managed.date(now), managed.date(now))
			rows, err := cold.DeviceSessions(ctx, []string{delegated.Token}, now)
			must(err)
			if rr, ok := rows[delegated.Token]; !ok || rr.Session.ImpersonatedBy == nil || *rr.Session.ImpersonatedBy != alice.User.ID {
				t.Fatal("remembered delegation lost its source identity")
			}
			update(`DELETE FROM "session" WHERE "id"=?`, sourceID)
			rows, err = cold.DeviceSessions(ctx, []string{delegated.Token}, now)
			must(err)
			if len(rows) != 0 {
				t.Fatal("remembered session survived its delegation source")
			}
		})
	}
}
