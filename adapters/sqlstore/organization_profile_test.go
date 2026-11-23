package sqlstore

import (
	"errors"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	auth "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/authtest"
	"github.com/Plain-Org/plain-auth/client"
	org "github.com/Plain-Org/plain-auth/plugins/organization"
	"github.com/Plain-Org/plain-auth/schema"
)

func TestOrganizationProfile(t *testing.T) {
	for _, engine := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(engine, func(t *testing.T) {
			ctx := t.Context()
			must := func(e error) {
				t.Helper()
				if e != nil {
					t.Fatal(e)
				}
			}
			dsn := organizationTestDSN(t, engine)
			ddl, e := schema.Generate(engine, []string{"organization", "admin"})
			must(e)
			first, e := OpenWithSchema(ctx, engine, dsn, ddl)
			must(e)
			defer first.Close()
			second, e := Open(ctx, engine, dsn)
			must(e)
			defer second.Close()
			service, e := org.NewService(org.Options{Store: second})
			must(e)
			host := httptest.NewUnstartedServer(nil)
			base := "http://" + host.Listener.Addr().String()
			app, e := authtest.New(auth.Options{BaseURL: base, Store: first, Secret: strings.Repeat("t", 40), Plugins: []auth.Plugin{service.Plugin()}})
			must(e)
			host.Config.Handler = app.Auth
			host.Start()
			defer host.Close()
			type scope struct {
				user  auth.User
				login *authtest.LoginResult
				team  org.Organization
			}
			newGroup := func() scope {
				user, e := app.SaveUser(ctx, authtest.NewUser())
				must(e)
				login, e := app.Login(ctx, user.ID)
				must(e)
				team := authtest.NewOrganization("Team")
				must(first.CreateOrganization(ctx, team, org.Member{ID: user.ID, OrganizationID: team.ID, UserID: user.ID, Role: "owner", CreatedAt: user.CreatedAt}, login.Session.ID, false))
				return scope{user, login, team}
			}
			a, b := newGroup(), newGroup()
			jar, e := cookiejar.New(nil)
			must(e)
			u, e := url.Parse(base)
			must(e)
			jar.SetCookies(u, []*http.Cookie{app.Auth.SessionCookie(a.login.Token, true)})
			c, e := client.New(base, &http.Client{Jar: jar})
			must(e)
			name := "Shared"
			unique := "first-slug"
			got, e := c.UpdateOrganization(ctx, "", org.ProfileUpdate{Name: &name, Slug: &unique, Metadata: map[string]any{"visible": true}})
			must(e)
			if got.ID != a.team.ID || got.Name != name || got.Slug != unique || !strings.Contains(string(got.Metadata), "visible") {
				t.Fatal("unexpected organization update", got)
			}
			ok, e := c.CheckOrganizationSlug(ctx, a.team.Slug)
			if e != nil || !ok {
				t.Fatal("former slug still occupied", e)
			}
			_, e = c.CheckOrganizationSlug(ctx, b.team.Slug)
			var api *auth.APIError
			if !errors.As(e, &api) || api.Code != "ORGANIZATION_SLUG_ALREADY_TAKEN" {
				t.Fatal("occupied slug returned success", e)
			}
			_, e = c.UpdateOrganization(ctx, b.team.ID, org.ProfileUpdate{Name: &name})
			if !errors.As(e, &api) || api.Code != "USER_IS_NOT_A_MEMBER_OF_THE_ORGANIZATION" {
				t.Fatal("cross-tenant mutation", e)
			}
			target := "competing-slug"
			start := make(chan struct{})
			results := make(chan error, 2)
			rename := func(node *Store, sc scope) {
				<-start
				_, e := node.UpdateOrganizationProfile(ctx, sc.user.ID, sc.login.Token, sc.team.ID, org.ProfileUpdate{Slug: &target})
				results <- e
			}
			go rename(first, a)
			go rename(second, b)
			close(start)
			valid, taken := 0, 0
			for range 2 {
				if e := <-results; e == nil {
					valid++
				} else if errors.Is(e, org.ErrSlugTaken) {
					taken++
				} else {
					t.Fatal(e)
				}
			}
			if valid != 1 || taken != 1 {
				t.Fatal("slug did not have exactly one owner", valid, taken)
			}
			expires := time.Now().UTC().Truncate(time.Millisecond).Add(350 * time.Millisecond)
			_, e = first.db.ExecContext(ctx, first.bind(`UPDATE "session" SET "expiresAt"=? WHERE "id"=?`), first.date(expires), b.login.Session.ID)
			must(e)
			holder, e := first.beginMembershipChange(ctx)
			must(e)
			defer holder.Rollback()
			must(first.lockOrganization(ctx, holder, b.team.ID))
			pending := make(chan error, 1)
			go func() {
				_, e := second.UpdateOrganizationProfile(ctx, b.user.ID, b.login.Token, b.team.ID, org.ProfileUpdate{Name: &name})
				pending <- e
			}()
			select {
			case early := <-pending:
				t.Fatalf("profile write escaped the tenant lock: %v", early)
			case <-time.After(time.Until(expires) + 25*time.Millisecond):
			}
			must(holder.Commit())
			if e := <-pending; !errors.Is(e, org.ErrUnauthenticated) {
				t.Fatal("expired session wrote a profile after the tenant lock was released", e)
			}
			var storedName string
			must(first.db.QueryRowContext(ctx, first.bind(`SELECT "name" FROM "organization" WHERE "id"=?`), b.team.ID).Scan(&storedName))
			if storedName != b.team.Name {
				t.Fatal("failed transaction changed the stored profile")
			}
			must(first.DeleteSession(ctx, a.login.Token))
			if _, e := second.UpdateOrganizationProfile(ctx, a.user.ID, a.login.Token, a.team.ID, org.ProfileUpdate{Name: &name}); !errors.Is(e, org.ErrUnauthenticated) {
				t.Fatal("revoked session changed organization", e)
			}
		})
	}
}
