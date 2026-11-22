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

	auth "github.com/Plain-Auth/plain-auth"
	"github.com/Plain-Auth/plain-auth/client"
	org "github.com/Plain-Auth/plain-auth/plugins/organization"
	"github.com/Plain-Auth/plain-auth/schema"
)

func TestOrganizationMemberRole(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			ctx := t.Context()
			must := func(err error) {
				t.Helper()
				if err != nil {
					t.Fatal(err)
				}
			}
			problem := func(err error, code string) {
				t.Helper()
				var p *auth.APIError
				if !errors.As(err, &p) || p.Code != code {
					t.Fatalf("wanted %s, got %v", code, err)
				}
			}
			dsn := organizationTestDSN(t, dialect)
			ddl, err := schema.Generate(dialect, []string{"organization", "admin"})
			must(err)
			first, err := OpenWithSchema(ctx, dialect, dsn, ddl)
			must(err)
			t.Cleanup(func() { first.Close() })
			second, err := Open(ctx, dialect, dsn)
			must(err)
			t.Cleanup(func() { second.Close() })
			service, err := org.NewService(org.Options{Store: first})
			must(err)
			now := time.Now().UTC().Truncate(time.Millisecond)
			session := func(user string) auth.Session {
				return auth.Session{ID: user + "-s", UserID: user, Token: user + "-t", CreatedAt: now, UpdatedAt: now, ExpiresAt: now.Add(time.Hour)}
			}
			for _, user := range []string{"Owner", "Peer", "Observer"} {
				must(first.CreateUser(ctx, auth.User{ID: user, Email: strings.ToLower(user) + "@example.test", Name: user, CreatedAt: now, UpdatedAt: now}, "", &auth.StoredSession{Session: session(user)}))
			}
			group := func(id, peerRole string) {
				t.Helper()
				member := func(user, role string) org.Member {
					return org.Member{ID: id + "-" + user, OrganizationID: id, UserID: user, Role: role, CreatedAt: now}
				}
				must(first.CreateOrganization(ctx, org.Organization{ID: id, Name: id, Slug: strings.ToLower(id), CreatedAt: now}, member("Owner", "owner"), session("Owner").ID, false))
				must(first.AddOrganizationMember(ctx, member("Peer", peerRole), ""))
			}
			request := func(group, user, role string) org.UpdateMemberRoleRequest {
				return org.UpdateMemberRoleRequest{OrganizationID: group, MemberID: group + "-" + user, Roles: []string{role}}
			}
			group("North", "admin")
			group("South", "member")
			host := httptest.NewUnstartedServer(nil)
			base := "http://" + host.Listener.Addr().String()
			instance, err := auth.New(auth.Options{Store: second, BaseURL: base, Secret: strings.Repeat("R", 32), Plugins: []auth.Plugin{service.Plugin()}})
			must(err)
			host.Config.Handler = instance
			host.Start()
			t.Cleanup(host.Close)
			jar, err := cookiejar.New(nil)
			must(err)
			u, err := url.Parse(base)
			must(err)
			jar.SetCookies(u, []*http.Cookie{instance.SessionCookie(session("Owner").Token, true)})
			sdk, err := client.New(base, &http.Client{Jar: jar})
			must(err)
			change := request("North", "Peer", "admin")
			change.Roles = []string{"member, admin", "admin"}
			got, err := sdk.UpdateOrganizationMemberRole(ctx, change)
			must(err)
			if got.Role != "member,admin,admin" || got.ID != "North-Peer" || got.UserID != "Peer" {
				t.Fatalf("HTTP client member shape: %+v", got)
			}
			raw := func(store *Store, user, token string, r org.UpdateMemberRoleRequest) error {
				_, err := store.UpdateOrganizationMemberRole(ctx, user, token, r)
				return err
			}
			problem(raw(first, "owner", "Owner-t", change), "UNAUTHORIZED")
			problem(raw(first, "Owner", "owner-t", change), "UNAUTHORIZED")
			change.OrganizationID = "north"
			problem(raw(first, "Owner", "Owner-t", change), "MEMBER_NOT_FOUND")
			change.OrganizationID = "South"
			problem(raw(first, "Owner", "Owner-t", change), "YOU_ARE_NOT_ALLOWED_TO_UPDATE_THIS_MEMBER")
			change.OrganizationID = "North"
			change.MemberID = "north-peer"
			problem(raw(first, "Owner", "Owner-t", change), "MEMBER_NOT_FOUND")
			change.MemberID = "North-Peer"
			problem(raw(first, "Observer", "Observer-t", change), "MEMBER_NOT_FOUND")
			delegated := session("Peer")
			delegated.ID = "delegated"
			delegated.Token = "delegated-token"
			operator := "Owner"
			delegated.ImpersonatedBy = &operator
			must(first.CreateSession(ctx, auth.StoredSession{Session: delegated}))
			problem(raw(second, "Peer", delegated.Token, change), "UNAUTHORIZED")
			stale := session("Peer")
			stale.ID = "stale"
			stale.Token = "stale-token"
			must(first.CreateSession(ctx, auth.StoredSession{Session: stale}))
			must(first.DeleteSession(ctx, stale.Token))
			problem(raw(second, "Peer", stale.Token, change), "UNAUTHORIZED")
			_, err = first.db.ExecContext(ctx, first.bind(`UPDATE "user" SET "banned"=? WHERE "id"=?`), true, "Peer")
			must(err)
			problem(raw(second, "Peer", "Peer-t", change), "BANNED_USER")
			_, err = first.db.ExecContext(ctx, first.bind(`UPDATE "user" SET "banned"=? WHERE "id"=?`), false, "Peer")
			must(err)

			// Promoting another owner and then demoting yourself transfers control.
			_, err = service.UpdateMemberRole(ctx, session("Owner"), request("North", "Peer", " owner, member "))
			must(err)
			_, err = service.UpdateMemberRole(ctx, session("Owner"), request("North", "Owner", "member"))
			must(err)
			problem(raw(second, "Owner", "Owner-t", request("North", "Peer", "admin")), "YOU_ARE_NOT_ALLOWED_TO_UPDATE_THIS_MEMBER")
			problem(raw(second, "Peer", "Peer-t", request("North", "Peer", "member")), "YOU_CANNOT_LEAVE_THE_ORGANIZATION_WITHOUT_AN_OWNER")

			// Count and authorize inside the same tenant lock as removals. Both
			// stores have independent pools and are opened on the same database.
			for _, mode := range []string{"Self", "Opposed", "Removal"} {
				group(mode, "owner")
				gate := make(chan struct{})
				results := make(chan error, 2)
				go func() {
					<-gate
					if mode == "Opposed" {
						results <- raw(first, "Owner", "Owner-t", request(mode, "Peer", "member"))
						return
					}
					results <- raw(first, "Owner", "Owner-t", request(mode, "Owner", "member"))
				}()
				go func() {
					<-gate
					switch mode {
					case "Opposed":
						results <- raw(second, "Peer", "Peer-t", request(mode, "Owner", "member"))
					case "Removal":
						_, e := second.LeaveOrganization(ctx, "Peer", "Peer-t", mode)
						results <- e
					default:
						results <- raw(second, "Peer", "Peer-t", request(mode, "Peer", "member"))
					}
				}()
				close(gate)
				a, b := <-results, <-results
				if a != nil {
					a, b = b, a
				}
				must(a)
				if !errors.Is(b, org.ErrSoleOwnerDemotion) && !errors.Is(b, org.ErrLastOwner) && !errors.Is(b, org.ErrMemberRoleDenied) {
					t.Fatalf("%s lost transactional authorization: %v", mode, b)
				}
				var owners int
				must(first.db.QueryRowContext(ctx, first.bind(`SELECT COUNT(*) FROM "member" WHERE "organizationId"=? AND "role"='owner'`), mode).Scan(&owners))
				if owners != 1 {
					t.Fatalf("concurrent membership changes left %d owners in %s", owners, mode)
				}
			}
		})
	}
}
