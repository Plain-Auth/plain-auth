package sqlstore

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	auth "github.com/Plain-Org/plain-auth"
	org "github.com/Plain-Org/plain-auth/plugins/organization"
	"github.com/Plain-Org/plain-auth/schema"
)

// Run the member role hooks around POST /organization/update-member-role.
func TestOrganizationMemberRoleHooks(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
			defer cancel()
			must := func(err error) {
				t.Helper()
				if err != nil {
					t.Fatal(err)
				}
			}
			code := func(err error, status int, want string) {
				t.Helper()
				var problem *auth.APIError
				if !errors.As(err, &problem) || problem.Status != status || problem.Code != want {
					t.Fatalf("want %d %s, got %v", status, want, err)
				}
			}
			dsn := organizationTestDSN(t, dialect)
			store, err := OpenWithOptions(ctx, dialect, dsn, []string{"organization"}, schema.Options{})
			must(err)
			t.Cleanup(func() { store.Close() })
			role := func(id string) string {
				t.Helper()
				var r string
				must(store.db.QueryRowContext(ctx, store.bind(`SELECT "role" FROM "member" WHERE "id"=?`), id).Scan(&r))
				return r
			}
			now := time.Now().UTC().Truncate(time.Millisecond)
			account := func(id string) auth.Session {
				t.Helper()
				user := auth.User{ID: id, Name: id, Email: id + "@example.test", CreatedAt: now, UpdatedAt: now}
				session := auth.StoredSession{Session: auth.Session{ID: id + "-s", Token: id + "-t", UserID: id, CreatedAt: now, UpdatedAt: now, ExpiresAt: now.Add(time.Hour)}}
				must(store.CreateUser(ctx, user, "", &session))
				return session.Session
			}
			ada, lin, max := account("Ada"), account("Lin"), account("Max")
			group := org.Organization{ID: "Acme", Name: "Acme", Slug: "acme", CreatedAt: now}
			must(store.CreateOrganization(ctx, group, org.Member{ID: "ada-m", UserID: ada.UserID, OrganizationID: group.ID, Role: "owner", CreatedAt: now}, ada.ID, false))
			for _, m := range []org.Member{{ID: "lin-m", UserID: lin.UserID, Role: "admin"}, {ID: "max-m", UserID: max.UserID, Role: "member"}} {
				m.OrganizationID, m.CreatedAt = group.ID, now
				must(store.AddOrganizationMember(ctx, m, ""))
			}
			var mu sync.Mutex
			var events []string
			record := func(e string) { mu.Lock(); events = append(events, e); mu.Unlock() }
			seen := func() string { mu.Lock(); defer mu.Unlock(); s := strings.Join(events, ","); events = nil; return s }
			var override *org.MemberOverride
			var beforeErr, afterErr error
			service, err := org.NewService(org.Options{
				Store: store,
				BeforeUpdateMemberRole: func(_ context.Context, in org.BeforeMemberRoleUpdate) (*org.MemberOverride, error) {
					record("before:" + in.Member.ID + ":" + in.Member.Role + "->" + in.NewRole + ":" + in.User.Email + ":" + in.Organization.Slug)
					return override, beforeErr
				},
				AfterUpdateMemberRole: func(_ context.Context, in org.AfterMemberRoleUpdate) error {
					record("after:" + in.Member.ID + ":" + in.PreviousRole + "->" + in.Member.Role + ":" + in.User.ID)
					return afterErr
				},
			})
			must(err)
			update := func(s auth.Session, member string, roles ...string) (*org.Member, error) {
				return organizationRoleClient(t, store, service, s).UpdateOrganizationMemberRole(ctx, org.UpdateMemberRoleRequest{OrganizationID: group.ID, MemberID: member, Roles: roles})
			}

			// Both hooks see the member, the roles, the account and the organization.
			updated, err := update(ada, "max-m", "admin")
			must(err)
			if got := seen(); got != "before:max-m:member->admin:max@example.test:acme,after:max-m:member->admin:Max" || updated.Role != "admin" {
				t.Fatal("unexpected role hooks or result", got, updated)
			}

			// The before hook can replace the roles to set.
			override = &org.MemberOverride{Roles: []string{"member"}}
			updated, err = update(ada, "max-m", "owner")
			must(err)
			if got := seen(); got != "before:max-m:admin->owner:max@example.test:acme,after:max-m:admin->member:Max" || role("max-m") != "member" {
				t.Fatal("the override was not saved", got)
			}

			// A replacement is checked like the caller's own request.
			override = &org.MemberOverride{Roles: []string{"owner"}}
			_, err = update(lin, "max-m", "admin")
			code(err, 403, "YOU_ARE_NOT_ALLOWED_TO_UPDATE_THIS_MEMBER")
			override = nil
			if seen() != "before:max-m:member->admin:max@example.test:acme" || role("max-m") != "member" {
				t.Fatal("an admin granted the owner role through the hook")
			}

			// A before-hook error cancels the change.
			beforeErr = errors.New("approval required")
			if _, err = update(ada, "max-m", "admin"); err == nil {
				t.Fatal("the before hook did not cancel the change")
			}
			beforeErr = nil
			if seen() != "before:max-m:member->admin:max@example.test:acme" || role("max-m") != "member" {
				t.Fatal("a cancelled change was saved")
			}

			// Refused changes never reach the hooks.
			_, err = update(max, "lin-m", "member")
			code(err, 403, "YOU_ARE_NOT_ALLOWED_TO_UPDATE_THIS_MEMBER")
			_, err = update(ada, "max-m", "auditor")
			code(err, 400, "ROLE_NOT_FOUND")
			_, err = update(ada, "ada-m", "member")
			code(err, 400, "YOU_CANNOT_LEAVE_THE_ORGANIZATION_WITHOUT_AN_OWNER")
			if got := seen(); got != "" {
				t.Fatal("a refused change reached the hooks", got)
			}

			// An after-hook error is returned and the new role remains.
			afterErr = errors.New("audit sink unavailable")
			if _, err = update(ada, "max-m", "admin"); err == nil {
				t.Fatal("lost the after-hook error")
			}
			if seen() != "before:max-m:member->admin:max@example.test:acme,after:max-m:member->admin:Max" || role("max-m") != "admin" {
				t.Fatal("an after-hook error reverted the change")
			}
		})
	}
}
