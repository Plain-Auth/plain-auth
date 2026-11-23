package sqlstore

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	auth "github.com/Plain-Auth/plain-auth"
	org "github.com/Plain-Auth/plain-auth/plugins/organization"
	"github.com/Plain-Auth/plain-auth/schema"
)

func TestMemberDirectorySnapshot(t *testing.T) {
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
			store, err := OpenWithOptions(ctx, dialect, dsn, []string{"organization"}, schema.Options{})
			must(err)
			t.Cleanup(func() { store.Close() })
			writer, err := Open(ctx, dialect, dsn)
			must(err)
			t.Cleanup(func() { writer.Close() })
			now := time.Now().UTC().Truncate(time.Millisecond)
			created := time.Date(2024, 2, 3, 4, 5, 6, 789000000, time.UTC)
			for _, id := range []string{"Caller", "Peer", "Third"} {
				session := auth.Session{ID: id + "-s", Token: id + "-token", UserID: id, CreatedAt: now, UpdatedAt: now, ExpiresAt: now.Add(time.Hour)}
				must(store.CreateUser(ctx, auth.User{ID: id, Name: id, Email: strings.ToLower(id) + "@example.test", CreatedAt: now, UpdatedAt: now}, "", &auth.StoredSession{Session: session}))
			}
			group := "Studio"
			owner := org.Member{ID: "m0", OrganizationID: group, UserID: "Caller", Role: "owner", CreatedAt: created}
			must(store.CreateOrganization(ctx, org.Organization{ID: group, Slug: "studio", Name: "Studio", CreatedAt: created}, owner, "Caller-s", false))
			for i, id := range []string{"Peer", "Third"} {
				must(store.AddOrganizationMember(ctx, org.Member{ID: fmt.Sprintf("m%d", i+1), OrganizationID: group, UserID: id, Role: "member", CreatedAt: created.Add(time.Duration(i+1) * time.Second)}, ""))
			}
			for _, tc := range []struct {
				field, op string
				values    []string
				want      []string
			}{
				{"role", "in", []string{"owner", "member"}, []string{"m2", "m1", "m0"}},
				{"userId", "not_in", []string{"Caller", "Third"}, []string{"m1"}},
				{"userId", "eq", []string{"caller"}, nil},
				{"organizationId", "ne", []string{group}, nil},
				{"id", "gt", []string{"m1"}, []string{"m2"}},
				{"id", "gte", []string{"m1"}, []string{"m2", "m1"}},
				{"id", "lt", []string{"m1"}, []string{"m0"}},
				{"createdAt", "lte", []string{created.Format(time.RFC3339Nano)}, []string{"m0"}},
				{"createdAt", "eq", []string{created.In(time.FixedZone("west", -7*3600)).Format(time.RFC3339Nano)}, []string{"m0"}},
				{"createdAt", "starts_with", []string{"2024-02-03T04:05:06."}, []string{"m0"}},
				{"role", "contains", []string{"m_m%"}, []string{"m2", "m1"}},
				{"role", "ends_with", []string{"er"}, []string{"m2", "m1", "m0"}},
			} {
				page, err := store.ListOrganizationMembers(ctx, "Caller-s", "Caller", org.MemberListQuery{OrganizationID: "unused", OrganizationSlug: "studio", SortBy: "createdAt", SortDirection: "desc", FilterField: tc.field, FilterOperator: tc.op, FilterValues: tc.values})
				must(err)
				var ids []string
				for _, m := range page.Members {
					if m.OrganizationID != group || m.UserID != m.User.ID || m.User.Name != m.UserID {
						t.Fatal("unexpected member or joined profile", m)
					}
					ids = append(ids, m.ID)
				}
				if page.Members == nil || page.Total != len(tc.want) || !slices.Equal(ids, tc.want) {
					t.Fatalf("%s %s returned IDs %v total %d, want %v", tc.field, tc.op, ids, page.Total, tc.want)
				}
			}
			for _, q := range []org.MemberListQuery{
				{SortBy: "email"}, {FilterField: "user.name", FilterValues: []string{"Peer"}}, {SortDirection: "not-a-direction"}, {Limit: -1},
			} {
				_, err := store.ListOrganizationMembers(ctx, "Caller-s", "Caller", q)
				var api *auth.APIError
				if !errors.As(err, &api) || api.Code != "VALIDATION_ERROR" {
					t.Fatal("invalid directory query accepted", q, err)
				}
			}
			// Flip membership roles as a group on a second database connection.
			// A filtered count and its rows must both describe the same commit.
			done := make(chan error, 1)
			go func() {
				for i := 0; i < 35; i++ {
					role := "member"
					if i%2 == 0 {
						role = "admin"
					}
					if _, err := writer.db.ExecContext(ctx, writer.bind(`UPDATE "member" SET "role"=? WHERE "organizationId"=? AND "userId"<>'Caller'`), role, group); err != nil {
						done <- err
						return
					}
				}
				done <- nil
			}()
			for range 35 {
				page, err := store.ListOrganizationMembers(ctx, "Caller-s", "Caller", org.MemberListQuery{FilterField: "role", FilterValues: []string{"admin"}})
				must(err)
				if page.Total != len(page.Members) || (page.Total != 0 && page.Total != 2) {
					t.Fatal("directory mixed count and profiles from different snapshots", page)
				}
			}
			must(<-done)
			_, err = writer.db.ExecContext(ctx, writer.bind(`DELETE FROM "member" WHERE "id"=?`), "m0")
			must(err)
			_, err = store.ListOrganizationMembers(ctx, "Caller-s", "Caller", org.MemberListQuery{Offset: 999})
			if !errors.Is(err, org.ErrRoleReadDenied) {
				t.Fatal("removed caller received a filtered count", err)
			}
			_, err = store.ListOrganizationMembers(ctx, "caller-s", "Caller", org.MemberListQuery{})
			if !errors.Is(err, org.ErrUnauthenticated) {
				t.Fatal("mismatched session ID accepted", err)
			}
		})
	}
}
