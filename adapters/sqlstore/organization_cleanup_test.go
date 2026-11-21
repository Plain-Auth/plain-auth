package sqlstore

import (
	"context"
	"crypto/rand"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-sql-driver/mysql"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
	auth "github.com/FineStack/frost-auth"
	org "github.com/FineStack/frost-auth/plugins/organization"
	"github.com/FineStack/frost-auth/schema"
)

// Use a separate database (MySQL) or schema (PostgreSQL) so profile migrations
// never change the caller's core test tables.
func organizationTestDSN(t *testing.T, dialect string) string {
	t.Helper()
	if dialect == "sqlite" {
		return filepath.Join(t.TempDir(), "teams.sqlite")
	}
	dsn := os.Getenv("AUTH_TEST_" + strings.ToUpper(dialect) + "_DSN")
	if dsn == "" {
		t.Skip("requires a local disposable database")
	}
	namespace := "orgtest_" + strings.ToLower(rand.Text()[:12])
	driver := "pgx"
	entity := "SCHEMA"
	if dialect == "mysql" {
		driver = "mysql"
		entity = "DATABASE"
	}
	admin, err := sql.Open(driver, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { admin.Close() })
	if _, err := admin.ExecContext(t.Context(), "CREATE "+entity+" "+namespace); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		statement := "DROP " + entity + " " + namespace
		if dialect == "postgres" {
			statement += " CASCADE"
		}
		if _, err := admin.ExecContext(context.Background(), statement); err != nil {
			t.Error(err)
		}
	})
	if dialect == "mysql" {
		cfg, err := mysql.ParseDSN(dsn)
		if err != nil {
			t.Fatal(err)
		}
		cfg.DBName = namespace
		return cfg.FormatDSN()
	}
	cfg, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	cfg.RuntimeParams["search_path"] = namespace
	key := stdlib.RegisterConnConfig(cfg)
	t.Cleanup(func() { stdlib.UnregisterConnConfig(key) })
	return key
}

func TestOrganizationAccountDeletion(t *testing.T) {
	for _, dialect := range []string{"sqlite", "mysql", "postgres"} {
		t.Run(dialect, func(t *testing.T) {
			ctx := t.Context()
			must := func(err error) {
				t.Helper()
				if err != nil {
					t.Fatal(err)
				}
			}
			dsn := organizationTestDSN(t, dialect)
			ddl, err := schema.Generate(dialect, []string{"organization-teams"})
			must(err)
			s, err := OpenWithSchema(ctx, dialect, dsn, ddl)
			must(err)
			defer s.Close()
			// A separate server with only core features can delete the account.
			bare, err := Open(ctx, dialect, dsn)
			must(err)
			defer bare.Close()
			now := time.Now().UTC().Truncate(time.Millisecond)
			actor := func(name string) (auth.User, auth.StoredSession) {
				u := auth.User{ID: name, Name: name, Email: name + "@example.test", CreatedAt: now, UpdatedAt: now}
				ss := auth.StoredSession{Session: auth.Session{ID: name + "-s", Token: name + "-t", UserID: name, CreatedAt: now, UpdatedAt: now, ExpiresAt: now.Add(time.Hour)}}
				must(s.CreateUser(ctx, u, "local-fixture", &ss))
				return u, ss
			}
			owner, ownerSession := actor("owner")
			member, memberSession := actor("member")
			o := org.Organization{ID: "example", Name: "Example", Slug: "example", CreatedAt: now}
			must(s.CreateOrganization(ctx, o, org.Member{ID: "owner-m", UserID: owner.ID, OrganizationID: o.ID, Role: "owner", CreatedAt: now}, ownerSession.ID, false))
			invite := func(id, email, role, by string) org.Invitation {
				return org.Invitation{ID: id, OrganizationID: o.ID, InviterID: by, Email: email, Role: role, Status: "pending", CreatedAt: now, ExpiresAt: now.Add(time.Hour)}
			}
			welcome := invite("welcome", member.Email, "admin", owner.ID)
			_, err = s.InviteOrganizationMember(ctx, welcome, ownerSession.ID, false)
			must(err)
			stale := owner
			stale.Email = member.Email
			stale.EmailVerified = true
			private, _, err := s.AcceptOrganizationInvitation(ctx, welcome.ID, ownerSession.ID, stale, now, false)
			if !errors.Is(err, org.ErrRecipient) || private.ID != "" || private.Email != "" {
				t.Fatalf("recipient mismatch disclosed invitation: %+v %v", private, err)
			}
			stale = member
			stale.EmailVerified = true
			_, _, err = s.AcceptOrganizationInvitation(ctx, welcome.ID, memberSession.ID, stale, now, true)
			if !errors.Is(err, org.ErrUnverified) {
				t.Fatalf("stale verification was trusted: %v", err)
			}
			_, _, err = s.AcceptOrganizationInvitation(ctx, welcome.ID, memberSession.ID, member, now, false)
			must(err)
			pending := invite("pending", "other@example.test", "member", owner.ID)
			_, err = s.InviteOrganizationMember(ctx, pending, ownerSession.ID, false)
			must(err)
			other := invite("unrelated", "third@example.test", "member", member.ID)
			_, err = s.InviteOrganizationMember(ctx, other, memberSession.ID, false)
			must(err)
			exec := func(q string, args ...any) {
				t.Helper()
				_, err := s.db.ExecContext(ctx, s.bind(q), args...)
				must(err)
			}
			exec(`INSERT INTO "team" ("id","name","memberCount","organizationId","createdAt") VALUES(?,?,?,?,?)`, "team", "Team", 2, o.ID, s.date(now))
			for _, u := range []auth.User{member, owner} {
				exec(`INSERT INTO "teamMember" ("id","teamId","userId") VALUES(?,?,?)`, "tm-"+u.ID, "team", u.ID)
			}
			must(bare.DeleteAccount(ctx, owner.ID, ownerSession.Token, "", "", now))
			count := func(expected int, q string, args ...any) {
				t.Helper()
				var n int
				must(s.db.QueryRowContext(ctx, s.bind(q), args...).Scan(&n))
				if n != expected {
					t.Fatalf("%s: got %d, want %d", q, n, expected)
				}
			}
			count(0, `SELECT COUNT(*) FROM "member" WHERE "userId"=?`, owner.ID)
			count(0, `SELECT COUNT(*) FROM "teamMember" WHERE "userId"=?`, owner.ID)
			count(0, `SELECT COUNT(*) FROM "invitation" WHERE "inviterId"=?`, owner.ID)
			count(1, `SELECT COUNT(*) FROM "member" WHERE "userId"=?`, member.ID)
			count(1, `SELECT COUNT(*) FROM "teamMember" WHERE "userId"=?`, member.ID)
			count(1, `SELECT COUNT(*) FROM "invitation" WHERE "id"=?`, other.ID)
			count(1, `SELECT "memberCount" FROM "team" WHERE "id"=?`, "team")
			private, err = s.InviteOrganizationMember(ctx, pending, ownerSession.ID, true)
			if !errors.Is(err, org.ErrUnauthenticated) || private.ID != "" {
				t.Fatalf("deleted inviter: %+v %v", private, err)
			}
			must(s.DeleteSession(ctx, memberSession.Token))
			private, err = s.InviteOrganizationMember(ctx, other, memberSession.ID, true)
			if !errors.Is(err, org.ErrUnauthenticated) || private.ID != "" {
				t.Fatalf("revoked inviter: %+v %v", private, err)
			}
			if err := s.SetActiveOrganization(ctx, memberSession.ID, member.ID, nil); !errors.Is(err, org.ErrUnauthenticated) {
				t.Fatalf("revoked session changed active organization: %v", err)
			}
		})
	}
}
