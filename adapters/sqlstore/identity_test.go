package sqlstore

import (
	"context"
	"errors"
	"testing"
	"time"

	auth "github.com/FineStack/frost-auth"
)

func TestLinkedAccountIsolation(t *testing.T) {
	ctx := context.Background()
	s, err := Open(ctx, "sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	now := time.Now().UTC()
	for _, id := range []string{"one", "two"} {
		u := auth.User{ID: id, Email: id + "@example.test", CreatedAt: now, UpdatedAt: now}
		if err := s.CreateUser(ctx, u, "private-password-hash", nil); err != nil {
			t.Fatal(err)
		}
	}
	_, err = s.db.Exec(`INSERT INTO "account" ("id","accountId","providerId","userId","accessToken","scope","createdAt","updatedAt") VALUES ('other','remote-subject','sample','one','private-token',' read, write ',?,?)`, s.date(now), s.date(now))
	if err != nil {
		t.Fatal(err)
	}
	rows, err := s.ListUserAccounts(ctx, "one")
	if err != nil || len(rows) != 2 {
		t.Fatal(rows, err)
	}
	for _, a := range rows {
		if a.ID == "other" && (len(a.Scopes) != 2 || a.Scopes[1] != "write") {
			t.Fatal(a)
		}
	}
	if !errors.Is(s.UnlinkAccount(ctx, "two", "other", true), auth.ErrNotFound) {
		t.Fatal("unlinked another user's account")
	}
	if err := s.UnlinkAccount(ctx, "one", "other", false); err != nil {
		t.Fatal(err)
	}
	rows, err = s.ListUserAccounts(ctx, "one")
	if err != nil || len(rows) != 1 {
		t.Fatal(rows, err)
	}
	if !errors.Is(s.UnlinkAccount(ctx, "one", rows[0].ID, false), auth.ErrLastAccount) {
		t.Fatal("unlinked last account")
	}
}
