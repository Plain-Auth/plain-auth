package sqlstore

import (
	"context"
	"errors"
	"testing"
	"time"

	auth "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/schema"
)

func TestBillingCustomerScope(t *testing.T) {
	ctx := context.Background()
	ddl, err := schema.Generate("sqlite", []string{"stripe-subscriptions"})
	if err != nil {
		t.Fatal(err)
	}
	s, err := OpenWithSchema(ctx, "sqlite", ":memory:", ddl)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	now := time.Now()
	for _, id := range []string{"one", "two"} {
		if err := s.CreateUser(ctx, auth.User{ID: id, Email: id + "@example.test", CreatedAt: now, UpdatedAt: now}, "hash", nil); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.db.Exec(`INSERT INTO "subscription" ("id","referenceId","plan","status","stripeCustomerId") VALUES ('sub','one','pro','active','cus_one')`); err != nil {
		t.Fatal(err)
	}
	if v, err := s.StripeCustomer(ctx, "one"); err != nil || v != "cus_one" {
		t.Fatal(v, err)
	}
	if v, err := s.StripeCustomer(ctx, "two"); !errors.Is(err, auth.ErrNotFound) || v != "" {
		t.Fatal(v, err)
	}
	if _, err := s.db.Exec(`UPDATE "user" SET "stripeCustomerId"='cus_profile' WHERE "id"='one'`); err != nil {
		t.Fatal(err)
	}
	if v, err := s.StripeCustomer(ctx, "one"); err != nil || v != "cus_profile" {
		t.Fatal(v, err)
	}
}
