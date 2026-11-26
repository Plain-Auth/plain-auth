package sqlstore

import (
	"errors"
	"testing"
	"time"

	plainauth "github.com/Plain-Org/plain-auth"
	ak "github.com/Plain-Org/plain-auth/plugins/apikey"
	"github.com/Plain-Org/plain-auth/schema"
)

// Keys without rate settings are unlimited and unstamped, a remaining count
// runs out and removes a key without a refill, a refill resets the count
// after its interval, and expiresIn sets the expiry from creation.
func TestAPIKeyUsageBudgets(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			ctx := t.Context()
			must := func(err error) {
				t.Helper()
				if err != nil {
					t.Fatal(err)
				}
			}
			ddl, err := schema.Generate(dialect, []string{"api-key"})
			must(err)
			store, err := OpenWithSchema(ctx, dialect, organizationTestDSN(t, dialect), ddl)
			must(err)
			defer store.Close()
			owner := testUser("budget-owner")
			must(store.CreateUser(ctx, owner, "", nil))
			uid := owner.ID
			budget, err := ak.New(ak.Options{Store: store, DisableRateLimit: true})
			must(err)
			limits, err := ak.New(ak.Options{Store: store, ConfigID: "limits"})
			must(err)
			n := func(v int64) *int64 { return &v }
			verify := func(s *ak.Service, secret string) ak.Verification {
				t.Helper()
				v, err := s.Verify(ctx, secret, nil)
				must(err)
				return v
			}
			code := func(err error) string {
				var api *plainauth.APIError
				if errors.As(err, &api) {
					return api.Code
				}
				return ""
			}

			for _, column := range []string{"rateLimitMax", "rateLimitTimeWindow"} {
				k, err := limits.Create(ctx, uid, ak.CreateInput{Policy: ak.Policy{RateLimitMax: n(1)}})
				must(err)
				_, err = store.db.ExecContext(ctx, store.bind(`UPDATE "apikey" SET "`+column+`"=NULL WHERE "id"=?`), k.ID)
				must(err)
				for range 3 {
					if !verify(limits, k.Secret).Valid {
						t.Fatal("a key with a null rate limit setting was limited or stamped", column)
					}
				}
				got, err := limits.Get(ctx, uid, k.ID)
				must(err)
				if got.RequestCount != 0 || got.LastRequest != nil || column == "rateLimitMax" && got.RateLimitMax != nil || column == "rateLimitTimeWindow" && got.RateLimitTimeWindow != nil {
					t.Fatal("a key with a null rate limit setting was limited or stamped", column, got.RequestCount, got.LastRequest)
				}
			}

			free, err := budget.Create(ctx, uid, ak.CreateInput{})
			must(err)
			for range 12 {
				if !verify(budget, free.Secret).Valid {
					t.Fatal("a key without a remaining count was capped")
				}
			}
			if got, err := budget.Get(ctx, uid, free.ID); err != nil || got.Remaining != nil || got.ExpiresAt != nil || free.ExpiresAt != nil {
				t.Fatal("a key without a remaining count was capped, or a key created without expiresIn has an expiry", err)
			}
			once, err := budget.Create(ctx, uid, ak.CreateInput{Policy: ak.Policy{Remaining: n(1)}})
			must(err)
			if r := verify(budget, once.Secret); !r.Valid || r.Key.Remaining == nil || *r.Key.Remaining != 0 {
				t.Fatal("the last use was refused")
			}
			if got, err := budget.Get(ctx, uid, once.ID); err != nil || got.Remaining == nil || *got.Remaining != 0 {
				t.Fatal("the last use removed the key before a further request", err)
			}
			if r := verify(budget, once.Secret); r.Valid || r.Error.Code != "USAGE_EXCEEDED" {
				t.Fatal("a used-up key was accepted", r.Error)
			}
			var rows int
			must(store.db.QueryRowContext(ctx, store.bind(`SELECT count(*) FROM "apikey" WHERE "id"=?`), once.ID).Scan(&rows))
			if _, err := budget.Get(ctx, uid, once.ID); code(err) != "KEY_NOT_FOUND" || rows != 0 {
				t.Fatal("an exhausted key without a refill was kept", err, rows)
			}
			if r := verify(budget, once.Secret); r.Valid || r.Error.Code != "INVALID_API_KEY" {
				t.Fatal("a removed key did not answer INVALID_API_KEY", r.Error)
			}

			hour := time.Hour
			_, err = budget.Create(ctx, uid, ak.CreateInput{Policy: ak.Policy{RefillAmount: n(3)}})
			if code(err) != "REFILL_INTERVAL_AND_AMOUNT_REQUIRED" {
				t.Fatal("a refill amount without an interval was not refused", err)
			}
			_, err = budget.Create(ctx, uid, ak.CreateInput{Policy: ak.Policy{RefillInterval: &hour}})
			if code(err) != "REFILL_AMOUNT_AND_INTERVAL_REQUIRED" {
				t.Fatal("a refill interval without an amount was not refused", err)
			}
			seeded, err := budget.Create(ctx, uid, ak.CreateInput{Policy: ak.Policy{RefillInterval: &hour, RefillAmount: n(3)}})
			must(err)
			for range 5 {
				if !verify(budget, seeded.Secret).Valid {
					t.Fatal("a refill policy capped a key without a remaining count")
				}
			}
			if got, err := budget.Get(ctx, uid, seeded.ID); err != nil || got.Remaining != nil || got.RefillAmount == nil || *got.RefillAmount != 3 || got.RefillInterval == nil || *got.RefillInterval != 3600000 {
				t.Fatal("a refill policy capped a key without a remaining count", err)
			}
			refill, err := budget.Create(ctx, uid, ak.CreateInput{Policy: ak.Policy{Remaining: n(5), RefillInterval: &hour, RefillAmount: n(3)}})
			must(err)
			remaining := func() int64 {
				t.Helper()
				got, err := budget.Get(ctx, uid, refill.ID)
				if err != nil || got.Remaining == nil {
					t.Fatal("the refillable key was not found", err)
				}
				return *got.Remaining
			}
			if !verify(budget, refill.Secret).Valid || remaining() != 4 {
				t.Fatal("a use inside the first interval refilled the key")
			}
			_, err = store.db.ExecContext(ctx, store.bind(`UPDATE "apikey" SET "createdAt"=? WHERE "id"=?`), store.date(time.Now().Add(-2*time.Hour)), refill.ID)
			must(err)
			r := verify(budget, refill.Secret)
			if !r.Valid || remaining() != 2 {
				t.Fatal("a refill added to the remaining count instead of resetting it")
			}
			got, err := budget.Get(ctx, uid, refill.ID)
			if err != nil || got.LastRefillAt == nil || time.Since(*got.LastRefillAt) > time.Minute || r.Key.LastRefillAt == nil || !r.Key.LastRefillAt.Equal(*got.LastRefillAt) {
				t.Fatal("a refill did not record its time", err)
			}
			if !verify(budget, refill.Secret).Valid || remaining() != 1 {
				t.Fatal("a recent refill was repeated because the key is old")
			}
			if !verify(budget, refill.Secret).Valid {
				t.Fatal("the last refilled use was refused")
			}
			if r := verify(budget, refill.Secret); r.Valid || r.Error.Code != "USAGE_EXCEEDED" || remaining() != 0 {
				t.Fatal("an exhausted refillable key was removed")
			}
			_, err = store.db.ExecContext(ctx, store.bind(`UPDATE "apikey" SET "lastRefillAt"=? WHERE "id"=?`), store.date(time.Now().Add(-2*time.Hour)), refill.ID)
			must(err)
			if !verify(budget, refill.Secret).Valid || remaining() != 2 {
				t.Fatal("an exhausted key did not refill after its interval")
			}

			dated, err := budget.Create(ctx, uid, ak.CreateInput{ExpiresIn: 48 * time.Hour})
			must(err)
			stored, err := budget.Get(ctx, uid, dated.ID)
			must(err)
			if dated.ExpiresAt == nil || !dated.ExpiresAt.Equal(dated.CreatedAt.Add(48*time.Hour)) || stored.ExpiresAt == nil || !stored.ExpiresAt.Equal(stored.CreatedAt.Add(48*time.Hour)) || !verify(budget, dated.Secret).Valid {
				t.Fatal("expiresIn did not set the expiry from the creation time")
			}
		})
	}
}
