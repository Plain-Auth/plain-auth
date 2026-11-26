package sqlstore

import (
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	plainauth "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/client"
	ak "github.com/Plain-Org/plain-auth/plugins/apikey"
	"github.com/Plain-Org/plain-auth/schema"
)

// Create and update apply the name bounds, expiresIn in seconds and the
// per-key rate and refill settings, and refuse server-only fields from the
// browser.
func TestAPIKeyCreateAndUpdateParameters(t *testing.T) {
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
				var api *plainauth.APIError
				if !errors.As(err, &api) || api.Code != code {
					t.Fatalf("expected %s, got %v", code, err)
				}
			}
			ddl, err := schema.Generate(dialect, []string{"api-key"})
			must(err)
			store, err := OpenWithSchema(ctx, dialect, organizationTestDSN(t, dialect), ddl)
			must(err)
			defer store.Close()
			keys, err := ak.New(ak.Options{Store: store, MinNameLength: 3, MaxNameLength: 8})
			must(err)
			plugin, err := ak.NewPlugin(keys)
			must(err)
			const origin = "https://parameters.example"
			off := false
			host, err := plainauth.New(plainauth.Options{Store: store, BaseURL: origin, Secret: strings.Repeat("p", 32), EmailAndPassword: true, RateLimit: &off, Plugins: []plainauth.Plugin{plugin}})
			must(err)
			member, err := client.New(origin, &http.Client{Transport: guestTransport{host}})
			must(err)
			account, err := member.SignUpEmail(ctx, client.SignUpRequest{Name: "Params", Email: "params@example.test", Password: "parameter-password"})
			must(err)
			uid := account.User.ID
			n := func(v int64) *int64 { return &v }
			off2, on := false, true
			minute, hour := time.Minute, time.Hour
			verify := func(secret string) ak.Verification {
				t.Helper()
				v, err := keys.Verify(ctx, secret, nil)
				must(err)
				return v
			}
			get := func(id string) *ak.Key {
				t.Helper()
				k, err := keys.Get(ctx, uid, id)
				must(err)
				return k
			}
			ago := func(column, id string, d time.Duration) {
				t.Helper()
				_, err := store.db.ExecContext(ctx, store.bind(`UPDATE "apikey" SET "`+column+`"=? WHERE "id"=?`), store.date(time.Now().Add(-d)), id)
				must(err)
			}

			made, err := member.CreateAPIKey(ctx, client.CreateAPIKeyRequest{Name: "ops"})
			must(err)
			if made.Name == nil || *made.Name != "ops" || get(made.ID).Name == nil || *get(made.ID).Name != "ops" {
				t.Fatal("a named key did not keep its name")
			}
			unnamed, err := member.CreateAPIKey(ctx, client.CreateAPIKeyRequest{})
			must(err)
			if unnamed.Name != nil || unnamed.ExpiresAt != nil {
				t.Fatal("an unnamed key got a name or an expiry")
			}
			for _, name := range []string{"ab", "overflows", "🔑🔑🔑🔑🔑"} {
				_, err := member.CreateAPIKey(ctx, client.CreateAPIKeyRequest{Name: name})
				expect(err, "INVALID_NAME_LENGTH")
			}
			if emoji, err := member.CreateAPIKey(ctx, client.CreateAPIKeyRequest{Name: "🔑🔑🔑"}); err != nil || emoji.Name == nil || *emoji.Name != "🔑🔑🔑" {
				t.Fatal("a name inside the limits in UTF-16 units was refused", err)
			}
			if dated, err := member.CreateAPIKey(ctx, client.CreateAPIKeyRequest{Name: "dated", ExpiresIn: n(172800)}); err != nil || dated.ExpiresAt == nil || !dated.ExpiresAt.Equal(dated.CreatedAt.Add(48*time.Hour)) {
				t.Fatal("expiresIn in seconds did not set the expiry from the creation time", err)
			}

			windowed, err := keys.Create(ctx, uid, ak.CreateInput{Policy: ak.Policy{RateLimitMax: n(1), RateWindow: &minute}})
			must(err)
			if windowed.RateLimitTimeWindow == nil || *windowed.RateLimitTimeWindow != 60000 || windowed.RateLimitMax == nil || *windowed.RateLimitMax != 1 || !verify(windowed.Secret).Valid {
				t.Fatal("a key's own rate window was not stored")
			}
			if r := verify(windowed.Secret); r.Valid || r.Error.Code != "RATE_LIMITED" || r.Error.TryAgainIn == nil || *r.Error.TryAgainIn <= 0 || *r.Error.TryAgainIn > 60000 {
				t.Fatal("the key's own window did not set the retry interval")
			}
			ago("lastRequest", windowed.ID, 2*time.Minute)
			if !verify(windowed.Secret).Valid || get(windowed.ID).RequestCount != 1 {
				t.Fatal("the key's own window did not reopen after it passed")
			}
			unlimited, err := keys.Create(ctx, uid, ak.CreateInput{Policy: ak.Policy{RateLimitEnabled: &off2, RateLimitMax: n(1)}})
			must(err)
			for range 3 {
				if !verify(unlimited.Secret).Valid {
					t.Fatal("a key created with rate limiting off was refused")
				}
			}
			if k := get(unlimited.ID); k.RateLimitEnabled || k.RequestCount != 0 || k.LastRequest == nil {
				t.Fatal("a key created with rate limiting off was limited or not tracked")
			}

			before, err := member.ListAPIKeys(ctx, "default", ak.PageOptions{})
			must(err)
			for _, route := range []string{"/api-key/create", "/api-key/update"} {
				for field, value := range map[string]any{"refillAmount": 5, "refillInterval": 60000, "rateLimitEnabled": false, "rateLimitTimeWindow": 1000, "rateLimitMax": 99} {
					body := map[string]any{field: value}
					if route == "/api-key/update" {
						body["keyId"] = made.ID
					}
					expect(member.Do(ctx, http.MethodPost, route, body, nil), "SERVER_ONLY_PROPERTY")
				}
			}
			after, err := member.ListAPIKeys(ctx, "default", ak.PageOptions{})
			must(err)
			if k := get(made.ID); k.RefillAmount != nil || k.RefillInterval != nil || !k.RateLimitEnabled || *k.RateLimitTimeWindow != 86400000 || *k.RateLimitMax != 10 || after.Total != before.Total {
				t.Fatal("a browser request changed a server-only property")
			}

			changed, err := member.UpdateAPIKey(ctx, client.UpdateAPIKeyRequest{KeyID: made.ID, ExpiresIn: n(172800)})
			must(err)
			if changed.ExpiresAt == nil || !changed.ExpiresAt.Equal(changed.UpdatedAt.Add(48*time.Hour)) || !get(made.ID).ExpiresAt.Equal(*changed.ExpiresAt) {
				t.Fatal("expiresIn on update did not count from the update")
			}
			if cleared, err := member.UpdateAPIKey(ctx, client.UpdateAPIKeyRequest{KeyID: made.ID, ClearExpiration: true}); err != nil || cleared.ExpiresAt != nil || get(made.ID).ExpiresAt != nil {
				t.Fatal("a null expiresIn did not remove the expiry", err)
			}
			_, err = member.UpdateAPIKey(ctx, client.UpdateAPIKeyRequest{KeyID: made.ID, ExpiresIn: n(60)})
			expect(err, "EXPIRES_IN_IS_TOO_SMALL")
			_, err = member.UpdateAPIKey(ctx, client.UpdateAPIKeyRequest{KeyID: made.ID, ExpiresIn: n(400 * 86400)})
			expect(err, "EXPIRES_IN_IS_TOO_LARGE")
			if get(made.ID).ExpiresAt != nil {
				t.Fatal("a refused expiry change was saved")
			}

			k, err := keys.Create(ctx, uid, ak.CreateInput{Policy: ak.Policy{Remaining: n(1)}})
			must(err)
			_, err = keys.Update(ctx, uid, k.ID, ak.UpdateInput{Policy: ak.Policy{RefillAmount: n(4)}})
			expect(err, "REFILL_INTERVAL_AND_AMOUNT_REQUIRED")
			_, err = keys.Update(ctx, uid, k.ID, ak.UpdateInput{Policy: ak.Policy{RefillInterval: &hour}})
			expect(err, "REFILL_AMOUNT_AND_INTERVAL_REQUIRED")
			up, err := keys.Update(ctx, uid, k.ID, ak.UpdateInput{Policy: ak.Policy{RefillAmount: n(4), RefillInterval: &hour}})
			must(err)
			if *up.RefillAmount != 4 || *up.RefillInterval != 3600000 || *up.Remaining != 1 {
				t.Fatal("server update did not save the refill policy")
			}
			if !verify(k.Secret).Valid || verify(k.Secret).Error.Code != "USAGE_EXCEEDED" || *get(k.ID).Remaining != 0 {
				t.Fatal("an exhausted key with an updated refill policy was removed")
			}
			ago("createdAt", k.ID, 2*time.Hour)
			if !verify(k.Secret).Valid || *get(k.ID).Remaining != 3 {
				t.Fatal("the updated refill amount was not used")
			}
			up, err = keys.Update(ctx, uid, k.ID, ak.UpdateInput{Policy: ak.Policy{RefillAmount: n(2), RefillInterval: &minute}})
			must(err)
			ago("lastRefillAt", k.ID, 2*time.Minute)
			if *up.RefillInterval != 60000 || !verify(k.Secret).Valid || *get(k.ID).Remaining != 1 {
				t.Fatal("the updated refill interval did not decide the next refill")
			}

			rk, err := keys.Create(ctx, uid, ak.CreateInput{})
			must(err)
			if up, err := keys.Update(ctx, uid, rk.ID, ak.UpdateInput{Policy: ak.Policy{RateLimitMax: n(1)}}); err != nil || *up.RateLimitMax != 1 || !verify(rk.Secret).Valid {
				t.Fatal("the updated rate limit maximum was not stored", err)
			}
			if r := verify(rk.Secret); r.Valid || r.Error.Code != "RATE_LIMITED" || *r.Error.TryAgainIn <= 60000 {
				t.Fatal("the updated rate limit maximum was not enforced")
			}
			_, err = keys.Update(ctx, uid, rk.ID, ak.UpdateInput{Policy: ak.Policy{RateLimitMax: n(0)}})
			expect(err, "VALIDATION_ERROR")
			if up, err := keys.Update(ctx, uid, rk.ID, ak.UpdateInput{Policy: ak.Policy{RateLimitEnabled: &off2}}); err != nil || up.RateLimitEnabled {
				t.Fatal("rate limiting was not turned off", err)
			}
			if !verify(rk.Secret).Valid || !verify(rk.Secret).Valid || get(rk.ID).RequestCount != 1 {
				t.Fatal("a key with rate limiting turned off by update was limited or counted")
			}
			_, err = keys.Update(ctx, uid, rk.ID, ak.UpdateInput{Policy: ak.Policy{RateLimitEnabled: &on}})
			must(err)
			if verify(rk.Secret).Valid {
				t.Fatal("turning rate limiting back on did not restore the limit")
			}
			if up, err := keys.Update(ctx, uid, rk.ID, ak.UpdateInput{Policy: ak.Policy{RateWindow: &minute}}); err != nil || *up.RateLimitTimeWindow != 60000 {
				t.Fatal("the updated window was not stored", err)
			}
			if r := verify(rk.Secret); r.Valid || r.Error.Code != "RATE_LIMITED" || *r.Error.TryAgainIn <= 0 || *r.Error.TryAgainIn > 60000 {
				t.Fatal("the updated window did not set the retry interval")
			}
			ago("lastRequest", rk.ID, 2*time.Minute)
			if !verify(rk.Secret).Valid {
				t.Fatal("the updated window did not reopen after it passed")
			}
		})
	}
}
