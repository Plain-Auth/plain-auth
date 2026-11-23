package sqlstore

import (
	"net/http"
	"sync"
	"testing"
	"time"

	stripeclient "github.com/Plain-Org/plain-auth/client/stripe"
	billing "github.com/Plain-Org/plain-auth/plugins/stripe"
)

func TestStripeTrialCheckoutEligibility(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			type submission struct{ key, days string }
			submissions := map[string][]submission{}
			var transportMu sync.Mutex
			handler := func(f *returnFixture, r *http.Request) (*http.Response, error) {
				transportMu.Lock()
				defer transportMu.Unlock()
				if r.Method == "POST" && r.URL.Path == "/v1/checkout/sessions" {
					if err := r.ParseForm(); err != nil {
						return nil, err
					}
					buyer := r.Form.Get("customer")
					submissions[buyer] = append(submissions[buyer], submission{r.Header.Get("Idempotency-Key"), r.Form.Get("subscription_data[trial_period_days]")})
					if buyer == "cus_retry" && len(submissions[buyer]) == 1 {
						return stripeJSON(503, map[string]any{"error": map[string]string{"type": "api_error", "message": "fixture lost response"}}), nil
					}
				}
				return f.provider(r)
			}
			f := configuredReturnFixture(t, dialect, billing.Plan{Name: "pro", PriceID: "price_pro", FreeTrial: &billing.FreeTrial{Days: 14}}, true, handler)
			ctx := t.Context()
			history := func(owner, id, status string, start, end any) {
				t.Helper()
				_, err := f.store.db.ExecContext(ctx, f.store.bind(`INSERT INTO "subscription" ("id","referenceId","plan","status","trialStart","trialEnd") VALUES(?,?,?,?,?,?)`), id, owner, "previous-plan", status, start, end)
				if err != nil {
					t.Fatal(err)
				}
			}
			created := f.store.date(time.Now().UTC().Add(-24 * time.Hour))
			request := stripeclient.Checkout{Plan: "pro", DisableRedirect: true}
			for _, c := range []struct {
				name         string
				start, end   any
				status, days string
			}{
				{"fresh", nil, nil, "", "14"},
				{"priorstart", created, nil, "canceled", ""},
				{"priorend", nil, created, "incomplete_expired", ""},
				{"paid", nil, nil, "canceled", "14"},
				{"abandoned", nil, nil, "incomplete_expired", "14"},
			} {
				buyer := f.user(c.name)
				if c.status != "" {
					history(buyer.User.ID, "history-"+c.name, c.status, c.start, c.end)
				}
				client := meteredClient(t, f.a, buyer.Token)
				if _, err := client.Upgrade(ctx, request); err != nil {
					t.Fatal(err)
				}
				sent := submissions["cus_"+c.name]
				if len(sent) != 1 || sent[0].days != c.days {
					t.Fatalf("%s: got %+v, want trial days %q", c.name, sent, c.days)
				}
			}
			retrying := f.user("retry")
			first := meteredClient(t, f.a, retrying.Token)
			if _, err := first.Upgrade(ctx, request); err == nil {
				t.Fatal("provider failure acknowledged a checkout")
			}
			history(retrying.User.ID, "history-after-reservation", "canceled", created, nil)
			second := meteredClient(t, f.b, retrying.Token)
			if _, err := second.Upgrade(ctx, request); err != nil {
				t.Fatal(err)
			}
			seen := submissions["cus_retry"]
			if len(seen) != 2 || seen[0] != seen[1] || seen[0].days != "14" || seen[0].key == "" {
				t.Fatalf("cross-replica retry changed the reserved trial or idempotency key: %+v", seen)
			}

			racer := f.user("concurrent")
			type result struct {
				id  string
				err error
			}
			ready := make(chan struct{})
			results := make(chan result, 2)
			for _, client := range []stripeclient.Client{meteredClient(t, f.a, racer.Token), meteredClient(t, f.b, racer.Token)} {
				go func() {
					<-ready
					page, err := client.Upgrade(ctx, request)
					results <- result{page.ID, err}
				}()
			}
			close(ready)
			left, right := <-results, <-results
			if left.err != nil || right.err != nil || left.id == "" || left.id != right.id {
				t.Fatalf("concurrent trial checkout: %+v %+v", left, right)
			}
			attempts := submissions["cus_concurrent"]
			if len(attempts) == 0 || attempts[0].days != "14" {
				t.Fatal("eligible concurrent purchase lost its trial")
			}
			for _, attempt := range attempts {
				if attempt != attempts[0] {
					t.Fatal("concurrent purchases sent different trial terms or idempotency keys")
				}
			}
			// The same administrator has already trialed personally. Each organization's
			// own billing history determines whether it receives the plan's trial.
			admin := f.user("administrator")
			history(admin.User.ID, "history-admin", "canceled", created, nil)
			groups := meteredClient(t, f.a, admin.Token)
			for _, suffix := range []string{"new", "used"} {
				var group struct{ ID string }
				if err := groups.Auth.Do(ctx, "POST", "/organization/create", map[string]string{"name": "Trial " + suffix, "slug": "trial-" + suffix}, &group); err != nil {
					t.Fatal(err)
				}
				customer := "cus_group_" + suffix
				if _, err := f.store.db.ExecContext(ctx, f.store.bind(`UPDATE "organization" SET "stripeCustomerId"=? WHERE "id"=?`), customer, group.ID); err != nil {
					t.Fatal(err)
				}
				if suffix == "used" {
					history(group.ID, "history-group", "canceled", nil, created)
				}
				input := stripeclient.Checkout{Plan: "pro", ReferenceID: group.ID, CustomerType: "organization", DisableRedirect: true}
				if _, err := first.Upgrade(ctx, input); err == nil || len(submissions[customer]) != 0 {
					t.Fatal("outsider opened an organization trial")
				}
				if _, err := groups.Upgrade(ctx, input); err != nil {
					t.Fatal(err)
				}
				days := "14"
				if suffix == "used" {
					days = ""
				}
				if seen := submissions[customer]; len(seen) != 1 || seen[0].days != days {
					t.Fatalf("%s: got %+v want %q", suffix, seen, days)
				}
			}
		})
	}
}
