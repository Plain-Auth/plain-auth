package sqlstore

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Plain-Org/plain-auth"
	stripeclient "github.com/Plain-Org/plain-auth/client/stripe"
	billing "github.com/Plain-Org/plain-auth/plugins/stripe"
	"github.com/Plain-Org/plain-auth/schema"
	sdk "github.com/stripe/stripe-go/v87"
)

type scheduleProvider struct {
	calls, portals, cancelUpdates                         int
	portalForm                                            url.Values
	onPortal, onPriceRead                                 func()
	cancelAt                                              int64
	atEnd                                                 bool
	mu                                                    sync.Mutex
	start, end                                            int64
	attached, createKey, updateKey, target, attempt, mode string
	created, updated, released                            int
	loseCreate, loseUpdate, loseRelease                   bool
	lastReleased                                          string
	onScheduleRead                                        func()
}

func (p *scheduleProvider) response() map[string]any {
	first := map[string]any{"start_date": p.start, "end_date": p.end, "items": []any{map[string]any{"price": "price_month", "quantity": 1}},
		"invoice_settings": map[string]any{"issuer": map[string]string{"type": "self"}}}
	if p.mode == "customPhase" {
		first["discounts"] = []any{map[string]string{"coupon": "coupon_host"}}
	}
	phases := []any{first}
	meta := map[string]string{}
	if p.target != "" {
		phases = append(phases, map[string]any{"start_date": p.end, "proration_behavior": "none", "items": []any{map[string]any{"price": p.target, "quantity": 1}}})
		meta["source"], meta["plainauthPlanChange"] = "plain-auth", p.attempt
	}
	customer := "cus_owner"
	if p.mode == "otherCustomer" {
		customer = "cus_other"
	}
	return map[string]any{"id": p.attached, "object": "subscription_schedule", "status": "active", "subscription": "sub_owner", "customer": customer, "end_behavior": "release", "metadata": meta, "phases": phases}
}

func (p *scheduleProvider) RoundTrip(r *http.Request) (*http.Response, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := r.ParseForm(); err != nil {
		return nil, err
	}
	p.calls++
	key := r.Header.Get("Idempotency-Key")
	path := r.URL.Path
	switch {
	case (r.Method == "GET" || r.Method == "POST") && path == "/v1/subscriptions/sub_owner":
		if r.Method == "POST" {
			if p.cancelAt != 0 && r.PostForm.Has("cancel_at") && r.PostForm.Get("cancel_at") == "" {
				p.cancelAt = 0
			} else if p.atEnd && r.PostForm.Get("cancel_at_period_end") == "false" {
				p.atEnd = false
			} else {
				return nil, errors.New("invalid cancellation restore")
			}
			p.cancelUpdates++
		}
		item := map[string]any{"id": "si_owner", "quantity": 1, "current_period_start": p.start, "current_period_end": p.end,
			"price": map[string]any{"id": "price_month", "recurring": map[string]any{"interval": "month", "interval_count": 1, "usage_type": "licensed"}}}
		sub := map[string]any{"id": "sub_owner", "object": "subscription", "customer": "cus_owner", "status": "active", "items": map[string]any{"data": []any{item}}}
		sub["cancel_at_period_end"], sub["cancel_at"] = p.atEnd, p.cancelAt
		if p.attached != "" {
			sub["schedule"] = p.attached
		}
		if p.mode == "discount" {
			sub["discounts"] = []string{"di_host"}
		}
		return stripeJSON(200, sub), nil
	case r.Method == "GET" && strings.HasPrefix(path, "/v1/prices/"):
		if p.onPriceRead != nil {
			fn := p.onPriceRead
			p.onPriceRead = nil
			fn()
		}
		price := strings.TrimPrefix(path, "/v1/prices/")
		interval := "month"
		if price == "price_year" {
			interval = "year"
		}
		return stripeJSON(200, map[string]any{"id": price, "active": true, "recurring": map[string]any{"interval": interval, "interval_count": 1, "usage_type": "licensed"}}), nil
	case r.Method == "POST" && path == "/v1/billing_portal/sessions":
		p.portals++
		p.portalForm = r.PostForm
		if p.onPortal != nil {
			fn := p.onPortal
			p.onPortal = nil
			fn()
		}
		return stripeJSON(200, map[string]string{"id": "bps_owner", "customer": r.PostForm.Get("customer"), "url": "https://billing.example.test/" + r.PostForm.Get("flow_data[type]")}), nil
	case r.Method == "POST" && path == "/v1/subscription_schedules":
		if key == "" || len(r.PostForm) != 1 || r.PostForm.Get("from_subscription") != "sub_owner" {
			return nil, errors.New("invalid schedule create")
		}
		if p.attached == "" {
			if p.createKey == key {
				return nil, errors.New("recreated released schedule with old key")
			}
			p.created++
			p.attached = "sched_" + strconv.Itoa(p.created)
			p.createKey = key
			p.target = ""
			p.attempt = ""
		} else if p.createKey != key {
			return nil, errors.New("recreated attached schedule with distinct idempotency key")
		}
		if p.loseCreate {
			p.loseCreate = false
			return nil, errors.New("lost create response")
		}
		return stripeJSON(200, p.response()), nil
	case p.attached != "" && path == "/v1/subscription_schedules/"+p.attached && r.Method == "GET":
		if p.onScheduleRead != nil {
			fn := p.onScheduleRead
			p.onScheduleRead = nil
			fn()
		}
		return stripeJSON(200, p.response()), nil
	case p.attached != "" && path == "/v1/subscription_schedules/"+p.attached && r.Method == "POST":
		f := r.PostForm
		if key == "" || key == p.createKey || f.Get("metadata[source]") != "plain-auth" || f.Get("metadata[plainauthPlanChange]") == "" || f.Get("end_behavior") != "release" ||
			f.Get("phases[0][start_date]") != strconv.FormatInt(p.start, 10) || f.Get("phases[0][end_date]") != strconv.FormatInt(p.end, 10) ||
			f.Get("phases[0][items][0][price]") != "price_month" || f.Get("phases[0][items][0][quantity]") != "1" ||
			f.Get("phases[1][start_date]") != strconv.FormatInt(p.end, 10) || f.Get("phases[1][items][0][quantity]") != "1" || f.Get("phases[1][proration_behavior]") != "none" {
			return nil, fmt.Errorf("wrong phase terms: %v", f)
		}
		next := f.Get("phases[1][items][0][price]")
		if next != "price_year" && next != "price_team" {
			return nil, fmt.Errorf("unexpected future price %s", next)
		}
		if p.target != "" && (key != p.updateKey || p.target != next) {
			return nil, errors.New("rewrote a scheduled change")
		}
		if p.target == "" {
			p.updated++
		}
		p.target, p.updateKey, p.attempt = next, key, f.Get("metadata[plainauthPlanChange]")
		if p.loseUpdate {
			p.loseUpdate = false
			return nil, errors.New("lost schedule update response")
		}
		return stripeJSON(200, p.response()), nil
	case p.attached != "" && path == "/v1/subscription_schedules/"+p.attached+"/release" && r.Method == "POST":
		id := p.attached
		p.attached = ""
		p.target = ""
		p.released++
		p.lastReleased = id
		if p.loseRelease {
			p.loseRelease = false
			return nil, errors.New("lost release response")
		}
		return stripeJSON(200, map[string]string{"id": id, "status": "released", "customer": "cus_owner", "released_subscription": "sub_owner"}), nil
	case p.lastReleased != "" && path == "/v1/subscription_schedules/"+p.lastReleased && r.Method == "GET":
		return stripeJSON(200, map[string]string{"id": p.lastReleased, "status": "released", "customer": "cus_owner", "released_subscription": "sub_owner"}), nil
	default:
		return nil, fmt.Errorf("unexpected schedule request %s %s", r.Method, path)
	}
}

func TestPeriodEndPlanChanges(t *testing.T) {
	for _, kind := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(kind, func(t *testing.T) {
			ctx := t.Context()
			ddl, err := schema.Generate(kind, []string{"stripe-subscriptions"})
			if err != nil {
				t.Fatal(err)
			}
			dsn := organizationTestDSN(t, kind)
			p := &scheduleProvider{start: time.Now().Add(-time.Hour).Unix(), end: time.Now().Add(30 * 24 * time.Hour).Unix()}
			backends := sdk.NewBackendsWithConfig(&sdk.BackendConfig{HTTPClient: &http.Client{Transport: p}, MaxNetworkRetries: sdk.Int64(0)})
			plugin := billing.New(billing.Options{WebhookSecret: "whsec_local", Subscriptions: &billing.SubscriptionOptions{Client: sdk.NewClient("sk_test_local", sdk.WithBackends(backends)),
				Plans: []billing.Plan{{Name: "basic", PriceID: "price_month"}, {Name: "team", PriceID: "price_team", AnnualPriceID: "price_year"}}}})
			const origin = "https://billing.example"
			newServer := func() (*plainauth.Auth, *Store) {
				s, err := OpenWithSchema(ctx, kind, dsn, ddl)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { s.Close() })
				off := false
				a, err := plainauth.New(plainauth.Options{BaseURL: origin, Secret: strings.Repeat("s", 32), EmailAndPassword: true, Store: s, RateLimit: &off, Plugins: []plainauth.Plugin{plugin}})
				if err != nil {
					t.Fatal(err)
				}
				return a, s
			}
			a, store := newServer()
			b, _ := newServer()
			exec := func(q string, args ...any) {
				t.Helper()
				if _, err := store.db.ExecContext(ctx, store.bind(q), args...); err != nil {
					t.Fatal(err)
				}
			}
			register := func(name string) (string, *http.Cookie) {
				u, err := a.SignUpEmail(ctx, plainauth.SignUpInput{Name: name, Email: name + "@example.test", Password: "local-fixture-pass"}, plainauth.RequestMeta{})
				if err != nil {
					t.Fatal(err)
				}
				return u.User.ID, a.SessionCookie(u.Token, true)
			}
			uid, owner := register("owner")
			_, peer := register("other")
			exec(`UPDATE "user" SET "stripeCustomerId"=? WHERE "id"=?`, "cus_owner", uid)
			exec(`INSERT INTO "subscription" ("id","plan","referenceId","stripeCustomerId","stripeSubscriptionId","status","seats") VALUES(?,?,?,?,?,'active',1)`, "local_owner", "basic", uid, "cus_owner", "sub_owner")
			call := func(server *plainauth.Auth, cookie *http.Cookie, path string, annual bool) (int, string) {
				var input any = map[string]string{"subscriptionId": "sub_owner"}
				if path == "upgrade" {
					input = stripeclient.Checkout{SubscriptionID: "sub_owner", Plan: "team", Annual: annual, ReturnURL: "/account", DisableRedirect: true, ScheduleAtPeriodEnd: true}
				}
				data, _ := json.Marshal(input)
				r := httptest.NewRequest("POST", origin+"/api/auth/subscription/"+path, bytes.NewReader(data))
				r.Header.Set("Content-Type", "application/json")
				r.Header.Set("Origin", origin)
				r.AddCookie(cookie)
				w := httptest.NewRecorder()
				server.ServeHTTP(w, r)
				return w.Code, w.Body.String()
			}
			check := func(server *plainauth.Auth, cookie *http.Cookie, path string, annual bool, code int, content string) {
				t.Helper()
				got, body := call(server, cookie, path, annual)
				if got != code || !strings.Contains(body, content) {
					t.Fatalf("%s expected %d %q, got %d %s", path, code, content, got, body)
				}
			}
			check(a, peer, "upgrade", true, 400, "SUBSCRIPTION_NOT_FOUND")
			p.mode = "discount"
			check(a, owner, "upgrade", true, 409, "UNSUPPORTED_SUBSCRIPTION_ITEM")
			p.mode = ""
			p.attached = "sched_external"
			check(a, owner, "upgrade", true, 409, "SUBSCRIPTION_PENDING_CHANGE")
			if p.created != 0 || p.updated != 0 || p.released != 0 {
				t.Fatal("modified an existing or unsupported billing relationship")
			}
			p.attached = ""
			p.loseCreate = true
			p.loseUpdate = true
			check(a, owner, "upgrade", true, 502, "STRIPE_SUBSCRIPTION_UNAVAILABLE")
			key := stripeRecordID("schedule-change", "sub_owner")
			var saved []byte
			if err := store.db.QueryRowContext(ctx, store.bind(`SELECT "value" FROM "verification" WHERE "id"=?`), key).Scan(&saved); err != nil {
				t.Fatal(err)
			}
			var old billing.ScheduleChange
			if err := json.Unmarshal(saved, &old); err != nil {
				t.Fatal(err)
			}
			old.Created = time.Now().Add(-24 * time.Hour).Unix()
			expired, _ := json.Marshal(old)
			exec(`UPDATE "verification" SET "value"=? WHERE "id"=?`, string(expired), key)
			check(b, owner, "upgrade", true, 409, "CHECKOUT_RECONCILIATION_REQUIRED")
			if p.created != 1 || p.updated != 0 {
				t.Fatal("expired idempotency window repeated a provider mutation")
			}
			exec(`UPDATE "verification" SET "value"=? WHERE "id"=?`, string(saved), key)
			check(b, owner, "upgrade", false, 409, "SUBSCRIPTION_PENDING_CHANGE")
			check(b, owner, "upgrade", true, 502, "STRIPE_SUBSCRIPTION_UNAVAILABLE")
			check(a, owner, "upgrade", true, 200, origin+"/account")
			check(b, owner, "upgrade", true, 200, `"redirect":false`)
			var price, schedule string
			if err := store.db.QueryRowContext(ctx, store.bind(`SELECT "plan","stripeScheduleId" FROM "subscription" WHERE "id"=?`), "local_owner").Scan(&price, &schedule); err != nil || price != "basic" || schedule != p.attached {
				t.Fatal("current plan or future schedule changed during retry", price, schedule, err)
			}
			if p.created != 1 || p.updated != 1 || p.target != "price_year" {
				t.Fatal("lost-response recovery duplicated or changed the subscription schedule")
			}
			p.loseRelease = true
			check(a, owner, "restore", false, 502, "STRIPE_SUBSCRIPTION_UNAVAILABLE")
			if p.released != 1 || p.attached != "" {
				t.Fatal("failed to release scheduled plan")
			}
			start := make(chan struct{})
			codes := make(chan int, 2)
			for i, server := range []*plainauth.Auth{a, b} {
				go func() { <-start; code, _ := call(server, owner, "upgrade", i == 0); codes <- code }()
			}
			close(start)
			first, second := <-codes, <-codes
			if !((first == 200 && second == 409) || (first == 409 && second == 200)) || p.created != 2 || p.updated != 2 {
				t.Fatal("competing plan destinations did not yield one schedule", first, second, p.created, p.updated)
			}
			check(a, owner, "restore", false, 200, "sub_owner")
			p.mode = "customPhase"
			check(b, owner, "upgrade", true, 409, "CHECKOUT_RECONCILIATION_REQUIRED")
			if p.updated != 2 {
				t.Fatal("overwrote a custom provider phase")
			}
			p.mode = "otherCustomer"
			check(b, owner, "upgrade", true, 409, "CHECKOUT_RECONCILIATION_REQUIRED")
			p.mode = ""
			check(a, owner, "restore", false, 200, "sub_owner")
			p.onScheduleRead = func() { exec(`UPDATE "subscription" SET "seats"=2 WHERE "id"='local_owner'`) }
			check(b, owner, "upgrade", true, 409, "CHECKOUT_RECONCILIATION_REQUIRED")
			if p.updated != 2 {
				t.Fatal("a changed local entitlement allowed a stale schedule update")
			}
			check(a, owner, "restore", false, 200, "sub_owner")
			p.onScheduleRead = func() { exec(`DELETE FROM "session" WHERE "userId"=?`, uid) }
			check(b, owner, "upgrade", true, 401, "UNAUTHORIZED")
			if p.updated != 2 {
				t.Fatal("session revocation during provider lookup allowed a future billing change")
			}
		})
	}
}
