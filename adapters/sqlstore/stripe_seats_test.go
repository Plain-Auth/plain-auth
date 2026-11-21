package sqlstore

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	auth "github.com/Stonewrit/stonewrit-auth"
	"github.com/Stonewrit/stonewrit-auth/client"
	stripeclient "github.com/Stonewrit/stonewrit-auth/client/stripe"
	org "github.com/Stonewrit/stonewrit-auth/plugins/organization"
	billing "github.com/Stonewrit/stonewrit-auth/plugins/stripe"
	"github.com/Stonewrit/stonewrit-auth/schema"
	sdk "github.com/stripe/stripe-go/v87"
	"github.com/stripe/stripe-go/v87/webhook"
)

type seatsProvider struct {
	mu                      sync.Mutex
	group, status, customer string
	purchased, current      int
	metadata                map[string]string
	keys                    map[string]int
	requests                []string
	failedKeys              []string
	afterPost               func()
	failAfterPost           bool
}

func (p *seatsProvider) subscription() map[string]any {
	status, customer := p.status, p.customer
	if status == "" {
		status = "active"
	}
	if customer == "" {
		customer = "cus_org"
	}
	return map[string]any{"id": "sub_auto", "object": "subscription", "customer": customer, "status": status, "metadata": p.metadata, "items": map[string]any{"data": []any{map[string]any{"id": "si_managed", "quantity": p.current, "price": map[string]any{"id": "price_seat", "recurring": map[string]any{"interval": "month", "interval_count": 1, "usage_type": "licensed"}}}}}}
}
func (p *seatsProvider) checkout() map[string]any {
	return map[string]any{"id": "cs_auto", "object": "checkout.session", "url": "https://billing.example.test/managed", "mode": "subscription", "status": "complete", "payment_status": "paid", "customer": "cus_org", "client_reference_id": p.group, "metadata": p.metadata, "subscription": "sub_auto", "line_items": map[string]any{"data": []any{map[string]any{"quantity": p.purchased, "price": map[string]string{"id": "price_seat"}}}}}
}
func (p *seatsProvider) RoundTrip(r *http.Request) (*http.Response, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := r.ParseForm(); err != nil {
		return nil, err
	}
	switch {
	case r.Method == "GET" && r.URL.Path == "/v1/subscriptions/sub_broken":
		broken := p.subscription()
		broken["id"], broken["customer"] = "sub_broken", "cus_broken"
		return stripeJSON(200, broken), nil
	case r.Method == "POST" && r.URL.Path == "/v1/subscriptions/sub_broken":
		p.failedKeys = append(p.failedKeys, r.Header.Get("Idempotency-Key"))
		return nil, errors.New("subscription update is unavailable")
	case r.Method == "GET" && r.URL.Path == "/v1/prices/price_seat":
		return stripeJSON(200, map[string]any{"id": "price_seat", "active": true, "recurring": map[string]any{"interval": "month", "interval_count": 1, "usage_type": "licensed"}}), nil
	case r.Method == "POST" && r.URL.Path == "/v1/checkout/sessions":
		if r.Form.Get("customer") != "cus_org" || r.Form.Get("client_reference_id") != p.group || r.Form.Get("line_items[0][price]") != "price_seat" || r.Form.Has("line_items[1][price]") {
			return nil, errors.New("wrong organization or duplicate base price")
		}
		p.purchased, _ = strconv.Atoi(r.Form.Get("line_items[0][quantity]"))
		p.current = p.purchased
		p.metadata = map[string]string{}
		for _, k := range []string{"userId", "customerType", "organizationId", "referenceId", "subscriptionId", "checkoutAttemptId"} {
			p.metadata[k] = r.Form.Get("metadata[" + k + "]")
		}
		return stripeJSON(200, p.checkout()), nil
	case r.Method == "GET" && r.URL.Path == "/v1/checkout/sessions/cs_auto":
		return stripeJSON(200, p.checkout()), nil
	case r.Method == "GET" && r.URL.Path == "/v1/subscriptions/sub_auto":
		return stripeJSON(200, p.subscription()), nil
	case r.Method == "POST" && r.URL.Path == "/v1/subscriptions/sub_auto":
		if r.Form.Get("items[0][id]") != "si_managed" || r.Form.Get("proration_behavior") != "none" || len(r.Form) != 3 {
			return nil, fmt.Errorf("invalid seat update: %v", r.Form)
		}
		q, err := strconv.Atoi(r.Form.Get("items[0][quantity]"))
		if err != nil {
			return nil, err
		}
		key := r.Header.Get("Idempotency-Key")
		if key == "" {
			return nil, errors.New("missing seat key")
		}
		if old, ok := p.keys[key]; ok {
			if old != q {
				return nil, errors.New("changed quantity for same key")
			}
		} else {
			p.keys[key] = q
			p.current = q
		}
		p.requests = append(p.requests, key)
		if p.afterPost != nil {
			fn := p.afterPost
			p.afterPost = nil
			fn()
		}
		if p.failAfterPost {
			p.failAfterPost = false
			return nil, errors.New("lost remote success")
		}
		return stripeJSON(200, p.subscription()), nil
	}
	return nil, fmt.Errorf("unexpected %s %s", r.Method, r.URL)
}

func TestAutomaticOrganizationSeats(t *testing.T) {
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
			ddl, err := schema.Generate(dialect, []string{"stripe-organization"})
			must(err)
			store, err := OpenWithSchema(ctx, dialect, dsn, ddl)
			must(err)
			defer store.Close()
			replica, err := OpenWithSchema(ctx, dialect, dsn, ddl)
			must(err)
			defer replica.Close()
			svc, err := org.NewService(org.Options{Store: store})
			must(err)
			groupPlugin, err := org.New(org.Options{Store: store})
			must(err)
			remote := &seatsProvider{keys: map[string]int{}}
			backend := sdk.NewBackendsWithConfig(&sdk.BackendConfig{HTTPClient: &http.Client{Transport: remote}, MaxNetworkRetries: sdk.Int64(0)})
			opts := billing.SubscriptionOptions{Client: sdk.NewClient("sk_test", sdk.WithBackends(backend)), Plans: []billing.Plan{{Name: "team", PriceID: "price_seat", SeatPriceID: "price_seat", ProrationBehavior: "none"}}}
			host := httptest.NewUnstartedServer(nil)
			origin := "https://" + host.Listener.Addr().String()
			off := false
			api, err := auth.New(auth.Options{BaseURL: origin, Secret: strings.Repeat("s", 32), EmailAndPassword: true, RateLimit: &off, Store: store, Plugins: []auth.Plugin{groupPlugin, billing.New(billing.Options{WebhookSecret: "whsec_auto", Subscriptions: &opts, Organization: &billing.OrganizationOptions{AuthorizeReference: func(m billing.ReferenceAuthorization) bool { return m.Role == "owner" }}})}})
			must(err)
			host.Config.Handler = api
			host.StartTLS()
			defer host.Close()
			register := func(name string) (stripeclient.Client, string, string) {
				t.Helper()
				cl, err := client.New(origin, host.Client())
				must(err)
				r, err := cl.SignUpEmail(ctx, client.SignUpRequest{Name: name, Email: name + "@example.test", Password: "local-password"})
				must(err)
				return stripeclient.Client{Auth: cl}, r.User.ID, *r.Token
			}
			owner, ownerID, token := register("owner")
			_, first, _ := register("first")
			invitee, second, secondToken := register("invitee")
			var group org.Organization
			must(owner.Auth.Do(ctx, "POST", "/organization/create", map[string]string{"name": "Group", "slug": "auto"}, &group))
			remote.group = group.ID
			_, err = store.db.ExecContext(ctx, store.bind(`UPDATE "organization" SET "stripeCustomerId"='cus_org' WHERE "id"=?`), group.ID)
			must(err)
			add := func(user string) (*org.Member, error) {
				return svc.AddMember(ctx, org.AddMemberRequest{UserID: user, OrganizationID: group.ID, Roles: []string{"member"}})
			}
			initial, err := add(first)
			must(err)
			request := stripeclient.Checkout{Plan: "team", Seats: 99, CustomerType: "organization", ReferenceID: group.ID}
			page, err := owner.Upgrade(ctx, request)
			must(err)
			if page.URL == "" || remote.purchased != 2 {
				t.Fatal("checkout ignored the committed membership count", page, remote.purchased)
			}
			var inv org.Invitation
			must(owner.Auth.Do(ctx, "POST", "/organization/invite-member", map[string]string{"email": "invitee@example.test", "role": "member", "organizationId": group.ID}, &inv))
			must(invitee.Auth.Do(ctx, "POST", "/organization/accept-invitation", map[string]string{"invitationId": inv.ID}, nil))
			page, err = owner.Upgrade(ctx, request)
			must(err)
			if page.ID != "cs_auto" || remote.purchased != 2 {
				t.Fatal("a checkout retry changed the purchased quantity")
			}
			deliver := func(eventID, kind string, object map[string]any) {
				t.Helper()
				raw, err := json.Marshal(map[string]any{"id": eventID, "object": "event", "api_version": sdk.APIVersion, "type": kind, "data": map[string]any{"object": object}})
				must(err)
				r := httptest.NewRequest("POST", origin+"/api/auth/stripe/webhook", bytes.NewReader(raw))
				r.Header.Set("Stripe-Signature", webhook.GenerateTestSignedPayload(&webhook.UnsignedPayload{Payload: raw, Secret: "whsec_auto"}).Header)
				rec := httptest.NewRecorder()
				api.ServeHTTP(rec, r)
				if rec.Code != 200 {
					t.Fatal(rec.Code, rec.Body.String())
				}
			}
			deliver("evt_auto_checkout", "checkout.session.completed", remote.checkout())
			worker, err := billing.NewSeatWorker(store, opts)
			must(err)
			restarted, err := billing.NewSeatWorker(replica, opts)
			must(err)
			remote.failAfterPost = true
			// Another database connection can commit a membership change while the
			// external request is pending; the worker must not hold that SQL lock.
			remote.afterPost = func() {
				short, cancel := context.WithTimeout(ctx, 2*time.Second)
				defer cancel()
				_, err := replica.RemoveOrganizationMember(short, ownerID, token, group.ID, initial.ID)
				if err != nil {
					t.Error("membership blocked behind Stripe", err)
				}
			}
			if err := worker.SyncOnce(ctx, 10); err == nil || remote.current != 3 {
				t.Fatal("lost response did not preserve the committed external operation", err, remote.current)
			}
			must(restarted.SyncOnce(ctx, 10))
			must(restarted.SyncOnce(ctx, 10))
			if remote.current != 2 || len(remote.requests) != 3 || remote.requests[0] != remote.requests[1] || remote.requests[2] == remote.requests[1] {
				t.Fatal("restart did not recover the same operation before the newer revision", remote.requests, remote.current)
			}
			reads := len(remote.requests)
			if _, err := add(second); err == nil {
				t.Fatal("duplicate membership committed")
			}
			must(worker.SyncOnce(ctx, 10))
			if len(remote.requests) != reads {
				t.Fatal("failed membership changed billing")
			}
			member, err := add(first)
			must(err)
			var wg sync.WaitGroup
			errs := make(chan error, 2)
			for _, w := range []*billing.SeatWorker{worker, restarted} {
				wg.Add(1)
				go func() { defer wg.Done(); errs <- w.SyncOnce(ctx, 10) }()
			}
			wg.Wait()
			close(errs)
			for err := range errs {
				must(err)
			}
			if remote.current != 3 || len(remote.keys) != 3 {
				t.Fatal("concurrent workers billed the membership revision more than once", remote.keys)
			}
			rows, err := owner.ListOrganization(ctx, group.ID)
			must(err)
			if len(rows) != 1 || rows[0].Seats == nil || *rows[0].Seats != 3 {
				t.Fatal("confirmed membership quantity missing", rows)
			}
			_, err = store.RemoveOrganizationMember(ctx, ownerID, token, group.ID, member.ID)
			must(err)
			must(worker.SyncOnce(ctx, 10))
			if remote.current != 2 {
				t.Fatal("member removal was not billed")
			}
			personal, err := owner.List(ctx)
			must(err)
			if len(personal) != 0 {
				t.Fatal("organization seat charges appeared on personal account")
			}
			last, _, lastToken := register("later")
			must(owner.Auth.Do(ctx, "POST", "/organization/invite-member", map[string]string{"email": "later@example.test", "role": "member", "organizationId": group.ID}, &inv))
			must(last.Auth.Do(ctx, "POST", "/organization/accept-invitation", map[string]string{"invitationId": inv.ID}, nil))
			must(worker.SyncOnce(ctx, 10))
			if remote.current != 3 {
				t.Fatal("active invitation acceptance did not add one seat")
			}
			laterUser, _, err := store.Credential(ctx, "later@example.test")
			must(err)
			_, err = store.LeaveOrganization(ctx, laterUser.ID, lastToken, group.ID)
			must(err)
			must(worker.SyncOnce(ctx, 10))
			if remote.current != 2 {
				t.Fatal("member departure did not remove one seat")
			}
			writes := len(remote.requests)
			temporary, err := add(first)
			must(err)
			_, err = store.RemoveOrganizationMember(ctx, ownerID, token, group.ID, temporary.ID)
			must(err)
			must(restarted.SyncOnce(ctx, 10))
			if len(remote.requests) != writes {
				t.Fatal("net-zero membership change created an external mutation")
			}
			// An already-paid subscription can predate this plan configuration.
			_, err = store.db.ExecContext(ctx, store.bind(`DELETE FROM "verification" WHERE "id"=?`), stripeRecordID("seats", group.ID))
			must(err)
			reenrolled, err := add(first)
			must(err)
			remote.customer = "cus_other"
			if err := worker.SyncOnce(ctx, 10); !errors.Is(err, billing.ErrSeatReconciliation) || len(remote.requests) != writes {
				t.Fatal("worker sent an update to a foreign customer", err)
			}
			remote.customer = ""
			remote.failAfterPost = true
			if err := worker.SyncOnce(ctx, 10); err == nil || remote.current != 3 {
				t.Fatal("existing paid subscription was not discovered", err)
			}
			preparedKey := remote.requests[len(remote.requests)-1]
			remote.status = "past_due"
			deliver("evt_auto_inactive", "customer.subscription.updated", remote.subscription())
			_, err = store.RemoveOrganizationMember(ctx, ownerID, token, group.ID, reenrolled.ID)
			must(err)
			requestsWhileInactive := len(remote.requests)
			must(restarted.SyncOnce(ctx, 10))
			if len(remote.requests) != requestsWhileInactive {
				t.Fatal("inactive subscription changed remotely")
			}
			remote.status = "active"
			deliver("evt_auto_resume", "customer.subscription.updated", remote.subscription())
			must(restarted.SyncOnce(ctx, 10))
			if remote.requests[len(remote.requests)-1] != preparedKey {
				t.Fatal("interrupted subscription lost its pending idempotency key")
			}
			must(restarted.SyncOnce(ctx, 10))
			if remote.current != 2 {
				t.Fatal("restored subscription did not recover current membership")
			}
			for _, deletion := range []struct {
				email, id, token string
				remaining        int
			}{{"invitee@example.test", second, secondToken, 1}, {"owner@example.test", ownerID, token, 0}} {
				_, hash, err := store.Credential(ctx, deletion.email)
				must(err)
				must(store.DeleteAccount(ctx, deletion.id, deletion.token, hash, "", time.Now()))
				must(restarted.SyncOnce(ctx, 10))
				var billed int
				must(store.db.QueryRowContext(ctx, store.bind(`SELECT "seats" FROM "subscription" WHERE "referenceId"=? AND "stripeSubscriptionId"='sub_auto' AND "status"='active'`), group.ID).Scan(&billed))
				if billed != deletion.remaining || remote.current != deletion.remaining {
					t.Fatal("account deletion left stale seat quantity", billed, remote.current, deletion.remaining)
				}
			}
		})
	}
}

func TestSeatWorkerFairnessAcrossRestarts(t *testing.T) {
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
			ddl, err := schema.Generate(dialect, []string{"stripe-organization"})
			must(err)
			store, err := OpenWithSchema(ctx, dialect, dsn, ddl)
			must(err)
			defer store.Close()
			seed := func(query string, args ...any) {
				_, err := store.db.ExecContext(ctx, store.bind(query), args...)
				must(err)
			}
			for _, group := range []struct{ id, customer, subscription string }{{"broken", "cus_broken", "sub_broken"}, {"healthy", "cus_org", "sub_auto"}} {
				seed(`INSERT INTO "organization" ("id","name","slug","createdAt","stripeCustomerId") VALUES(?,?,?,?,?)`, group.id, group.id, group.id, store.date(time.Now()), group.customer)
				seed(`INSERT INTO "subscription" ("id","referenceId","plan","status","stripeCustomerId","stripeSubscriptionId","seats") VALUES(?,?,'team','active',?,?,1)`, "local_"+group.id, group.id, group.customer, group.subscription)
			}
			remote := &seatsProvider{group: "healthy", purchased: 1, current: 1, keys: map[string]int{}}
			backend := sdk.NewBackendsWithConfig(&sdk.BackendConfig{HTTPClient: &http.Client{Transport: remote}, MaxNetworkRetries: sdk.Int64(0)})
			plan := billing.Plan{Name: "team", PriceID: "price_seat", SeatPriceID: "price_seat", ProrationBehavior: "none"}
			opts := billing.SubscriptionOptions{Client: sdk.NewClient("sk_test", sdk.WithBackends(backend)), Plans: []billing.Plan{plan}}
			must(store.DiscoverStripeSeats(ctx, plan, 10))
			seed(`UPDATE "verification" SET "updatedAt"=? WHERE "identifier"=?`, store.date(time.Now().Add(-time.Hour)), seatsDue+"broken")
			// A fresh worker must handle even a queued peer from a node with a faster clock.
			seed(`UPDATE "verification" SET "updatedAt"=? WHERE "identifier"=?`, store.date(time.Now().Add(time.Minute)), seatsDue+"healthy")
			poll := func() error {
				worker, err := billing.NewSeatWorker(store, opts)
				must(err)
				return worker.SyncOnce(ctx, 1)
			}
			loadBroken := func() billing.SeatAdjustment {
				var raw []byte
				must(store.db.QueryRowContext(ctx, store.bind(`SELECT "value" FROM "verification" WHERE "identifier"=?`), seatsDue+"broken").Scan(&raw))
				var state seatState
				must(json.Unmarshal(raw, &state))
				if state.Work == nil || state.Work.ID == "" {
					t.Fatal("pending operation lost")
				}
				return *state.Work
			}
			if err := poll(); err == nil {
				t.Fatal("failed organization unexpectedly reached Stripe")
			}
			original := loadBroken()
			if original.Item == "" {
				t.Fatal("failed operation was not prepared before the external call")
			}
			must(poll())
			if remote.current != 0 || len(remote.requests) != 1 {
				t.Fatal("a failed organization starved its healthy neighbor", remote.current, remote.requests)
			}
			if err := poll(); err == nil || loadBroken() != original || len(remote.failedKeys) != 2 || remote.failedKeys[0] == "" || remote.failedKeys[0] != remote.failedKeys[1] {
				t.Fatal("requeue changed the pending operation across fresh workers", err, remote.failedKeys)
			}
		})
	}
}
