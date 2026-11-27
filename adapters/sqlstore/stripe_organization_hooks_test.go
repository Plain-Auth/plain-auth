package sqlstore

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Plain-Org/plain-auth"
	org "github.com/Plain-Org/plain-auth/plugins/organization"
	billing "github.com/Plain-Org/plain-auth/plugins/stripe"
	"github.com/Plain-Org/plain-auth/schema"
	sdk "github.com/stripe/stripe-go/v87"
)

// OrganizationHooks rename an organization's Stripe customer after its name
// changes, never failing the update, and refuse deleting an organization
// while Stripe reports a subscription that still bills, on any page, while
// a purchase is pending, or when the lookup fails.
func TestOrganizationStripeHooks(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			ctx := t.Context()
			ddl, err := schema.Generate(dialect, []string{"stripe-organization"})
			if err != nil {
				t.Fatal(err)
			}
			store, err := OpenWithSchema(ctx, dialect, organizationTestDSN(t, dialect), ddl)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { store.Close() })
			type remoteCustomer struct {
				name          string
				deleted, fail bool
			}
			var mu sync.Mutex
			customers := map[string]*remoteCustomer{}
			var renames []string
			var statuses []string
			var calls int
			listFails := false
			transport := localBillingTransport(func(r *http.Request) (*http.Response, error) {
				mu.Lock()
				defer mu.Unlock()
				if err := r.ParseForm(); err != nil {
					return nil, err
				}
				calls++
				fail := stripeJSON(500, map[string]any{"error": map[string]string{"type": "api_error", "message": "provider detail"}})
				switch {
				case strings.HasPrefix(r.URL.Path, "/v1/customers/"):
					id := strings.TrimPrefix(r.URL.Path, "/v1/customers/")
					c := customers[id]
					if c == nil || c.fail {
						return fail, nil
					}
					if r.Method == "POST" {
						c.name = r.PostForm.Get("name")
						renames = append(renames, id+"="+c.name)
					}
					return stripeJSON(200, map[string]any{"id": id, "object": "customer", "name": c.name, "deleted": c.deleted}), nil
				case r.URL.Path == "/v1/subscriptions" && r.Method == "GET":
					if listFails {
						return fail, nil
					}
					if r.URL.Query().Get("status") != "all" || r.URL.Query().Get("limit") != "100" || r.URL.Query().Get("customer") == "" {
						return nil, fmt.Errorf("wrong subscription listing %s", r.URL.RawQuery)
					}
					// One subscription per page, continued with starting_after.
					next := 0
					if after := r.URL.Query().Get("starting_after"); after != "" {
						next, _ = strconv.Atoi(strings.TrimPrefix(after, "sub_"))
						next++
					}
					var data []any
					if next < len(statuses) {
						data = []any{map[string]any{"id": "sub_" + strconv.Itoa(next), "object": "subscription", "status": statuses[next]}}
					}
					return stripeJSON(200, map[string]any{"object": "list", "url": "/v1/subscriptions", "has_more": next+1 < len(statuses), "data": data}), nil
				}
				return nil, fmt.Errorf("unexpected Stripe call %s %s", r.Method, r.URL.Path)
			})
			remote := sdk.NewClient("sk_test_local", sdk.WithBackends(sdk.NewBackendsWithConfig(&sdk.BackendConfig{HTTPClient: &http.Client{Transport: transport}, MaxNetworkRetries: sdk.Int64(0)})))
			var logMu sync.Mutex
			var logs bytes.Buffer
			hooks := billing.OrganizationHooks{Client: remote, Store: store, Logger: slog.New(slog.NewTextHandler(lockedWriter{&logMu, &logs}, nil))}
			orgPlugin, err := org.New(org.Options{Store: store, AfterUpdateOrganization: hooks.AfterUpdateOrganization, BeforeDeleteOrganization: hooks.BeforeDeleteOrganization})
			if err != nil {
				t.Fatal(err)
			}
			const origin = "https://billing.example"
			off := false
			a, err := plainauth.New(plainauth.Options{Store: store, Secret: strings.Repeat("s", 32), BaseURL: origin, EmailAndPassword: true, RateLimit: &off, Plugins: []plainauth.Plugin{orgPlugin}})
			if err != nil {
				t.Fatal(err)
			}
			hit, err := a.SignUpEmail(ctx, plainauth.SignUpInput{Name: "owner", Email: "owner@example.test", Password: "local fixture password"}, plainauth.RequestMeta{})
			if err != nil {
				t.Fatal(err)
			}
			call := func(path string, body map[string]any) (int, map[string]any) {
				t.Helper()
				var src bytes.Buffer
				json.NewEncoder(&src).Encode(body)
				r := httptest.NewRequest("POST", origin+"/api/auth"+path, &src)
				r.Header.Set("Origin", origin)
				r.Header.Set("Content-Type", "application/json")
				r.AddCookie(a.SessionCookie(hit.Token, true))
				w := httptest.NewRecorder()
				a.ServeHTTP(w, r)
				var out map[string]any
				json.Unmarshal(w.Body.Bytes(), &out)
				return w.Code, out
			}
			groups := 0
			group := func(customer string) string {
				t.Helper()
				groups++
				name := fmt.Sprintf("group%d", groups)
				status, out := call("/organization/create", map[string]any{"name": name, "slug": name})
				id, _ := out["id"].(string)
				if status != 200 || id == "" {
					t.Fatal("organization create", status, out)
				}
				if customer != "" {
					if _, err := store.db.ExecContext(ctx, store.bind(`UPDATE "organization" SET "stripeCustomerId"=? WHERE "id"=?`), customer, id); err != nil {
						t.Fatal(err)
					}
				}
				return id
			}
			stripeCalls := func() int {
				mu.Lock()
				defer mu.Unlock()
				return calls
			}
			rename := func(id, name string) int {
				t.Helper()
				status, _ := call("/organization/update", map[string]any{"organizationId": id, "data": map[string]any{"name": name}})
				return status
			}
			logged := func() string {
				logMu.Lock()
				defer logMu.Unlock()
				return logs.String()
			}

			// A rename reaches the customer only when its name differs.
			customers["cus_named"] = &remoteCustomer{name: "Old"}
			named := group("cus_named")
			if status := rename(named, "Renamed"); status != 200 || len(renames) != 1 || renames[0] != "cus_named=Renamed" {
				t.Fatal("a rename did not reach the Stripe customer", status, renames)
			}
			if status, _ := call("/organization/update", map[string]any{"organizationId": named, "data": map[string]any{"slug": "renamed-slug"}}); status != 200 || len(renames) != 1 {
				t.Fatal("an update that kept the name renamed the customer", status, renames)
			}
			// A deleted customer, a failed lookup and an organization without
			// a customer leave Stripe alone and the update intact.
			customers["cus_gone"] = &remoteCustomer{name: "Gone", deleted: true}
			customers["cus_down"] = &remoteCustomer{name: "Down", fail: true}
			for _, customer := range []string{"cus_gone", "cus_down"} {
				if status := rename(group(customer), "Changed "+customer); status != 200 || len(renames) != 1 {
					t.Fatal("a deleted or unreachable customer was renamed or failed the update", customer, status, renames)
				}
			}
			if out := logged(); !strings.Contains(out, "Stripe customer was deleted") || !strings.Contains(out, "Failed to sync organization to Stripe") || strings.Contains(out, "provider detail") {
				t.Fatal("the rename failures were not logged without provider text", out)
			}
			before := stripeCalls()
			if status := rename(group(""), "No customer"); status != 200 || stripeCalls() != before {
				t.Fatal("an organization without a customer called Stripe", status)
			}

			remains := func(id string) bool {
				t.Helper()
				var n int
				if err := store.db.QueryRowContext(ctx, store.bind(`SELECT COUNT(*) FROM "organization" WHERE "id"=?`), id).Scan(&n); err != nil {
					t.Fatal(err)
				}
				return n == 1
			}
			remove := func(id string) (int, string) {
				t.Helper()
				status, out := call("/organization/delete", map[string]any{"organizationId": id})
				code, _ := out["code"].(string)
				return status, code
			}
			// Deletion without a customer calls no Stripe API.
			before = stripeCalls()
			if id := group(""); func() bool { status, _ := remove(id); return status != 200 || remains(id) }() || stripeCalls() != before {
				t.Fatal("an organization without a customer was not deleted without a lookup")
			}
			// A subscription that still bills, on a later page, refuses it.
			statuses = []string{"canceled", "past_due"}
			billed := group("cus_billed")
			if status, code := remove(billed); status != 400 || code != "ORGANIZATION_HAS_ACTIVE_SUBSCRIPTION" || !remains(billed) {
				t.Fatal("a billing subscription on a later page did not refuse the deletion", status, code)
			}
			// Ended subscriptions allow it.
			statuses = []string{"canceled", "incomplete", "incomplete_expired"}
			if status, _ := remove(billed); status != 200 || remains(billed) {
				t.Fatal("ended subscriptions refused the deletion", status)
			}
			// A failed lookup refuses it.
			listFails = true
			down := group("cus_listdown")
			if status, _ := remove(down); status < 500 || !remains(down) {
				t.Fatal("a failed lookup allowed the deletion", status)
			}
			listFails = false
			// A pending purchase refuses it before any Stripe call.
			pending := group("")
			now := time.Now()
			if _, err := store.db.ExecContext(ctx, store.bind(`INSERT INTO "verification" ("id","identifier","value","expiresAt","createdAt","updatedAt") VALUES (?,?,?,?,?,?)`), "pending-org-"+strconv.Itoa(groups), "stripe-org-checkout:"+pending, "{}", store.date(now.Add(time.Hour)), store.date(now), store.date(now)); err != nil {
				t.Fatal(err)
			}
			before = stripeCalls()
			if status, code := remove(pending); status != 400 || code != "ORGANIZATION_HAS_ACTIVE_SUBSCRIPTION" || !remains(pending) || stripeCalls() != before {
				t.Fatal("a pending purchase did not refuse the deletion", status, code)
			}
			// An expired reservation can no longer complete and allows it.
			if _, err := store.db.ExecContext(ctx, store.bind(`UPDATE "verification" SET "expiresAt"=? WHERE "identifier"=?`), store.date(now.Add(-time.Minute)), "stripe-org-checkout:"+pending); err != nil {
				t.Fatal(err)
			}
			if status, _ := remove(pending); status != 200 || remains(pending) {
				t.Fatal("an expired reservation refused the deletion", status)
			}
			// A rename reaches Stripe after the request was cancelled.
			cancelled, cancel := context.WithCancel(ctx)
			cancel()
			if err := hooks.AfterUpdateOrganization(cancelled, org.AfterProfileUpdate{Organization: &org.Organization{ID: named, Name: "Detached"}}); err != nil || renames[len(renames)-1] != "cus_named=Detached" {
				t.Fatal("a cancelled request stopped the rename", err, renames)
			}
			// Hooks without a client or store refuse a deletion and never fail
			// an update.
			if err := (billing.OrganizationHooks{}).BeforeDeleteOrganization(ctx, org.OrganizationDeletion{}); err == nil {
				t.Fatal("hooks without a client or store allowed a deletion")
			}
			if err := (billing.OrganizationHooks{}).AfterUpdateOrganization(ctx, org.AfterProfileUpdate{Organization: &org.Organization{ID: named}}); err != nil {
				t.Fatal("hooks without a client or store failed an update", err)
			}
		})
	}
}
