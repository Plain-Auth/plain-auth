package polar

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	auth "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/adapters/sqlstore"
	"github.com/Plain-Org/plain-auth/plugins/organization"
	"github.com/Plain-Org/plain-auth/schema"
	"github.com/google/uuid"
	polargo "github.com/polarsource/polar-go"
	"github.com/polarsource/polar-go/models/components"
)

// probe changes one row on another connection within a second and rolls
// back, proving no transaction holds it.
func probe(db *sql.DB, bind func(string) string, dialect, q string, args ...any) error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if dialect == "mysql" {
		q = strings.ReplaceAll(q, `"`, "`")
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	res, err := tx.ExecContext(ctx, bind(q), args...)
	if err != nil {
		return err
	}
	if n, err := res.RowsAffected(); err != nil || n != 1 {
		return fmt.Errorf("probe changed %d rows: %v", n, err)
	}
	return nil
}

// A checkout for an organization needs the caller's exact membership and
// the host's approval, both outside any transaction and again after the
// provider call; the reference is sent, stored and checked on every
// delivery; and a personal checkout keeps its slot.
func TestOrganizationCheckoutReference(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			ctx := t.Context()
			db, dsn := database(t, dialect)
			ddl, err := schema.Generate(dialect, []string{"organization"})
			if err != nil {
				t.Fatal(err)
			}
			store, err := sqlstore.OpenWithSchema(ctx, dialect, dsn, ddl)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { store.Close() })
			ledger, err := OpenLedger(ctx, db, dialect)
			if err != nil {
				t.Fatal(err)
			}
			quote := func(q string) string {
				if dialect == "mysql" {
					q = strings.ReplaceAll(q, `"`, "`")
				}
				return ledger.bind(q)
			}
			mock := new(provider)
			var mu sync.Mutex
			var asked []ReferenceAuthorization
			var probes []error
			var purchases []Purchase
			var alice, carol string
			service, err := NewService(Options{Client: polargo.New(polargo.WithSecurity("fake-token"), polargo.WithClient(transport(mock.create))), Ledger: ledger, OrganizationID: merchant,
				Checkout: &CheckoutOptions{Products: map[string]string{"pro": product}, HostedOrigin: hosted, SuccessURL: "/success"},
				Webhooks: &WebhookOptions{Secret: dashboardSecret, OnEvent: func(_ context.Context, e Event) error {
					if e.Purchase != nil {
						mu.Lock()
						purchases = append(purchases, *e.Purchase)
						mu.Unlock()
					}
					return nil
				}},
				Organization: &OrganizationOptions{AuthorizeReference: func(r ReferenceAuthorization) bool {
					mu.Lock()
					defer mu.Unlock()
					asked = append(asked, r)
					switch len(asked) {
					case 1:
						probes = append(probes, probe(db, ledger.bind, dialect, `UPDATE "member" SET "role"='probe' WHERE "organizationId"=? AND "userId"=?`, r.OrganizationID, r.UserID))
					case 2:
						probes = append(probes, probe(db, ledger.bind, dialect, `UPDATE plainauth_polar_checkout SET changed_us=changed_us+1 WHERE owner_id=? AND reference_id=?`, r.UserID, r.OrganizationID))
					}
					return r.UserID != carol
				}}})
			if err != nil {
				t.Fatal(err)
			}
			plugin := service.Plugin()
			orgPlugin, err := organization.New(organization.Options{Store: store})
			if err != nil {
				t.Fatal(err)
			}
			a, err := auth.New(auth.Options{BaseURL: host, Secret: strings.Repeat("o", 40), Store: store, EmailAndPassword: true, Plugins: []auth.Plugin{orgPlugin, plugin}})
			if err != nil {
				t.Fatal(err)
			}
			signup := func(name string) (string, *http.Cookie) {
				t.Helper()
				v, err := a.SignUpEmail(ctx, auth.SignUpInput{Name: name, Email: name + "@example.test", Password: "local fixture password"}, auth.RequestMeta{})
				if err != nil {
					t.Fatal(err)
				}
				if _, err := db.ExecContext(ctx, quote(`UPDATE "user" SET "emailVerified"=TRUE WHERE "id"=?`), v.User.ID); err != nil {
					t.Fatal(err)
				}
				return v.User.ID, a.SessionCookie(v.Token, true)
			}
			var aliceCookie, bobCookie, carolCookie *http.Cookie
			alice, aliceCookie = signup("alice")
			_, bobCookie = signup("bob")
			carol, carolCookie = signup("carol")
			w := call(a, "/organization/create", `{"name":"Acme","slug":"acme"}`, "", aliceCookie, nil)
			var created struct {
				ID string `json:"id"`
			}
			if json.Unmarshal([]byte(expect(t, w, 200)), &created); created.ID == "" {
				t.Fatal("the organization was not created", w.Body.String())
			}
			org := created.ID
			if _, err := db.ExecContext(ctx, quote(`INSERT INTO "member" ("id","organizationId","userId","role","createdAt") VALUES (?,?,?,?,?)`), uuid.NewString(), org, carol, "member", time.Now()); err != nil {
				t.Fatal(err)
			}
			body := func(ref string) string {
				raw, _ := json.Marshal(map[string]any{"slug": "pro", "referenceId": ref})
				return string(raw)
			}

			// Without the section, referenceId is an unsupported field.
			personalOnly, err := NewService(Options{Client: polargo.New(), OrganizationID: merchant, Ledger: ledger,
				Checkout: &CheckoutOptions{Products: map[string]string{"pro": product}, HostedOrigin: hosted, SuccessURL: "/success"}})
			if err != nil {
				t.Fatal(err)
			}
			if _, _, _, err := personalOnly.selection(map[string]any{"slug": "pro", "referenceId": org}); err == nil || !strings.Contains(err.Error(), "Unsupported checkout field") {
				t.Fatal("a reference was accepted without the organization section", err)
			}

			// A member the host approves buys for the organization.
			expect(t, call(a, "/checkout", body(org), "", aliceCookie, nil), 200)
			sent := mock.saved()
			metadata, _ := sent["metadata"].(map[string]string)
			if metadata[referenceMetadata] != org || sent["external_customer_id"] != alice {
				t.Fatal("the organization checkout was not sent with its reference", sent)
			}
			var stored string
			if err := db.QueryRowContext(ctx, ledger.bind("SELECT reference_id FROM plainauth_polar_checkout WHERE owner_id=? AND reference_id<>''"), alice).Scan(&stored); err != nil || stored != org {
				t.Fatal("organization checkout did not record referenceId", stored, err)
			}
			mu.Lock()
			if len(asked) != 2 || asked[0] != asked[1] || asked[0].UserID != alice || asked[0].OrganizationID != org || asked[0].Role != "owner" || asked[0].Action != "checkout" || asked[0].SessionID == "" {
				t.Fatalf("the host was not asked twice for the owner: %+v", asked)
			}
			for _, err := range probes {
				if err != nil {
					t.Fatal("a transaction was held while the host decided", err)
				}
			}
			mu.Unlock()
			if err := service.ReconcileCheckout(ctx, sent["id"].(string)); err != nil {
				t.Fatal("an organization checkout did not reconcile", err)
			}
			orgCheckout := sent

			// Non-members, a denied member, unknown and near-miss references are refused before Polar.
			variant := strings.ToUpper(org)
			if variant == org {
				variant = strings.ToLower(org)
			}
			before := mock.count()
			for name, tc := range map[string]struct {
				cookie *http.Cookie
				ref    string
			}{"bob": {bobCookie, org}, "carol": {carolCookie, org}, "unknown": {aliceCookie, uuid.NewString()}, "case": {aliceCookie, variant}, "space": {aliceCookie, org + " "}} {
				w := call(a, "/checkout", body(tc.ref), "", tc.cookie, nil)
				if w.Code != 403 || !strings.Contains(w.Body.String(), "POLAR_REFERENCE_FORBIDDEN") {
					t.Error("a reference was billed without membership and approval", name, w.Code, w.Body.String())
				}
			}
			for _, bad := range []any{"", strings.Repeat("o", 256), "org\n", 5} {
				raw, _ := json.Marshal(map[string]any{"slug": "pro", "referenceId": bad})
				if w := call(a, "/checkout", string(raw), "", aliceCookie, nil); w.Code != 400 || !strings.Contains(w.Body.String(), "POLAR_INVALID_REFERENCE") {
					t.Error("an invalid reference was accepted", bad, w.Code, w.Body.String())
				}
			}
			if w := call(a, "/checkout", body(org), "", nil, nil); w.Code != 401 {
				t.Fatal("a signed-out reference was answered", w.Code)
			}
			if mock.count() != before {
				t.Fatal("a refused reference reached Polar")
			}

			// One request key cannot change its reference.
			expect(t, call(a, "/checkout", body(org), "org-key-0000000000000000000000000", aliceCookie, nil), 200)
			expect(t, call(a, "/checkout", `{"slug":"pro"}`, "org-key-0000000000000000000000000", aliceCookie, nil), 409)
			// A personal checkout of the same product is another checkout, in the slot it always had.
			before = mock.count()
			expect(t, call(a, "/checkout", `{"slug":"pro"}`, "", aliceCookie, nil), 200)
			parts, _ := json.Marshal([]string{merchant, alice, "default:" + product})
			slot := sha256.Sum256(parts)
			var personal string
			if err := db.QueryRowContext(ctx, ledger.bind("SELECT slot FROM plainauth_polar_checkout WHERE owner_id=? AND reference_id='' AND products=?"), alice, product).Scan(&personal); err != nil || personal != hex.EncodeToString(slot[:]) || mock.count() != before+1 {
				t.Fatal("a personal checkout moved slot or reused the organization's", personal, err, mock.count()-before)
			}

			// A personal checkout's delivery cannot claim an organization.
			personalCheckout := mock.saved()
			for name, ref := range map[string]any{"organization": org, "number": 5} {
				snapshot := map[string]any{}
				for k, v := range personalCheckout {
					snapshot[k] = v
				}
				snapshot["metadata"] = map[string]any{attemptMetadata: personalCheckout["metadata"].(map[string]string)[attemptMetadata], referenceMetadata: ref}
				raw := eventPayload("checkout.updated", snapshot)
				expect(t, call(a, "/polar/webhooks", raw, "", nil, signed(raw, "personal-"+name, time.Now(), false)), 409)
			}

			// Deliveries must carry the stored reference.
			for name, ref := range map[string]any{"altered": uuid.NewString(), "missing": nil, "number": 5} {
				snapshot := map[string]any{}
				for k, v := range orgCheckout {
					snapshot[k] = v
				}
				meta := map[string]any{attemptMetadata: metadata[attemptMetadata]}
				if ref != nil {
					meta[referenceMetadata] = ref
				}
				snapshot["metadata"] = meta
				raw := eventPayload("checkout.updated", snapshot)
				expect(t, call(a, "/polar/webhooks", raw, "", nil, signed(raw, "reference-"+name, time.Now(), false)), 409)
			}
			raw := eventPayload("checkout.updated", orgCheckout)
			expect(t, call(a, "/polar/webhooks", raw, "", nil, signed(raw, "reference-ok", time.Now(), false)), 200)
			mu.Lock()
			if len(purchases) != 1 || purchases[0].ReferenceID != org || purchases[0].OwnerID != alice {
				t.Fatalf("the purchase did not report its organization: %+v", purchases)
			}
			mu.Unlock()

			// A membership removed during the provider call withholds the URL.
			mock.mu.Lock()
			mock.snapshot = func() {
				if _, err := db.ExecContext(context.Background(), quote(`DELETE FROM "member" WHERE "organizationId"=? AND "userId"=?`), org, alice); err != nil {
					t.Error(err)
				}
			}
			mock.mu.Unlock()
			if w := call(a, "/checkout", body(org), "org-key-1111111111111111111111111", aliceCookie, nil); w.Code != 403 || strings.Contains(w.Body.String(), hosted) {
				t.Fatal("a removed member received the checkout URL", w.Code, w.Body.String())
			}

			// Without the organization schema, the configuration is refused.
			bare, bareDSN := database(t, dialect)
			defaultDDL, err := schema.Generate(dialect, nil)
			if err != nil {
				t.Fatal(err)
			}
			plainStore, err := sqlstore.OpenWithSchema(ctx, dialect, bareDSN, defaultDDL)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { plainStore.Close() })
			bareLedger, err := OpenLedger(ctx, bare, dialect)
			if err != nil {
				t.Fatal(err)
			}
			unschemed, err := New(Options{Client: polargo.New(), OrganizationID: merchant, Ledger: bareLedger,
				Checkout:     &CheckoutOptions{Products: map[string]string{"pro": product}, HostedOrigin: hosted, SuccessURL: "/success"},
				Organization: &OrganizationOptions{AuthorizeReference: func(ReferenceAuthorization) bool { return true }}})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := auth.New(auth.Options{BaseURL: host, Secret: strings.Repeat("o", 40), Store: plainStore, Plugins: []auth.Plugin{unschemed}}); err == nil || !strings.Contains(err.Error(), "organization schema") {
				t.Fatal("organization references started without the member table", err)
			}
		})
	}
}

// Customer state names the organization a subscription bills, in text
// form when the metadata is not a string, and "" for a personal one.
func TestStateReferenceIDs(t *testing.T) {
	text, number := "org_text", int64(7)
	state := publicState(&components.CustomerStateIndividual{ActiveSubscriptions: []components.CustomerStateSubscription{
		{ID: "org", Metadata: map[string]components.MetadataOutputType{referenceMetadata: {Str: &text}}},
		{ID: "number", Metadata: map[string]components.MetadataOutputType{referenceMetadata: {Integer: &number}}},
		{ID: "personal", Metadata: map[string]components.MetadataOutputType{"other": {Str: &text}}},
	}})
	got := map[string]string{}
	for _, sub := range state.ActiveSubscriptions {
		got[sub.ID] = sub.ReferenceID
	}
	if got["org"] != text || got["number"] != "7" || got["personal"] != "" {
		t.Fatal("customer state did not name the organizations", got)
	}
	raw, _ := json.Marshal(state.ActiveSubscriptions[2])
	if !strings.Contains(string(raw), `"reference_id":""`) || strings.Contains(string(raw), "org_text") {
		t.Fatal("a personal subscription carried a reference or other metadata", string(raw))
	}
	raw, _ = json.Marshal(state.ActiveSubscriptions[0])
	if !strings.Contains(string(raw), `"reference_id":"org_text"`) {
		t.Fatal("an organization subscription did not name its reference", string(raw))
	}
}

// referenceProvider serves the merchant subscription list and, for the
// personal route, the customer portal.
type referenceProvider struct {
	listProvider
	merchantCalls int
	query         url.Values
	reference     string
	merchant      string
	onList        func()
}

func (p *referenceProvider) Do(req *http.Request) (*http.Response, error) {
	if req.URL.Path != "/v1/subscriptions/" {
		return p.listProvider.Do(req)
	}
	p.mu.Lock()
	p.merchantCalls++
	p.query = req.URL.Query()
	reference, owner, hook := p.reference, p.merchant, p.onList
	p.mu.Unlock()
	if req.Method != "GET" || req.URL.Host != "sandbox-api.polar.sh" || req.Header.Get("Polar-Version") != apiVersion || req.Header.Get("Authorization") != "Bearer fixture" {
		return nil, errors.New("unexpected merchant subscription request")
	}
	if hook != nil {
		hook()
	}
	now := time.Now().UTC()
	customer := map[string]any{"id": "55555555-0000-4000-8000-000000000001", "created_at": now, "modified_at": nil, "metadata": map[string]any{"crm": "private"}, "external_id": "member",
		"email": "member@example.test", "email_verified": true, "type": "individual", "name": "Member", "billing_address": nil, "tax_id": nil, "organization_id": owner, "deleted_at": nil, "avatar_url": "https://avatars.example.test/1"}
	item := map[string]any{"id": "66666666-0000-4000-8000-000000000001", "created_at": now, "modified_at": nil, "amount": 5000, "currency": "usd", "recurring_interval": "month",
		"recurring_interval_count": 1, "status": "active", "current_period_start": now, "current_period_end": now.Add(720 * time.Hour), "trial_start": nil, "trial_end": nil,
		"cancel_at_period_end": false, "canceled_at": nil, "started_at": now, "ends_at": nil, "ended_at": nil, "customer_id": customer["id"], "product_id": product,
		"discount_id": nil, "checkout_id": nil, "customer_cancellation_reason": nil, "customer_cancellation_comment": "private comment",
		"metadata": map[string]any{referenceMetadata: reference, "note": "merchant-only"}, "customer": customer, "discount": nil, "prices": []any{}, "meters": []any{}, "pending_update": nil,
		"product": map[string]any{"id": product, "created_at": now, "modified_at": nil, "trial_interval": nil, "trial_interval_count": nil, "name": "Team", "description": nil,
			"visibility": "public", "recurring_interval": "month", "recurring_interval_count": 1, "is_recurring": true, "is_archived": false, "organization_id": owner,
			"metadata": map[string]any{}, "prices": []any{}, "benefits": []any{}, "medias": []any{}, "attached_custom_fields": []any{}}}
	raw, _ := json.Marshal(map[string]any{"items": []any{item}, "pagination": map[string]any{"total_count": 1, "max_page": 1}})
	return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(bytes.NewReader(raw)), Request: req}, nil
}

// A member the host approves lists the organization's subscriptions by
// referenceId as redacted items; another organization's or merchant's item
// refuses the page; refusals reach no provider; and a membership removed
// during the call withholds the page.
func TestOrganizationSubscriptionsByReference(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			ctx := t.Context()
			db, dsn := database(t, dialect)
			ddl, err := schema.Generate(dialect, []string{"organization"})
			if err != nil {
				t.Fatal(err)
			}
			store, err := sqlstore.OpenWithSchema(ctx, dialect, dsn, ddl)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { store.Close() })
			ledger, err := OpenLedger(ctx, db, dialect)
			if err != nil {
				t.Fatal(err)
			}
			quote := func(q string) string {
				if dialect == "mysql" {
					q = strings.ReplaceAll(q, `"`, "`")
				}
				return ledger.bind(q)
			}
			remote := &referenceProvider{listProvider: listProvider{queries: map[string]url.Values{}}, merchant: merchant}
			var mu sync.Mutex
			var asked []ReferenceAuthorization
			var carol string
			plugin, err := New(Options{Client: polargo.New(polargo.WithSecurity("fixture"), polargo.WithClient(remote)), Ledger: ledger, OrganizationID: merchant,
				Portal: &PortalOptions{URL: portalURL},
				Organization: &OrganizationOptions{ServerURL: polargo.ServerList[polargo.ServerSandbox], AuthorizeReference: func(r ReferenceAuthorization) bool {
					mu.Lock()
					defer mu.Unlock()
					asked = append(asked, r)
					return r.UserID != carol
				}}})
			if err != nil {
				t.Fatal(err)
			}
			orgPlugin, err := organization.New(organization.Options{Store: store})
			if err != nil {
				t.Fatal(err)
			}
			a, err := auth.New(auth.Options{BaseURL: host, Secret: strings.Repeat("r", 40), Store: store, EmailAndPassword: true, Plugins: []auth.Plugin{orgPlugin, plugin}})
			if err != nil {
				t.Fatal(err)
			}
			signup := func(name string) (string, *http.Cookie) {
				t.Helper()
				v, err := a.SignUpEmail(ctx, auth.SignUpInput{Name: name, Email: name + "@example.test", Password: "local fixture password"}, auth.RequestMeta{})
				if err != nil {
					t.Fatal(err)
				}
				if _, err := db.ExecContext(ctx, quote(`UPDATE "user" SET "emailVerified"=TRUE WHERE "id"=?`), v.User.ID); err != nil {
					t.Fatal(err)
				}
				return v.User.ID, a.SessionCookie(v.Token, true)
			}
			alice, aliceCookie := signup("alice")
			_, bobCookie := signup("bob")
			var carolCookie *http.Cookie
			carol, carolCookie = signup("carol")
			var created struct {
				ID string `json:"id"`
			}
			if json.Unmarshal([]byte(expect(t, call(a, "/organization/create", `{"name":"Acme","slug":"acme"}`, "", aliceCookie, nil), 200)), &created); created.ID == "" {
				t.Fatal("the organization was not created")
			}
			org := created.ID
			if _, err := db.ExecContext(ctx, quote(`INSERT INTO "member" ("id","organizationId","userId","role","createdAt") VALUES (?,?,?,?,?)`), uuid.NewString(), org, carol, "member", time.Now()); err != nil {
				t.Fatal(err)
			}
			remote.reference = org
			get := func(path string, cookie *http.Cookie) (int, map[string]any, string) {
				t.Helper()
				w := readPersonal(a, "GET", path, "", cookie, nil)
				var out map[string]any
				json.Unmarshal(w.Body.Bytes(), &out)
				return w.Code, out, w.Body.String()
			}
			calls := func() int {
				remote.mu.Lock()
				defer remote.mu.Unlock()
				return remote.merchantCalls
			}
			path := "/customer/subscriptions/list?active=true&page=2&limit=5&referenceId=" + url.QueryEscape(org)

			// An approved member lists the organization's subscriptions as subsets.
			status, out, raw := get(path, aliceCookie)
			items, _ := out["items"].([]any)
			if status != 200 || len(items) != 1 || items[0].(map[string]any)["reference_id"] != org || items[0].(map[string]any)["product_id"] != product ||
				strings.Contains(raw, "member@example.test") || strings.Contains(raw, "merchant-only") || strings.Contains(raw, "private") {
				t.Fatal("member could not list the organization's subscriptions", status, raw)
			}
			remote.mu.Lock()
			query := remote.query
			remote.mu.Unlock()
			if len(query) != 5 || query.Get("organization_id") != merchant || query.Get("metadata["+referenceMetadata+"]") != org || query.Get("active") != "true" || query.Get("page") != "2" || query.Get("limit") != "5" {
				t.Fatal("the merchant list was not filtered by the organization", query)
			}
			mu.Lock()
			if len(asked) != 2 || asked[0].Action != "list-subscription" || asked[0].UserID != alice || asked[0].OrganizationID != org || asked[0].Role != "owner" {
				t.Fatalf("the host was not asked twice for the list: %+v", asked)
			}
			asked = nil
			mu.Unlock()

			// Another organization's or merchant's item refuses the page.
			for name, change := range map[string]func(){"reference": func() { remote.reference = uuid.NewString() }, "merchant": func() { remote.merchant = uuid.NewString() }} {
				remote.mu.Lock()
				change()
				remote.mu.Unlock()
				if status, out, _ := get(path, aliceCookie); status != 502 || out["code"] != "POLAR_CUSTOMER_MISMATCH" {
					t.Error("reference list returned another organization's subscription", name, status, out)
				}
				remote.mu.Lock()
				remote.reference, remote.merchant = org, merchant
				remote.mu.Unlock()
			}

			// A non-member, a denied member and a bad reference reach no provider.
			mu.Lock()
			asked = nil
			mu.Unlock()
			before := calls()
			if status, out, _ := get(path, bobCookie); status != 403 || out["code"] != "POLAR_REFERENCE_FORBIDDEN" {
				t.Error("a non-member listed the organization's subscriptions", status, out)
			}
			if status, out, _ := get(path, carolCookie); status != 403 || out["code"] != "POLAR_REFERENCE_FORBIDDEN" {
				t.Error("a denied member listed the organization's subscriptions", status, out)
			}
			mu.Lock()
			if len(asked) != 1 || asked[0].UserID != carol || asked[0].Action != "list-subscription" {
				t.Errorf("the denied member was not put to the host: %+v", asked)
			}
			mu.Unlock()
			if status, out, _ := get("/customer/subscriptions/list?referenceId=%0A", aliceCookie); status != 400 || out["code"] != "POLAR_INVALID_REFERENCE" {
				t.Error("an invalid reference was accepted", status, out)
			}
			if status, out, _ := get("/customer/orders/list?referenceId="+url.QueryEscape(org), aliceCookie); status != 400 || out["code"] != "POLAR_INVALID_QUERY" {
				t.Error("the orders list accepted a reference", status, out)
			}
			if w := readPersonal(a, "GET", path, "", nil, nil); w.Code != 401 {
				t.Error("a signed-out reference list was answered", w.Code)
			}
			if calls() != before {
				t.Fatal("a refused reference list reached Polar")
			}

			// Without referenceId, the customer portal answers and no merchant list is read.
			if status, _, raw := get("/customer/subscriptions/list", aliceCookie); status != 200 || calls() != before {
				t.Fatal("a personal list used the merchant list", status, raw)
			}

			// A membership removed during the call withholds the page.
			remote.mu.Lock()
			remote.onList = func() {
				if _, err := db.ExecContext(context.Background(), quote(`DELETE FROM "member" WHERE "organizationId"=? AND "userId"=?`), org, alice); err != nil {
					t.Error(err)
				}
			}
			remote.mu.Unlock()
			if status, out, raw := get(path, aliceCookie); status != 403 || strings.Contains(raw, "66666666") {
				t.Fatal("a removed member received the organization's subscriptions", status, out)
			}

			// Without the organization section, referenceId is an unknown query key.
			personal, err := New(Options{Client: polargo.New(polargo.WithSecurity("fixture"), polargo.WithClient(remote)), Ledger: ledger, OrganizationID: merchant, Portal: &PortalOptions{URL: portalURL}})
			if err != nil {
				t.Fatal(err)
			}
			plain, err := auth.New(auth.Options{BaseURL: host, Secret: strings.Repeat("r", 40), Store: store, EmailAndPassword: true, Plugins: []auth.Plugin{personal}})
			if err != nil {
				t.Fatal(err)
			}
			before = calls()
			if w := readPersonal(plain, "GET", path, "", aliceCookie, nil); w.Code != 400 || !strings.Contains(w.Body.String(), "POLAR_INVALID_QUERY") || calls() != before {
				t.Fatal("a reference list ran without the organization section", w.Code, w.Body.String())
			}
		})
	}
}
