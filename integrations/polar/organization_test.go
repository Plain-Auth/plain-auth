package polar

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
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
	if strings.Contains(string(raw), "reference_id") || strings.Contains(string(raw), "org_text") {
		t.Fatal("a personal subscription carried a reference or other metadata", string(raw))
	}
}
