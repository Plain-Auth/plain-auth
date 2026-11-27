package polar

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	auth "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/adapters/sqlstore"
	"github.com/Plain-Org/plain-auth/internal/polarledger"
	"github.com/Plain-Org/plain-auth/schema"
	polargo "github.com/polarsource/polar-go"
)

// A checkout offers up to ten distinct configured products in request
// order, a slug sent with products decides the purchase, a paid checkout
// that offered several must name the one bought, and the delivery reports
// it beside every offered product.
func TestMultiProductCheckout(t *testing.T) {
	const pro = "22222222-2222-4222-8222-222222222222"
	const team = "33333333-3333-4333-8333-333333333333"
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			ctx := t.Context()
			db, dsn := database(t, dialect)
			ddl, err := schema.Generate(dialect, nil)
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
			mock := new(provider)
			var mu sync.Mutex
			var purchases []Purchase
			plugin, err := New(Options{Client: polargo.New(polargo.WithSecurity("fake-token"), polargo.WithClient(transport(mock.create))), Ledger: ledger, OrganizationID: merchant,
				Checkout: &CheckoutOptions{Products: map[string]string{"pro": pro, "team": team}, HostedOrigin: hosted, SuccessURL: "/success"},
				Webhooks: &WebhookOptions{Secret: dashboardSecret, OnEvent: func(_ context.Context, e Event) error {
					if e.Purchase != nil {
						mu.Lock()
						purchases = append(purchases, *e.Purchase)
						mu.Unlock()
					}
					return nil
				}}})
			if err != nil {
				t.Fatal(err)
			}
			a, err := auth.New(auth.Options{BaseURL: host, Secret: strings.Repeat("m", 40), Store: store, EmailAndPassword: true, Plugins: []auth.Plugin{plugin}})
			if err != nil {
				t.Fatal(err)
			}
			v, err := a.SignUpEmail(ctx, auth.SignUpInput{Name: "buyer", Email: "buyer@example.test", Password: "local fixture password"}, auth.RequestMeta{})
			if err != nil {
				t.Fatal(err)
			}
			q := `UPDATE "user" SET "emailVerified"=TRUE WHERE "id"=?`
			if dialect == "mysql" {
				q = strings.ReplaceAll(q, `"`, "`")
			}
			if _, err := db.Exec(ledger.bind(q), v.User.ID); err != nil {
				t.Fatal(err)
			}
			cookie := a.SessionCookie(v.Token, true)
			buy := func(key, raw string) int {
				t.Helper()
				return call(a, "/checkout", raw, key, cookie, nil).Code
			}
			sent := func() []string {
				mock.mu.Lock()
				defer mock.mu.Unlock()
				return slices.Clone(mock.sent)
			}

			// Two products reach Polar in request order, and a retry reuses the purchase.
			if w := call(a, "/checkout", `{"products":["`+pro+`","`+team+`"]}`, "", cookie, nil); w.Code != 200 || !slices.Equal(sent(), []string{pro, team}) {
				t.Fatal("two products were not offered in order", w.Code, w.Body.String(), sent())
			}
			multi := mock.saved()
			// A reservation offering several stores the nil UUID as its single
			// product, so an earlier release never reuses it for one product.
			var single string
			if err := db.QueryRowContext(ctx, ledger.bind("SELECT product FROM plainauth_polar_checkout WHERE products=?"), pro+","+team).Scan(&single); err != nil || single != "00000000-0000-0000-0000-000000000000" {
				t.Fatal("a several-product reservation stored a product an earlier release could match", single, err)
			}
			if code := buy("", `{"products":["`+pro+`","`+team+`"]}`); code != 200 || mock.count() != 1 {
				t.Fatal("a retry did not reuse the purchase", code, mock.count())
			}
			// A slug sent with products decides the purchase.
			if code := buy("slugged", `{"slug":"team","products":["`+pro+`"]}`); code != 200 || !slices.Equal(sent(), []string{team}) {
				t.Fatal("the slug did not decide the purchase", code, sent())
			}
			// Duplicates, unconfigured products, more than ten and non-strings are refused.
			eleven := strings.TrimSuffix(strings.Repeat(`"`+pro+`",`, 11), ",")
			for _, bad := range []string{`{"products":["` + pro + `","` + pro + `"]}`, `{"products":["44444444-4444-4444-8444-444444444444"]}`, `{"products":[` + eleven + `]}`, `{"products":[1]}`, `{"products":[]}`, `{}`} {
				w := call(a, "/checkout", bad, "bad", cookie, nil)
				if w.Code != 400 || !strings.Contains(w.Body.String(), "POLAR_INVALID_PRODUCT") {
					t.Fatal("an invalid product list was accepted", bad, w.Code, w.Body.String())
				}
			}
			// A paid checkout that offered several must name the product
			// bought, and the purchase reports it beside every offered one.
			multi["status"], multi["product_id"], multi["modified_at"] = "succeeded", "", time.Now().UTC().Add(time.Minute)
			unnamed := eventPayload("checkout.updated", multi)
			expect(t, call(a, "/polar/webhooks", unnamed, "", nil, signed(unnamed, "unnamed", time.Now(), false)), 409)
			multi["product_id"] = team
			named := eventPayload("checkout.updated", multi)
			expect(t, call(a, "/polar/webhooks", named, "", nil, signed(named, "named", time.Now(), false)), 200)
			mu.Lock()
			last := purchases[len(purchases)-1]
			mu.Unlock()
			if last.ProductID != team || !slices.Equal(last.ProductIDs, []string{pro, team}) || last.Status != "succeeded" {
				t.Fatalf("the purchase did not report the product bought: %+v", last)
			}
		})
	}
}

// OpenLedger adds a missing column that has a default to a table that
// already holds rows, and a row written before reads its single product.
func TestLedgerUpgradeAddsProducts(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			ctx := t.Context()
			db, _ := database(t, dialect)
			for _, table := range polarledger.Tables(dialect) {
				var columns []string
				for _, column := range table.Columns {
					if !strings.Contains(column, "products") {
						columns = append(columns, column)
					}
				}
				if _, err := db.ExecContext(ctx, "CREATE TABLE "+table.Name+" ("+strings.Join(columns, ", ")+")"); err != nil {
					t.Fatal(err)
				}
			}
			const product = "22222222-2222-4222-8222-222222222222"
			slot := strings.Repeat("a", 64)
			l := &Ledger{db: db, dialect: dialect}
			if _, err := db.ExecContext(ctx, l.bind(`INSERT INTO plainauth_polar_checkout (slot,attempt,owner_id,contact_hash,product,merchant,success_url,return_url,hosted_url,status,expires_ms,changed_us) VALUES (?,?,?,?,?,?,?,?,'','pending',0,0)`),
				slot, "55555555-5555-4555-8555-555555555555", "owner", strings.Repeat("b", 64), product, "11111111-1111-4111-8111-111111111111", "https://app.test/s", ""); err != nil {
				t.Fatal(err)
			}
			ledger, err := OpenLedger(ctx, db, dialect)
			if err != nil {
				t.Fatal("the ledger did not upgrade a table with rows", err)
			}
			row, err := ledger.read(ctx, slot)
			if err != nil || !slices.Equal(row.Products, []string{product}) {
				t.Fatal("a row written before several products did not read its product", row.Products, err)
			}
			raw, _ := json.Marshal(row.Products)
			if string(raw) != `["`+product+`"]` {
				t.Fatal(string(raw))
			}
		})
	}
}
