package polar

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	auth "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/adapters/sqlstore"
	"github.com/Plain-Org/plain-auth/schema"
	"github.com/go-sql-driver/mysql"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
	_ "github.com/mattn/go-sqlite3"
	polargo "github.com/polarsource/polar-go"
)

const merchant = "b366834a-53a3-4f7f-a396-41ad2a05fc6a"
const product = "0f847f8d-54fa-4432-afd6-33349a60daca"
const otherProduct = "d55ad275-42fb-46b0-aa98-dc6f1da6dc17"
const host = "https://auth.example.test"
const hosted = "https://checkout.example.test"
const dashboardSecret = "whsec_bG9jYWwtd2ViaG9vay1maXh0dXJlLXByb29m"

func database(t *testing.T, dialect string) (*sql.DB, string) {
	t.Helper()
	ctx := t.Context()
	name := "polar_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	driver, dsn := "sqlite3", filepath.Join(t.TempDir(), "state.db")
	switch dialect {
	case "sqlite":
		dsn += "?_busy_timeout=5000&_txlock=immediate"
	case "postgres", "mysql":
		dsn = os.Getenv("AUTH_TEST_" + strings.ToUpper(dialect) + "_DSN")
		if dsn == "" {
			t.Skip("set AUTH_TEST_" + strings.ToUpper(dialect) + "_DSN for this database")
		}
		driver = "pgx"
		if dialect == "mysql" {
			driver = "mysql"
		}
		parent, err := sql.Open(driver, dsn)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { parent.Close() })
		object := "DATABASE"
		if dialect == "postgres" {
			object = "SCHEMA"
		}
		if _, err = parent.ExecContext(ctx, "CREATE "+object+" "+name); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			q := "DROP " + object + " " + name
			if dialect == "postgres" {
				q += " CASCADE"
			}
			if _, err := parent.Exec(q); err != nil {
				t.Error(err)
			}
		})
		if dialect == "mysql" {
			cfg, err := mysql.ParseDSN(dsn)
			if err != nil {
				t.Fatal(err)
			}
			cfg.DBName = name
			dsn = cfg.FormatDSN()
		} else {
			cfg, err := pgx.ParseConfig(dsn)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(dsn, "://") {
				u, err := url.Parse(dsn)
				if err != nil {
					t.Fatal(err)
				}
				q := u.Query()
				q.Set("search_path", name)
				u.RawQuery = q.Encode()
				dsn = u.String()
			} else {
				dsn = cfg.ConnString() + " search_path=" + name
			}
		}
	}
	db, err := sql.Open(driver, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if dialect == "sqlite" {
		// WAL is a persistent file setting. Select it before opening competing
		// connections so first-use journal conversion cannot race ledger DDL.
		var mode string
		if err := db.QueryRowContext(ctx, "PRAGMA journal_mode=WAL").Scan(&mode); err != nil || mode != "wal" {
			t.Fatalf("enable SQLite WAL: mode %q, error %v", mode, err)
		}
		dsn, _, _ = strings.Cut(dsn, "?")
	}
	return db, dsn
}

type transport func(*http.Request) (*http.Response, error)

func (f transport) Do(r *http.Request) (*http.Response, error) { return f(r) }

type provider struct {
	mu       sync.Mutex
	calls    int
	latest   map[string]any
	sent     []string
	lost     bool
	snapshot func()
}

func (p *provider) create(r *http.Request) (*http.Response, error) {
	if r.Method == "GET" {
		snapshot := p.saved()
		if snapshot == nil || r.URL.Path != "/v1/checkouts/"+fmt.Sprint(snapshot["id"]) || r.Header.Get("Polar-Version") != apiVersion || r.Header.Get("Authorization") != "Bearer fake-token" {
			return nil, errors.New("unexpected checkout read")
		}
		raw, _ := json.Marshal(snapshot)
		return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(bytes.NewReader(raw)), Request: r}, nil
	}
	if r.Method != "POST" || r.URL.Path != "/v1/checkouts/" || r.Header.Get("Authorization") != "Bearer fake-token" || r.Header.Get("Polar-Version") != apiVersion {
		return nil, errors.New("incorrect SDK request")
	}
	var in struct {
		Products []string          `json:"products"`
		Owner    string            `json:"external_customer_id"`
		Email    string            `json:"customer_email"`
		Success  string            `json:"success_url"`
		Return   string            `json:"return_url"`
		Metadata map[string]string `json:"metadata"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		return nil, err
	}
	if len(in.Products) == 0 || in.Owner == "" || !strings.HasSuffix(in.Email, "@example.test") || in.Metadata[attemptMetadata] == "" {
		return nil, errors.New("missing bound purchase")
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	id := uuid.NewString()
	// Polar lists the offered products in its own order and selects none
	// until the customer chooses among several.
	var offered []map[string]string
	for i := len(in.Products) - 1; i >= 0; i-- {
		offered = append(offered, map[string]string{"id": in.Products[i]})
	}
	selected := ""
	if len(in.Products) == 1 {
		selected = in.Products[0]
	}
	raw := map[string]any{"id": id, "status": "open", "organization_id": merchant, "external_customer_id": in.Owner, "products": offered, "product_id": selected, "success_url": in.Success, "return_url": in.Return, "url": hosted + "/" + id, "expires_at": now.Add(time.Hour), "created_at": now, "metadata": in.Metadata, "client_secret": "internal-sdk-only"}
	p.mu.Lock()
	p.sent = in.Products
	p.mu.Unlock()
	p.mu.Lock()
	p.calls++
	p.latest = raw
	lost, signal := p.lost, p.snapshot
	p.mu.Unlock()
	if signal != nil {
		signal()
	}
	if lost {
		return nil, errors.New("response lost after creation")
	}
	encoded, _ := json.Marshal(raw)
	return &http.Response{StatusCode: 201, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(bytes.NewReader(encoded)), Request: r}, nil
}
func (p *provider) saved() map[string]any {
	p.mu.Lock()
	defer p.mu.Unlock()
	cloned := map[string]any{}
	for k, v := range p.latest {
		cloned[k] = v
	}
	return cloned
}
func (p *provider) count() int { p.mu.Lock(); defer p.mu.Unlock(); return p.calls }

func call(h http.Handler, path, raw, key string, cookie *http.Cookie, headers http.Header) *httptest.ResponseRecorder {
	r := httptest.NewRequest("POST", host+"/api/auth"+path, strings.NewReader(raw))
	for k, vs := range headers {
		for _, v := range vs {
			r.Header.Add(k, v)
		}
	}
	r.Header.Set("Content-Type", "application/json")
	if cookie != nil {
		r.AddCookie(cookie)
		r.Header.Set("Origin", host)
	}
	if key != "" {
		r.Header.Set("Idempotency-Key", key)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}
func eventPayload(typ string, data map[string]any) string {
	raw, _ := json.Marshal(map[string]any{"api_version": apiVersion, "timestamp": data["created_at"], "type": typ, "data": data})
	return string(raw)
}
func signed(raw, id string, stamp time.Time, legacy bool) http.Header {
	var secret []byte
	if legacy {
		secret = []byte(dashboardSecret)
	} else {
		secret, _ = base64.StdEncoding.DecodeString(strings.TrimPrefix(dashboardSecret, "whsec_"))
	}
	timestamp := strconv.FormatInt(stamp.Unix(), 10)
	mac := hmac.New(sha256.New, secret)
	fmt.Fprintf(mac, "%s.%s.%s", id, timestamp, raw)
	return http.Header{"Webhook-Timestamp": {timestamp}, "Webhook-Id": {id}, "Webhook-Signature": {"v1," + base64.StdEncoding.EncodeToString(mac.Sum(nil))}}
}
func expect(t *testing.T, w *httptest.ResponseRecorder, status int) string {
	t.Helper()
	if w.Code != status {
		t.Fatalf("HTTP %d expected %d, response %s", w.Code, status, w.Body.String())
	}
	return w.Body.String()
}

func TestOwnedCheckoutAndVerifiedDeliveries(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			ctx := t.Context()
			db, dsn := database(t, dialect)
			ddl, err := schema.Generate(dialect, []string{"anonymous", "admin"})
			if err != nil {
				t.Fatal(err)
			}
			store, err := sqlstore.OpenWithSchema(ctx, dialect, dsn, ddl)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { store.Close() })
			ready := make(chan error, 3)
			for range 3 {
				go func() { _, err := OpenLedger(ctx, db, dialect); ready <- err }()
			}
			for range 3 {
				if err := <-ready; err != nil {
					t.Fatalf("concurrent ledger initialization: %v", err)
				}
			}
			ledger, err := OpenLedger(ctx, db, dialect)
			if err != nil {
				t.Fatal(err)
			}
			mock := new(provider)
			var reject atomic.Bool
			// The handler fulfils once per checkout and status, as the guide advises.
			var handledMu sync.Mutex
			fulfilled := map[string]Purchase{}
			byDelivery := map[string]*Purchase{}
			handled := 0
			purchases := func() int {
				handledMu.Lock()
				defer handledMu.Unlock()
				return len(fulfilled)
			}
			opts := Options{Client: polargo.New(polargo.WithSecurity("fake-token"), polargo.WithClient(transport(mock.create))), Ledger: ledger, OrganizationID: merchant,
				Checkout: &CheckoutOptions{Products: map[string]string{"pro": product, "team": otherProduct}, HostedOrigin: hosted, SuccessURL: "/success?checkout_id={CHECKOUT_ID}", ReturnURL: "/cancel"}}
			opts.Webhooks = &WebhookOptions{Secret: dashboardSecret,
				OnEvent: func(ctx context.Context, e Event) error {
					// No ledger transaction is open while the handler runs.
					probe, cancel := context.WithTimeout(ctx, 2*time.Second)
					defer cancel()
					if _, err := ledger.db.ExecContext(probe, ledger.bind("UPDATE plainauth_polar_checkout SET status=status WHERE 1=0")); err != nil {
						return err
					}
					handledMu.Lock()
					handled++
					byDelivery[e.DeliveryID] = e.Purchase
					if p := e.Purchase; p != nil && (e.Checkout == nil || e.Checkout.ID != p.CheckoutID) {
						t.Errorf("a reserved delivery lost its typed checkout: %s", e.DeliveryID)
					}
					if p := e.Purchase; p != nil {
						fulfilled[p.CheckoutID+":"+p.Status] = *p
					}
					handledMu.Unlock()
					if reject.Swap(false) {
						return errors.New("transient callback failure")
					}
					return nil
				}}
			makeAuth := func(override Options) *auth.Auth {
				t.Helper()
				p, err := New(override)
				if err != nil {
					t.Fatal(err)
				}
				credential := auth.Plugin{ID: "verified-application", CredentialSessions: &auth.CredentialSessionResolver{
					Matches: func(headers http.Header) bool { return headers.Get("X-Fixture-Key") == "worker" },
					Resolve: func(context.Context, http.Header, auth.RequestMeta, time.Duration) (*auth.CredentialSession, error) {
						return &auth.CredentialSession{Identity: auth.SessionResult{Session: auth.Session{ID: "worker", UserID: "worker"}, User: auth.User{ID: "worker", EmailVerified: true}}}, nil
					},
				}}
				a, err := auth.New(auth.Options{BaseURL: host, Secret: strings.Repeat("x", 40), Store: store, EmailAndPassword: true, Plugins: []auth.Plugin{p, credential}})
				if err != nil {
					t.Fatal(err)
				}
				return a
			}
			a := makeAuth(opts)
			signup := func(name string) (string, *http.Cookie) {
				t.Helper()
				v, err := a.SignUpEmail(ctx, auth.SignUpInput{Name: name, Email: name + "@example.test", Password: "fixture-password"}, auth.RequestMeta{})
				if err != nil {
					t.Fatal(err)
				}
				return v.User.ID, a.SessionCookie(v.Token, true)
			}
			verify := func(id string) {
				q := "UPDATE \"user\" SET \"emailVerified\"=TRUE WHERE \"id\"=?"
				if dialect == "mysql" {
					q = strings.ReplaceAll(q, "\"", "`")
				}
				if _, err := db.Exec(ledger.bind(q), id); err != nil {
					t.Fatal(err)
				}
			}
			user, alice := signup("alice")
			bobID, bob := signup("bob")
			verify(bobID)
			buy := func(h http.Handler, c *http.Cookie, key, raw string) *httptest.ResponseRecorder {
				return call(h, "/checkout", raw, key, c, nil)
			}
			const body = `{"slug":"pro","redirect":false}`
			expect(t, buy(a, nil, "one", body), 401)
			expect(t, call(a, "/checkout", body, "worker", nil, http.Header{"X-Fixture-Key": {"worker"}}), 403)
			expect(t, buy(a, alice, "one", body), 403)
			verify(user)
			for _, bad := range []string{`{"slug":"unknown"}`, `{"products":["wrong"]}`, `{"slug":"pro","referenceId":"tenant"}`, `{"slug":"pro","customerId":"other"}`, `{"slug":"pro","success_url":"https://evil.test"}`} {
				expect(t, buy(a, alice, "one", bad), 400)
			}
			if mock.count() != 0 {
				t.Fatal("untrusted identity or fields reached Polar")
			}
			accountSQL := func(query string, args ...any) {
				t.Helper()
				if dialect == "mysql" {
					query = strings.ReplaceAll(query, "\"", string(rune(96)))
				}
				if _, err := db.Exec(ledger.bind(query), args...); err != nil {
					t.Fatal(err)
				}
			}
			accountSQL(`UPDATE "user" SET "isAnonymous"=TRUE WHERE "id"=?`, user)
			expect(t, buy(a, alice, "guest", body), 403)
			accountSQL(`UPDATE "user" SET "isAnonymous"=FALSE WHERE "id"=?`, user)
			accountSQL(`UPDATE "session" SET "impersonatedBy"=? WHERE "userId"=?`, bobID, user)
			expect(t, buy(a, alice, "delegated", body), 403)
			accountSQL(`UPDATE "session" SET "impersonatedBy"=NULL WHERE "userId"=?`, user)
			if mock.count() != 0 {
				t.Fatal("guest or impersonated session reached checkout")
			}
			first := expect(t, buy(a, alice, "one", body), 200)
			if strings.Contains(first, "internal-sdk-only") || !strings.Contains(first, `"redirect":false`) {
				t.Fatal("checkout result disclosed a secret or lost redirect preference")
			}
			freshLedger, err := OpenLedger(ctx, db, dialect)
			if err != nil {
				t.Fatal(err)
			}
			opts.Ledger = freshLedger
			replica := makeAuth(opts)
			// A node with only webhooks completes checkouts other nodes reserved.
			hooksOnly := makeAuth(Options{Client: opts.Client, OrganizationID: merchant, Ledger: ledger, Webhooks: opts.Webhooks})
			if got := expect(t, buy(replica, alice, "one", body), 200); got != first || mock.count() != 1 {
				t.Fatal("restart did not reuse the original hosted checkout")
			}
			expect(t, buy(replica, alice, "one", `{"slug":"team"}`), 409)
			if second := expect(t, buy(replica, bob, "one", fmt.Sprintf(`{"products":["%s"]}`, product)), 200); second == first || mock.count() != 2 {
				t.Fatal("checkout ownership crossed users")
			}
			mock.mu.Lock()
			mock.lost = true
			mock.mu.Unlock()
			expect(t, buy(a, alice, "lost", body), 409)
			expect(t, buy(replica, alice, "lost", body), 409)
			if mock.count() != 3 {
				t.Fatal("ambiguous provider response caused a second remote POST")
			}
			snapshot := mock.saved()
			notify := func(h http.Handler, raw, id string) *httptest.ResponseRecorder {
				return call(h, "/polar/webhooks", raw, "", nil, signed(raw, id, time.Now(), false))
			}
			raw := eventPayload("checkout.created", snapshot)
			expect(t, call(a, "/polar/webhooks", raw, "", nil, nil), 403)
			expect(t, call(a, "/polar/webhooks", raw+" ", "", nil, signed(raw, "tampered", time.Now(), false)), 403)
			expect(t, call(a, "/polar/webhooks", raw, "", nil, signed(raw, "expired", time.Now().Add(-6*time.Minute), false)), 403)
			for k, v := range map[string]any{"external_customer_id": bobID, "organization_id": otherProduct, "product_id": otherProduct, "url": "https://evil.test/checkout"} {
				wrong := mock.saved()
				wrong[k] = v
				expect(t, notify(replica, eventPayload("checkout.created", wrong), "mismatch-"+k), 409)
			}
			expect(t, call(a, "/polar/webhooks", raw, "", nil, signed(raw, "future", time.Now().Add(6*time.Minute), false)), 403)
			ambiguous := signed(raw, "two-headers", time.Now(), false)
			ambiguous.Add("Webhook-Id", "other")
			expect(t, call(a, "/polar/webhooks", raw, "", nil, ambiguous), 403)
			unknown := eventPayload("unrelated.new.event", nil)
			expect(t, notify(a, unknown, "future-event-type"), 200)
			// A failing handler answers 400 after the ledger committed the
			// delivery, so the lost response recovers and the retry, on a node
			// with only webhooks, runs the handler again.
			reject.Store(true)
			if w := notify(a, raw, "created"); w.Code != 400 || !strings.Contains(w.Body.String(), "POLAR_WEBHOOK_ERROR") || strings.Contains(w.Body.String(), "transient") {
				t.Fatal("a failing handler was not answered with POLAR_WEBHOOK_ERROR", w.Code, w.Body.String())
			}
			expect(t, buy(hooksOnly, alice, "lost", body), 404)
			expect(t, notify(hooksOnly, raw, "created"), 200)
			if !strings.Contains(expect(t, buy(replica, alice, "lost", body), 200), snapshot["id"].(string)) {
				t.Fatal("signed event failed to recover lost response")
			}
			expect(t, notify(a, raw, "created"), 200)
			expect(t, notify(a, raw+" ", "created"), 409)
			handledMu.Lock()
			opened, runs := fulfilled[snapshot["id"].(string)+":open"], handled
			handledMu.Unlock()
			if purchases() != 1 || opened.OwnerID == "" || opened.ProductID != product || opened.Changed.IsZero() || runs < 3 {
				t.Fatalf("the open purchase was not reported once per state: %d %+v %d", purchases(), opened, runs)
			}
			snapshot["status"] = "succeeded"
			snapshot["modified_at"] = time.Now().Add(time.Minute).UTC()
			updated := eventPayload("checkout.updated", snapshot)
			var wg sync.WaitGroup
			codes := make(chan int, 4)
			for range 4 {
				wg.Go(func() { codes <- notify(replica, updated, "updated").Code })
			}
			wg.Wait()
			close(codes)
			for code := range codes {
				if code != 200 {
					t.Fatalf("concurrent duplicate returned %d", code)
				}
			}
			handledMu.Lock()
			before := handled
			handledMu.Unlock()
			expect(t, notify(a, raw, "old-open"), 200)
			expect(t, buy(a, alice, "lost", body), 409)
			handledMu.Lock()
			staleRan, stalePurchase := handled-before, byDelivery["old-open"]
			handledMu.Unlock()
			if purchases() != 2 || staleRan != 1 || stalePurchase != nil {
				t.Fatalf("a stale delivery was reported as a purchase: %d %d", purchases(), staleRan)
			}
			// A read-only provider fetch can recover a known, bound checkout even if webhook delivery is delayed.
			expect(t, buy(replica, bob, "read-recovery", body), 409)
			recovery, err := NewService(opts)
			if err != nil {
				t.Fatal(err)
			}
			saved := mock.saved()
			if err := recovery.ReconcileCheckout(ctx, saved["id"].(string)); err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(expect(t, buy(a, bob, "read-recovery", body), 200), saved["id"].(string)) {
				t.Fatal("read-only recovery lost customer ownership")
			}
			if purchases() != 2 {
				t.Fatal("operator recovery synthesized a provider delivery")
			}

			// Expiry must be authenticated and carry Polar's expired checkout status.
			expect(t, notify(a, eventPayload("checkout.expired", saved), "expiry"), 409)
			saved["status"] = "expired"
			saved["modified_at"] = time.Now().Add(time.Second).UTC()
			expect(t, notify(a, eventPayload("checkout.expired", saved), "expiry"), 200)
			if got := expect(t, buy(replica, bob, "read-recovery", body), 409); strings.Contains(got, hosted) {
				t.Fatal("an expired checkout still disclosed its hosted URL")
			}

			// Polar may deliver a signed completion before the original SDK response reaches the handler.
			mock.mu.Lock()
			mock.lost = false
			mock.snapshot = func() {
				current := mock.saved()
				current["status"] = "succeeded"
				current["modified_at"] = time.Now().Add(time.Second).UTC()
				expect(t, notify(replica, eventPayload("checkout.updated", current), "early-success"), 200)
			}
			mock.mu.Unlock()
			if got := expect(t, buy(a, bob, "early-event", body), 409); strings.Contains(got, hosted) {
				t.Fatal("an older SDK response reopened an already completed checkout")
			}

			// Multiple replicas select one sender. Hold the remote response while the others retry.
			started, release := make(chan struct{}), make(chan struct{})
			mock.mu.Lock()
			mock.lost = false
			mock.snapshot = func() { close(started); <-release }
			mock.mu.Unlock()
			final := make(chan *httptest.ResponseRecorder, 1)
			go func() { final <- buy(a, alice, "concurrent", body) }()
			select {
			case <-started:
			case <-time.After(5 * time.Second):
				t.Fatal("provider was not reached")
			}
			expect(t, buy(replica, alice, "concurrent", body), 409)
			// Revocation during the provider call must withhold the hosted URL.
			accountSQL(`DELETE FROM "session" WHERE "userId"=?`, user)
			close(release)
			if result := <-final; result.Code != 401 || strings.Contains(result.Body.String(), hosted) {
				t.Fatal("revoked owner recovered a hosted checkout")
			}
			mock.mu.Lock()
			mock.snapshot = nil
			mock.mu.Unlock()
			if mock.count() != 6 {
				t.Fatal("concurrent requests issued duplicate remote checkout")
			}

			legacySecret := *opts.Webhooks
			legacySecret.LegacySecret = true
			opts.Webhooks = &legacySecret
			legacy := makeAuth(opts)
			expect(t, call(legacy, "/polar/webhooks", updated, "", nil, signed(updated, "updated", time.Now(), true)), 200)
			expect(t, call(a, "/polar/webhooks", updated, "", nil, signed(updated, "wrong-mode", time.Now(), true)), 403)
		})
	}
}

func TestGuestOwnerAcrossPostgresSearchPath(t *testing.T) {
	ctx := t.Context()
	db, dsn := database(t, "postgres")
	ddl, err := schema.Generate("postgres", []string{"anonymous"})
	if err != nil {
		t.Fatal(err)
	}
	store, err := sqlstore.OpenWithSchema(ctx, "postgres", dsn, ddl)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	authOpts := auth.Options{BaseURL: host, Secret: strings.Repeat("z", 40), Store: store}
	anonymous, err := auth.NewAnonymous(auth.AnonymousOptions{EmailDomainName: "example.test"})
	if err != nil {
		t.Fatal(err)
	}
	authOpts.Plugins = []auth.Plugin{anonymous}
	issuer, err := auth.New(authOpts)
	if err != nil {
		t.Fatal(err)
	}
	login := call(issuer, "/sign-in/anonymous", "{}", "", nil, nil)
	expect(t, login, 200)
	var guest auth.AuthResult
	if err := json.Unmarshal(login.Body.Bytes(), &guest); err != nil || guest.Token == "" || guest.User.IsAnonymous == nil || !*guest.User.IsAnonymous {
		t.Fatalf("missing issued guest account: %v", err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE "user" SET "emailVerified"=TRUE WHERE id=$1`, guest.User.ID); err != nil {
		t.Fatal(err)
	}

	// The ledger resolves its own tables in the first schema and the auth tables in the second.
	leading := "polar_empty_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if _, err := db.ExecContext(ctx, "CREATE SCHEMA "+leading); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := db.Exec("DROP SCHEMA " + leading + " CASCADE"); err != nil {
			t.Error(err)
		}
	})
	cfg, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	cfg.RuntimeParams["search_path"] = leading + "," + cfg.RuntimeParams["search_path"]
	mixed := stdlib.OpenDB(*cfg)
	defer mixed.Close()
	ledger, err := OpenLedger(ctx, mixed, "postgres")
	if err != nil {
		t.Fatal(err)
	}
	mock := new(provider)
	billing, err := New(Options{
		Client: polargo.New(polargo.WithSecurity("fake-token"), polargo.WithClient(transport(mock.create))),
		Ledger: ledger, OrganizationID: merchant,
		Checkout: &CheckoutOptions{Products: map[string]string{"pro": product}, HostedOrigin: hosted, SuccessURL: "/success"},
		Webhooks: &WebhookOptions{Secret: dashboardSecret},
		Portal:   &PortalOptions{URL: portalURL},
	})
	if err != nil {
		t.Fatal(err)
	}
	// The checkout node deliberately omits the anonymous plugin. It must still enforce the actual account row.
	authOpts.Plugins = []auth.Plugin{billing}
	checkout, err := auth.New(authOpts)
	if err != nil {
		t.Fatal(err)
	}
	result := call(checkout, "/checkout", `{"slug":"pro"}`, "guest-attempt", issuer.SessionCookie(guest.Token, true), nil)
	expect(t, result, 403)
	for _, path := range []string{"/customer/portal", "/customer/state"} {
		result := readPersonal(checkout, "GET", path, "", issuer.SessionCookie(guest.Token, true), http.Header{"Sec-Fetch-Site": {"same-origin"}})
		expect(t, result, 403)
	}
	var reservations int
	if err := mixed.QueryRowContext(ctx, "SELECT COUNT(*) FROM plainauth_polar_checkout").Scan(&reservations); err != nil {
		t.Fatal(err)
	}
	if mock.count() != 0 || reservations != 0 || strings.Contains(result.Body.String(), hosted) {
		t.Fatal("a guest selected from the second PostgreSQL schema obtained a purchase")
	}
}

// Client and the merchant are always required; each section mounts only
// its routes and needs a ledger; checkout needs products and a success URL.
func TestOptionSections(t *testing.T) {
	client := polargo.New(polargo.WithSecurity("fixture"))
	const merchant = "11111111-1111-4111-8111-111111111111"
	const product = "22222222-2222-4222-8222-222222222222"
	ledger := &Ledger{}
	checkout := &CheckoutOptions{Products: map[string]string{"pro": product}, HostedOrigin: "https://polar.test", SuccessURL: "/success"}
	for name, tc := range map[string]struct {
		opts Options
		want string
	}{
		"no client":           {Options{OrganizationID: merchant}, "polar: configure a client and the merchant organization UUID"},
		"no merchant":         {Options{Client: client}, "polar: configure a client and the merchant organization UUID"},
		"checkout ledger":     {Options{Client: client, OrganizationID: merchant, Checkout: checkout}, "polar: checkout, portal, webhooks and usage need a ledger"},
		"webhooks ledger":     {Options{Client: client, OrganizationID: merchant, Webhooks: &WebhookOptions{Secret: "whsec_x"}}, "polar: checkout, portal, webhooks and usage need a ledger"},
		"portal ledger":       {Options{Client: client, OrganizationID: merchant, Portal: &PortalOptions{URL: "https://polar.test/portal"}}, "polar: checkout, portal, webhooks and usage need a ledger"},
		"no products":         {Options{Client: client, OrganizationID: merchant, Ledger: ledger, Checkout: &CheckoutOptions{HostedOrigin: "https://polar.test", SuccessURL: "/success"}}, "polar: checkout needs products and a success URL"},
		"no success":          {Options{Client: client, OrganizationID: merchant, Ledger: ledger, Checkout: &CheckoutOptions{Products: checkout.Products, HostedOrigin: "https://polar.test"}}, "polar: checkout needs products and a success URL"},
		"bad origin":          {Options{Client: client, OrganizationID: merchant, Ledger: ledger, Checkout: &CheckoutOptions{Products: checkout.Products, HostedOrigin: "http://polar.test", SuccessURL: "/success"}}, "polar: hosted origin must be an exact HTTPS origin"},
		"no webhook secret":   {Options{Client: client, OrganizationID: merchant, Ledger: ledger, Webhooks: &WebhookOptions{}}, "polar: a webhook signing secret is required"},
		"no authorization":    {Options{Client: client, OrganizationID: merchant, Ledger: ledger, Checkout: checkout, Organization: &OrganizationOptions{}}, "polar: organization references need AuthorizeReference"},
		"organization only":   {Options{Client: client, OrganizationID: merchant, Ledger: ledger, Organization: &OrganizationOptions{AuthorizeReference: func(ReferenceAuthorization) bool { return true }}}, "polar: organization references need the checkout or portal section"},
		"organization server": {Options{Client: client, OrganizationID: merchant, Ledger: ledger, Checkout: checkout, Organization: &OrganizationOptions{ServerURL: "https://api.polar.test/v1", AuthorizeReference: func(ReferenceAuthorization) bool { return true }}}, "polar: the organization server URL must be an HTTPS origin"},
		"organization ledger": {Options{Client: client, OrganizationID: merchant, Checkout: checkout, Organization: &OrganizationOptions{AuthorizeReference: func(ReferenceAuthorization) bool { return true }}}, "polar: checkout, portal, webhooks and usage need a ledger"},
	} {
		if _, err := NewService(tc.opts); err == nil || err.Error() != tc.want {
			t.Error("an invalid configuration was handled wrongly", name, err)
		}
	}
	bare, err := NewService(Options{Client: client, OrganizationID: merchant})
	if err != nil || len(bare.Plugin().Endpoints) != 0 {
		t.Fatal("a configuration without sections mounted routes", err)
	}
	if err := bare.ReconcileCheckout(t.Context(), product); err == nil || err.Error() != "polar: checkout is not enabled" {
		t.Fatal("recovery ran without checkout", err)
	}
	webhooks, err := NewService(Options{Client: client, OrganizationID: merchant, Ledger: ledger, Webhooks: &WebhookOptions{Secret: "whsec_" + strings.Repeat("A", 32)}})
	if err != nil {
		t.Fatal(err)
	}
	if paths := webhooks.Plugin().Endpoints; len(paths) != 1 || paths[0].Path != "/polar/webhooks" {
		t.Fatal("a webhooks-only configuration mounted other routes", paths)
	}
	// Without checkout, a stored URL keeps its shape checks but any host.
	if !webhooks.hosted("https://any.polar.test/checkout/x") || webhooks.hosted("http://any.polar.test/x") || webhooks.hosted("https://any.polar.test") {
		t.Fatal("a webhooks-only node checked hosted URLs wrongly")
	}
}
