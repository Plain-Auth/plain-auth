package sqlstore

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Plain-Org/plain-auth"
	billing "github.com/Plain-Org/plain-auth/plugins/stripe"
	"github.com/Plain-Org/plain-auth/schema"
	sdk "github.com/stripe/stripe-go/v87"
	"golang.org/x/oauth2"
)

// A sign-up creates the user's Stripe customer with the user's email, name
// and metadata over the host's parameters, or links the customer Stripe has
// for a verified email that no other user owns, through search or a list
// when search is unavailable. Failures are logged without the email and
// never fail the sign-up.
func TestSignUpStripeCustomer(t *testing.T) {
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
			var mu sync.Mutex
			var searches, lists, creates []url.Values
			var deletes []string
			var found, listed []map[string]any
			searchStatus, listStatus, createStatus := 200, 200, 200
			made := 0
			transport := localBillingTransport(func(r *http.Request) (*http.Response, error) {
				mu.Lock()
				defer mu.Unlock()
				if err := r.ParseForm(); err != nil {
					return nil, err
				}
				fail := func(status int) *http.Response {
					return stripeJSON(status, map[string]any{"error": map[string]string{"type": "api_error", "code": "fixture_failure", "message": "provider detail"}})
				}
				switch {
				case r.URL.Path == "/v1/customers/search":
					searches = append(searches, r.Form)
					if searchStatus != 200 {
						return fail(searchStatus), nil
					}
					return stripeJSON(200, map[string]any{"object": "search_result", "has_more": false, "data": found}), nil
				case r.URL.Path == "/v1/customers" && r.Method == http.MethodGet:
					lists = append(lists, r.Form)
					if listStatus != 200 {
						return fail(listStatus), nil
					}
					return stripeJSON(200, map[string]any{"object": "list", "has_more": false, "data": listed}), nil
				case r.URL.Path == "/v1/customers" && r.Method == http.MethodPost:
					creates = append(creates, r.PostForm)
					if createStatus != 200 {
						return fail(createStatus), nil
					}
					made++
					return stripeJSON(200, map[string]any{"id": fmt.Sprintf("cus_signup%d", made), "object": "customer", "email": r.PostForm.Get("email")}), nil
				case strings.HasPrefix(r.URL.Path, "/v1/customers/") && r.Method == http.MethodDelete:
					id := strings.TrimPrefix(r.URL.Path, "/v1/customers/")
					deletes = append(deletes, id)
					return stripeJSON(200, map[string]any{"id": id, "object": "customer", "deleted": true}), nil
				}
				return nil, fmt.Errorf("unexpected Stripe call %s %s", r.Method, r.URL.Path)
			})
			remote := sdk.NewClient("sk_test_local", sdk.WithBackends(sdk.NewBackendsWithConfig(&sdk.BackendConfig{HTTPClient: &http.Client{Transport: transport}, MaxNetworkRetries: sdk.Int64(0)})))
			var logMu sync.Mutex
			var logs bytes.Buffer
			logger := slog.New(slog.NewTextHandler(lockedWriter{&logMu, &logs}, nil))
			var created []billing.UserCustomerCreated
			var paramsFor func(billing.NewUserCustomer) (*sdk.CustomerCreateParams, error)
			var onCreate func(billing.UserCustomerCreated) error
			const origin = "https://billing.example"
			off := false
			a, err := plainauth.New(plainauth.Options{Store: store, Secret: strings.Repeat("s", 32), BaseURL: origin, EmailAndPassword: true, RateLimit: &off,
				// Users named "verified ..." sign up with a verified email.
				DatabaseHooks: plainauth.DatabaseHooks{User: plainauth.ModelHooks[plainauth.UserRecord]{Create: plainauth.OperationHooks[plainauth.UserRecord]{
					Before: func(_ context.Context, row *plainauth.UserRecord, _ *plainauth.HookContext) error {
						row.EmailVerified = strings.HasPrefix(row.Name, "verified")
						return nil
					}}}},
				Plugins: []plainauth.Plugin{billing.New(billing.Options{UserCustomers: &billing.UserCustomerOptions{Client: remote, CreateCustomerOnSignUp: true, Logger: logger,
					CustomerCreateParams: func(_ context.Context, in billing.NewUserCustomer) (*sdk.CustomerCreateParams, error) {
						if paramsFor == nil {
							return nil, nil
						}
						return paramsFor(in)
					},
					OnCustomerCreate: func(_ context.Context, c billing.UserCustomerCreated) error {
						mu.Lock()
						created = append(created, c)
						mu.Unlock()
						if onCreate != nil {
							return onCreate(c)
						}
						return nil
					}}})}})
			if err != nil {
				t.Fatal(err)
			}
			customerOf := func(id string) string {
				t.Helper()
				var customer sql.NullString
				if err := store.db.QueryRowContext(ctx, store.bind(`SELECT "stripeCustomerId" FROM "user" WHERE "id"=?`), id).Scan(&customer); err != nil {
					t.Fatal(err)
				}
				return customer.String
			}
			reset := func() {
				mu.Lock()
				searches, lists, creates, deletes, created = nil, nil, nil, nil, nil
				found, listed = nil, nil
				searchStatus, listStatus, createStatus = 200, 200, 200
				mu.Unlock()
				paramsFor, onCreate = nil, nil
				logMu.Lock()
				logs.Reset()
				logMu.Unlock()
			}
			logged := func() string {
				logMu.Lock()
				defer logMu.Unlock()
				return logs.String()
			}
			signUp := func(name string) plainauth.User {
				t.Helper()
				hit, err := a.SignUpEmail(ctx, plainauth.SignUpInput{Name: name, Email: strings.ReplaceAll(name, " ", ".") + "@example.test", Password: "local fixture password"}, plainauth.RequestMeta{})
				if err != nil {
					t.Fatal("the sign-up failed", name, err)
				}
				return hit.User
			}

			// An unverified email is not looked up: a customer is created
			// with the user's email, name and metadata.
			reset()
			user := signUp("new buyer")
			if len(searches)+len(lists) != 0 || len(creates) != 1 || customerOf(user.ID) != "cus_signup1" {
				t.Fatal("an unverified sign-up did not create its own customer", len(searches), len(lists), len(creates), customerOf(user.ID))
			}
			if f := creates[0]; f.Get("email") != user.Email || f.Get("name") != "new buyer" || f.Get("metadata[userId]") != user.ID || f.Get("metadata[customerType]") != "user" {
				t.Fatal("the created customer lacks the user's fields", f)
			}
			if len(created) != 1 || created[0].Customer.ID != "cus_signup1" || created[0].User.ID != user.ID || created[0].Hook != nil {
				t.Fatal("OnCustomerCreate did not report the created customer for a Go call", created)
			}
			if out := logged(); !strings.Contains(out, "Created Stripe customer") || !strings.Contains(out, "customer_id=cus_signup1") || strings.Contains(out, user.Email) {
				t.Fatal("the creation was not logged by ID alone", out)
			}

			// A verified email links the customer search finds when it names
			// no other user, and creates none.
			reset()
			found = []map[string]any{{"id": "cus_found", "object": "customer", "metadata": map[string]string{}}}
			user = signUp("verified buyer")
			if len(searches) != 1 || len(creates) != 0 || customerOf(user.ID) != "cus_found" {
				t.Fatal("a verified sign-up did not link the customer search found", len(searches), len(creates), customerOf(user.ID))
			}
			if q := searches[0].Get("query"); q != `email:"verified.buyer@example.test" AND -metadata["customerType"]:"organization"` || searches[0].Get("limit") != "1" {
				t.Fatal("the customer search is not the email query", searches[0])
			}
			if len(created) != 1 || created[0].Customer.ID != "cus_found" || !strings.Contains(logged(), "Linked existing Stripe customer") {
				t.Fatal("a linked customer was not reported", created, logged())
			}

			// A match that names another user, or that another user holds,
			// is not shared: a new customer is created.
			reset()
			found = []map[string]any{{"id": "cus_theirs", "object": "customer", "metadata": map[string]string{"userId": "someone-else"}}}
			user = signUp("verified second")
			if len(creates) != 1 || customerOf(user.ID) != "cus_signup2" {
				t.Fatal("a customer naming another user was reused", len(creates), customerOf(user.ID))
			}
			reset()
			found = []map[string]any{{"id": "cus_found", "object": "customer", "metadata": map[string]string{}}}
			user = signUp("verified third")
			if len(creates) != 1 || customerOf(user.ID) != "cus_signup3" {
				t.Fatal("a customer another user holds was shared", len(creates), customerOf(user.ID))
			}

			// When search is unavailable, the list by email supplies the
			// first customer that is not an organization's.
			reset()
			searchStatus = 400
			listed = []map[string]any{{"id": "cus_org", "object": "customer", "metadata": map[string]string{"customerType": "organization"}}, {"id": "cus_listed", "object": "customer", "metadata": map[string]string{}}}
			user = signUp("verified listed")
			if len(lists) != 1 || lists[0].Get("email") != user.Email || lists[0].Get("limit") != "100" || len(creates) != 0 || customerOf(user.ID) != "cus_listed" {
				t.Fatal("the list fallback did not link the person's customer", len(lists), len(creates), customerOf(user.ID))
			}

			// A failed lookup, creation or parameters callback leaves the user
			// without a customer and the sign-up intact, and logs no email.
			reset()
			searchStatus, listStatus = 400, 500
			user = signUp("verified outage")
			if len(creates) != 0 || customerOf(user.ID) != "" || !strings.Contains(logged(), "Stripe customer lookup failed") || !strings.Contains(logged(), "code=fixture_failure") || strings.Contains(logged(), user.Email) || strings.Contains(logged(), "provider detail") {
				t.Fatal("a failed lookup did not leave the user alone", len(creates), customerOf(user.ID), logged())
			}
			reset()
			createStatus = 500
			user = signUp("refused buyer")
			if customerOf(user.ID) != "" || len(created) != 0 || !strings.Contains(logged(), "Stripe customer creation failed") || strings.Contains(logged(), user.Email) {
				t.Fatal("a failed creation did not leave the user alone", customerOf(user.ID), created, logged())
			}
			reset()
			paramsFor = func(billing.NewUserCustomer) (*sdk.CustomerCreateParams, error) {
				return nil, errors.New("host detail")
			}
			user = signUp("callback buyer")
			if len(creates) != 0 || customerOf(user.ID) != "" || !strings.Contains(logged(), "Stripe CustomerCreateParams failed") || strings.Contains(logged(), "host detail") {
				t.Fatal("a failed parameters callback still created a customer", len(creates), customerOf(user.ID), logged())
			}

			// The host's parameters are kept beneath the user's email and name
			// and the plugin's metadata keys; request options are refused.
			reset()
			paramsFor = func(in billing.NewUserCustomer) (*sdk.CustomerCreateParams, error) {
				p := &sdk.CustomerCreateParams{Email: sdk.String("host@example.test"), Name: sdk.String("Host Name"), Description: sdk.String("from " + in.User.Name), Metadata: map[string]string{"source": "ads", "userId": "spoofed", "customerType": "organization"}}
				p.Params.Metadata = map[string]string{"campaign": "spring"}
				return p, nil
			}
			user = signUp("param buyer")
			if len(creates) != 1 {
				t.Fatal("the host's parameters did not create a customer", len(creates))
			}
			if f := creates[0]; f.Get("email") != user.Email || f.Get("name") != "param buyer" || f.Get("description") != "from param buyer" || f.Get("metadata[source]") != "ads" || f.Get("metadata[campaign]") != "spring" || f.Get("metadata[userId]") != user.ID || f.Get("metadata[customerType]") != "user" {
				t.Fatal("the host's parameters were not merged beneath the plugin's", f)
			}
			reset()
			paramsFor = func(billing.NewUserCustomer) (*sdk.CustomerCreateParams, error) {
				p := &sdk.CustomerCreateParams{}
				p.SetStripeAccount("acct_connected")
				return p, nil
			}
			user = signUp("connected buyer")
			if len(creates) != 0 || customerOf(user.ID) != "" || !strings.Contains(logged(), "returned unsupported options") {
				t.Fatal("a connected-account customer was created", len(creates), customerOf(user.ID), logged())
			}

			// A personal Checkout reserved while the customer was created keeps
			// its own customer: the new one is not linked and is deleted.
			reset()
			paramsFor = func(in billing.NewUserCustomer) (*sdk.CustomerCreateParams, error) {
				_, err := store.db.ExecContext(ctx, store.bind(`INSERT INTO "verification" ("id","identifier","value","expiresAt","createdAt","updatedAt") VALUES (?,?,?,?,?,?)`), "pending-"+in.User.ID[:16], "stripe-checkout:"+in.User.ID, "{}", time.Now().Add(time.Hour), time.Now(), time.Now())
				return nil, err
			}
			user = signUp("pending buyer")
			if customerOf(user.ID) != "" || len(deletes) != 1 || deletes[0] != "cus_signup5" || len(created) != 0 || !strings.Contains(logged(), "Stripe customer not linked") {
				t.Fatal("a customer was linked over a pending Checkout", customerOf(user.ID), deletes, created, logged())
			}

			// A failing or panicking OnCustomerCreate is logged; the customer
			// stays linked and the HTTP sign-up answers 200 with the endpoint
			// call in the hook.
			reset()
			onCreate = func(billing.UserCustomerCreated) error { return errors.New("host detail") }
			user = signUp("noisy buyer")
			if customerOf(user.ID) != "cus_signup6" || !strings.Contains(logged(), "Stripe OnCustomerCreate failed") || strings.Contains(logged(), "host detail") {
				t.Fatal("a failing OnCustomerCreate undid the link", customerOf(user.ID), logged())
			}
			reset()
			onCreate = func(billing.UserCustomerCreated) error { panic("host panic") }
			raw, _ := json.Marshal(map[string]string{"name": "http buyer", "email": "http.buyer@example.test", "password": "local fixture password"})
			r := httptest.NewRequest(http.MethodPost, origin+"/api/auth/sign-up/email", bytes.NewReader(raw))
			r.Header.Set("Content-Type", "application/json")
			r.Header.Set("Origin", origin)
			w := httptest.NewRecorder()
			a.ServeHTTP(w, r)
			var out struct{ User plainauth.User }
			json.Unmarshal(w.Body.Bytes(), &out)
			if w.Code != 200 || customerOf(out.User.ID) != "cus_signup7" || len(created) != 1 || created[0].Hook == nil || created[0].Hook.Request == nil || !strings.Contains(logged(), "Stripe sign-up customer hook panicked") || strings.Contains(logged(), "host panic") {
				t.Fatal("a panicking OnCustomerCreate failed the HTTP sign-up", w.Code, w.Body.String(), created, logged())
			}

			// The store links only a user without a customer, reports a
			// customer the user already holds as linked, refuses a customer
			// another account holds, and ignores a missing user.
			if linked, err := store.LinkStripeUserCustomer(ctx, out.User.ID, "cus_other"); err != nil || linked {
				t.Fatal("a user's customer was replaced", linked, err)
			}
			if linked, err := store.LinkStripeUserCustomer(ctx, out.User.ID, "cus_signup7"); err != nil || !linked {
				t.Fatal("the user's own customer was not reported as linked", linked, err)
			}
			fresh := signUpWithout(t, ctx, store)
			if _, err := store.LinkStripeUserCustomer(ctx, fresh, "cus_signup7"); !errors.Is(err, billing.ErrCustomerInUse) {
				t.Fatal("another user's customer was linked", err)
			}
			if linked, err := store.LinkStripeUserCustomer(ctx, "missing-user", "cus_missing"); err != nil || linked {
				t.Fatal("a missing user was linked", linked, err)
			}

			// A store failure that stored nothing deletes the created
			// customer; one that may have stored the link keeps it.
			failing := &linkFailures{Store: store}
			other, err := plainauth.New(plainauth.Options{Store: failing, Secret: strings.Repeat("s", 32), BaseURL: origin, EmailAndPassword: true, RateLimit: &off,
				Plugins: []plainauth.Plugin{billing.New(billing.Options{UserCustomers: &billing.UserCustomerOptions{Client: remote, CreateCustomerOnSignUp: true, Logger: logger}})}})
			if err != nil {
				t.Fatal(err)
			}
			for _, maybe := range []bool{false, true} {
				reset()
				failing.maybeStored = maybe
				if _, err := other.SignUpEmail(ctx, plainauth.SignUpInput{Name: "failing buyer", Email: fmt.Sprintf("failing.%v@example.test", maybe), Password: "local fixture password"}, plainauth.RequestMeta{}); err != nil {
					t.Fatal(err)
				}
				mu.Lock()
				removed := len(deletes)
				mu.Unlock()
				if maybe && (removed != 0 || !strings.Contains(logged(), "link not confirmed")) || !maybe && (removed != 1 || !strings.Contains(logged(), "Stripe customer not linked")) {
					t.Fatal("a failed link handled the created customer wrongly", maybe, removed, logged())
				}
			}
		})
	}
}

// linkFailures fails every customer link, reporting whether it may have
// been stored.
type linkFailures struct {
	*Store
	maybeStored bool
}

func (l *linkFailures) LinkStripeUserCustomer(context.Context, string, string) (bool, error) {
	return l.maybeStored, errors.New("link failed")
}

// signUpWithout stores a user directly, with no hooks.
func signUpWithout(t *testing.T, ctx context.Context, store *Store) string {
	t.Helper()
	id := fmt.Sprintf("plain-%d", time.Now().UnixNano())
	if _, err := store.db.ExecContext(ctx, store.bind(`INSERT INTO "user" ("id","name","email","emailVerified","createdAt","updatedAt") VALUES (?,?,?,?,?,?)`), id, "plain", id+"@example.test", false, time.Now(), time.Now()); err != nil {
		t.Fatal(err)
	}
	return id
}

// Customer options are checked at startup: a client is required, and the
// store must link customers on a schema with the user's customer column.
// Without CreateCustomerOnSignUp, a sign-up calls Stripe for nothing.
func TestUserCustomerOptions(t *testing.T) {
	ctx := t.Context()
	open := func(profiles ...string) *Store {
		ddl, err := schema.Generate("sqlite", profiles)
		if err != nil {
			t.Fatal(err)
		}
		store, err := OpenWithSchema(ctx, "sqlite", organizationTestDSN(t, "sqlite"), ddl)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { store.Close() })
		return store
	}
	calls := 0
	remote := sdk.NewClient("sk_test_local", sdk.WithBackends(sdk.NewBackendsWithConfig(&sdk.BackendConfig{HTTPClient: &http.Client{Transport: localBillingTransport(func(*http.Request) (*http.Response, error) {
		calls++
		return nil, errors.New("unexpected Stripe call")
	})}, MaxNetworkRetries: sdk.Int64(0)})))
	build := func(store *Store, o billing.UserCustomerOptions) (*plainauth.Auth, error) {
		return plainauth.New(plainauth.Options{Store: store, Secret: strings.Repeat("s", 32), BaseURL: "https://billing.example", EmailAndPassword: true,
			Plugins: []plainauth.Plugin{billing.New(billing.Options{UserCustomers: &o})}})
	}
	if _, err := build(open("stripe-subscriptions"), billing.UserCustomerOptions{CreateCustomerOnSignUp: true}); err == nil || !strings.Contains(err.Error(), "require a client") {
		t.Fatal("options without a client were accepted", err)
	}
	if _, err := build(open(), billing.UserCustomerOptions{Client: remote, CreateCustomerOnSignUp: true}); err == nil || !strings.Contains(err.Error(), "stripeCustomerId") {
		t.Fatal("a schema without the customer column was accepted", err)
	}
	a, err := build(open("stripe-subscriptions"), billing.UserCustomerOptions{Client: remote})
	if err != nil {
		t.Fatal(err)
	}
	// One plugin value serves one Auth.
	shared := billing.New(billing.Options{UserCustomers: &billing.UserCustomerOptions{Client: remote, CreateCustomerOnSignUp: true}})
	for i, store := range []*Store{open("stripe-subscriptions"), open("stripe-subscriptions")} {
		_, err := plainauth.New(plainauth.Options{Store: store, Secret: strings.Repeat("s", 32), BaseURL: "https://billing.example", EmailAndPassword: true, Plugins: []plainauth.Plugin{shared}})
		if i == 0 && err != nil || i == 1 && (err == nil || !strings.Contains(err.Error(), "serves one Auth")) {
			t.Fatal("a plugin value served a second Auth", i, err)
		}
	}
	if _, err := a.SignUpEmail(ctx, plainauth.SignUpInput{Name: "quiet", Email: "quiet@example.test", Password: "local fixture password"}, plainauth.RequestMeta{}); err != nil || calls != 0 {
		t.Fatal("a sign-up without CreateCustomerOnSignUp called Stripe", err, calls)
	}
}

// With SyncEmail, a user's changed email reaches their Stripe customer once
// stored, an update that keeps it changes nothing, and a deleted or
// unreachable customer or a user without one leaves the update intact; New
// refuses it beside a feature whose user updates skip the hooks.
func TestStripeEmailSync(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			ctx := t.Context()
			ddl, err := schema.Generate(dialect, []string{"stripe-subscriptions"})
			if err != nil {
				t.Fatal(err)
			}
			store, err := OpenWithSchema(ctx, dialect, organizationTestDSN(t, dialect), ddl)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { store.Close() })
			var mu sync.Mutex
			remoteEmail, deleted, down := "", false, false
			var updates []string
			calls := 0
			transport := localBillingTransport(func(r *http.Request) (*http.Response, error) {
				mu.Lock()
				defer mu.Unlock()
				if err := r.ParseForm(); err != nil {
					return nil, err
				}
				calls++
				if r.URL.Path != "/v1/customers/cus_sync" {
					return nil, fmt.Errorf("unexpected Stripe call %s %s", r.Method, r.URL.Path)
				}
				if down {
					return stripeJSON(500, map[string]any{"error": map[string]string{"type": "api_error", "message": "provider detail"}}), nil
				}
				if r.Method == "POST" {
					remoteEmail = r.PostForm.Get("email")
					updates = append(updates, remoteEmail)
				}
				return stripeJSON(200, map[string]any{"id": "cus_sync", "object": "customer", "email": remoteEmail, "deleted": deleted}), nil
			})
			remote := sdk.NewClient("sk_test_local", sdk.WithBackends(sdk.NewBackendsWithConfig(&sdk.BackendConfig{HTTPClient: &http.Client{Transport: transport}, MaxNetworkRetries: sdk.Int64(0)})))
			var logMu sync.Mutex
			var logs bytes.Buffer
			syncing := &billing.UserCustomerOptions{Client: remote, SyncEmail: true, Logger: slog.New(slog.NewTextHandler(lockedWriter{&logMu, &logs}, nil))}
			off := false
			options := plainauth.Options{Store: store, Secret: strings.Repeat("s", 32), BaseURL: "https://billing.example", EmailAndPassword: true, RateLimit: &off,
				ChangeEmailEnabled: true, UpdateEmailWithoutVerification: true,
				Plugins: []plainauth.Plugin{billing.New(billing.Options{UserCustomers: syncing})}}
			a, err := plainauth.New(options)
			if err != nil {
				t.Fatal(err)
			}
			users := 0
			signUp := func(customer string) (plainauth.User, http.Header) {
				t.Helper()
				users++
				hit, err := a.SignUpEmail(ctx, plainauth.SignUpInput{Name: "syncer", Email: fmt.Sprintf("syncer%d@example.test", users), Password: "local fixture password"}, plainauth.RequestMeta{})
				if err != nil {
					t.Fatal(err)
				}
				if customer != "" {
					if _, err := store.db.ExecContext(ctx, store.bind(`UPDATE "user" SET "stripeCustomerId"=? WHERE "id"=?`), customer, hit.User.ID); err != nil {
						t.Fatal(err)
					}
				}
				h := http.Header{}
				h.Add("Cookie", a.SessionCookie(hit.Token, true).String())
				return hit.User, h
			}
			state := func() (int, []string) {
				mu.Lock()
				defer mu.Unlock()
				return calls, slices.Clone(updates)
			}
			logged := func() string {
				logMu.Lock()
				defer logMu.Unlock()
				return logs.String()
			}

			// A changed email reaches the customer, and its log names no address.
			user, h := signUp("cus_sync")
			remoteEmail = user.Email
			if err := a.ChangeEmail(ctx, h, "changed@example.test", ""); err != nil {
				t.Fatal(err)
			}
			if _, got := state(); len(got) != 1 || got[0] != "changed@example.test" || !strings.Contains(logged(), "Synced email to Stripe customer") || strings.Contains(logged(), "changed@example.test") || strings.Contains(logged(), user.Email) {
				t.Fatal("the changed email did not reach the customer", got, logged())
			}
			// An update that keeps the email reads the customer and changes nothing.
			name := "renamed"
			if err := a.UpdateUser(ctx, h, plainauth.ProfileUpdate{Name: &name}); err != nil {
				t.Fatal(err)
			}
			if _, got := state(); len(got) != 1 {
				t.Fatal("an update that kept the email changed the customer", got)
			}
			// A deleted or unreachable customer leaves the update intact.
			deleted = true
			if err := a.ChangeEmail(ctx, h, "second@example.test", ""); err != nil {
				t.Fatal(err)
			}
			deleted, down = false, true
			if err := a.ChangeEmail(ctx, h, "third@example.test", ""); err != nil {
				t.Fatal(err)
			}
			down = false
			if _, got := state(); len(got) != 1 || !strings.Contains(logged(), "Stripe customer was deleted") || !strings.Contains(logged(), "Failed to sync email to Stripe") || strings.Contains(logged(), "provider detail") {
				t.Fatal("a deleted or unreachable customer was changed or failed the update", got, logged())
			}
			// A user without a customer calls no Stripe API.
			before, _ := state()
			_, plain := signUp("")
			if err := a.ChangeEmail(ctx, plain, "plain@example.test", ""); err != nil {
				t.Fatal(err)
			}
			if after, _ := state(); after != before {
				t.Fatal("a user without a customer called Stripe", after-before)
			}
			// New refuses it beside social sign-in.
			options.Plugins = []plainauth.Plugin{billing.New(billing.Options{UserCustomers: syncing})}
			options.SocialProviders = map[string]plainauth.OAuthProvider{"local": {Config: oauth2.Config{ClientID: "local", ClientSecret: "secret", Endpoint: oauth2.Endpoint{AuthURL: "https://idp.example/authorize", TokenURL: "https://idp.example/token"}},
				Resolve: func(context.Context, *oauth2.Token, string) (plainauth.OAuthProfile, error) {
					return plainauth.OAuthProfile{}, nil
				}}}
			if _, err := plainauth.New(options); err == nil || !strings.Contains(err.Error(), "social sign-in") {
				t.Fatal("email sync was accepted beside social sign-in", err)
			}
		})
	}
}
