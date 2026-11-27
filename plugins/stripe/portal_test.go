package stripe_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	auth "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/adapters/memory"
	billing "github.com/Plain-Org/plain-auth/plugins/stripe"
	sdk "github.com/stripe/stripe-go/v87"
)

type transport func(*http.Request) (*http.Response, error)

func (f transport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type customerLookup func(context.Context, string) (string, error)

func (f customerLookup) StripeCustomer(ctx context.Context, id string) (string, error) {
	return f(ctx, id)
}

func TestUserBillingPortal(t *testing.T) {
	var calls int
	var fail, missing bool
	api := sdk.NewBackendsWithConfig(&sdk.BackendConfig{MaxNetworkRetries: sdk.Int64(0), HTTPClient: &http.Client{Transport: transport(func(req *http.Request) (*http.Response, error) {
		calls++
		if fail {
			return &http.Response{StatusCode: 500, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(strings.NewReader(`{"error":{"type":"api_error","message":"down"}}`))}, nil
		}
		if req.URL.Path != "/v1/billing_portal/sessions" || req.Method != "POST" {
			t.Fatal(req.Method, req.URL.Path)
		}
		if err := req.ParseForm(); err != nil {
			t.Fatal(err)
		}
		if req.FormValue("customer") != "cus_local" || req.FormValue("return_url") != "https://app.example/account" || req.FormValue("locale") != "en" {
			t.Fatal("incorrect portal parameters")
		}
		return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(strings.NewReader(`{"id":"bps_test","object":"billing_portal.session","url":"https://billing.example/session"}`))}, nil
	})}})
	var owner string
	portal := billing.PortalOptions{Client: sdk.NewClient("sk_test_fixture", sdk.WithBackends(api)), Customers: customerLookup(func(_ context.Context, id string) (string, error) {
		if id != owner {
			t.Fatal("unscoped customer lookup")
		}
		if missing {
			return "", auth.ErrNotFound
		}
		return "cus_local", nil
	})}
	a, err := auth.New(auth.Options{Store: memory.New(), Secret: strings.Repeat("s", 32), BaseURL: "https://app.example", EmailAndPassword: true, Plugins: []auth.Plugin{billing.New(billing.Options{Portal: &portal})}})
	if err != nil {
		t.Fatal(err)
	}
	res, err := a.SignUpEmail(context.Background(), auth.SignUpInput{Name: "Ada", Email: "ada@example.test", Password: "test-password"}, auth.RequestMeta{})
	if err != nil {
		t.Fatal(err)
	}
	owner = res.User.ID
	run := func(body string, authenticated bool) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("POST", "/api/auth/subscription/billing-portal", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Origin", "https://app.example")
		if authenticated {
			r.AddCookie(a.SessionCookie(res.Token, true))
		}
		a.ServeHTTP(w, r)
		return w
	}
	if w := run("{}", false); w.Code != 401 {
		t.Fatal(w.Code, w.Body)
	}
	if w := run(`{"referenceId":"someone-else"}`, true); w.Code != 400 || !strings.Contains(w.Body.String(), "REFERENCE_ID_NOT_ALLOWED") {
		t.Fatal(w.Code, w.Body)
	}
	if w := run(`{"returnUrl":"https://untrusted.example/"}`, true); w.Code != 403 {
		t.Fatal(w.Code, w.Body)
	}
	w := run(`{"returnUrl":"/account","locale":"en","disableRedirect":true}`, true)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"redirect":false`) || !strings.Contains(w.Body.String(), "https://billing.example/session") || calls != 1 {
		t.Fatalf("portal response: %d %s, %d provider calls", w.Code, w.Body, calls)
	}
	// A missing customer answers before Stripe, a numeric locale is a
	// validation error, Stripe's failure answers 500, and redirect is the
	// default.
	missing = true
	if w := run(`{"returnUrl":"/account","locale":"en"}`, true); w.Code != 404 || !strings.Contains(w.Body.String(), `"CUSTOMER_NOT_FOUND"`) || calls != 1 {
		t.Fatalf("portal failure responses: missing customer %d %s, %d calls", w.Code, w.Body, calls)
	}
	missing = false
	if w := run(`{"returnUrl":"/account","locale":11}`, true); w.Code != 400 || !strings.Contains(w.Body.String(), `"VALIDATION_ERROR"`) || !strings.Contains(w.Body.String(), "[body.locale] Invalid input") {
		t.Fatalf("portal failure responses: numeric locale %d %s", w.Code, w.Body)
	}
	fail = true
	if w := run(`{"returnUrl":"/account","locale":"en"}`, true); w.Code != 500 || !strings.Contains(w.Body.String(), `"UNABLE_TO_CREATE_BILLING_PORTAL"`) {
		t.Fatalf("portal failure responses: Stripe failure %d %s", w.Code, w.Body)
	}
	fail = false
	if w := run(`{"returnUrl":"/account","locale":"en"}`, true); w.Code != 200 || !strings.Contains(w.Body.String(), `"redirect":true`) {
		t.Fatalf("portal failure responses: default redirect %d %s", w.Code, w.Body)
	}
}
