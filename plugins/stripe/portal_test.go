package stripe_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	auth "github.com/Stonewrit/stonewrit-auth"
	"github.com/Stonewrit/stonewrit-auth/adapters/memory"
	billing "github.com/Stonewrit/stonewrit-auth/plugins/stripe"
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
	api := sdk.NewBackendsWithConfig(&sdk.BackendConfig{HTTPClient: &http.Client{Transport: transport(func(req *http.Request) (*http.Response, error) {
		calls++
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
	if w := run(`{"referenceId":"someone-else"}`, true); w.Code != 403 {
		t.Fatal(w.Code, w.Body)
	}
	if w := run(`{"returnUrl":"https://untrusted.example/"}`, true); w.Code != 403 {
		t.Fatal(w.Code, w.Body)
	}
	w := run(`{"returnUrl":"/account","locale":"en","disableRedirect":true}`, true)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"redirect":false`) || !strings.Contains(w.Body.String(), "https://billing.example/session") || calls != 1 {
		t.Fatalf("portal response: %d %s, %d provider calls", w.Code, w.Body, calls)
	}
}
