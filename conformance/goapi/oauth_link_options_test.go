package goapi_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	auth "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/adapters/sqlite"
	"github.com/Plain-Org/plain-auth/client"
	"golang.org/x/oauth2"
)

type tenantHeader struct {
	mu     sync.Mutex
	tenant string
}

func (h *tenantHeader) set(tenant string) { h.mu.Lock(); h.tenant = tenant; h.mu.Unlock() }
func (h *tenantHeader) RoundTrip(r *http.Request) (*http.Response, error) {
	h.mu.Lock()
	tenant := h.tenant
	h.mu.Unlock()
	r = r.Clone(r.Context())
	if tenant != "" {
		r.Header.Set("X-Tenant", tenant)
	}
	return http.DefaultTransport.RoundTrip(r)
}

// TrustedProvidersForRequest picks the trusted providers per request, and ID
// token links report the reference's link error codes.
func TestTrustedProvidersForRequest(t *testing.T) {
	ctx := t.Context()
	store, err := sqlite.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	const email = "owner@example.test"
	// An ID token "subject|email|verified" carries its own claims.
	p := auth.OAuthProvider{
		Config: oauth2.Config{ClientID: "mobile-test", Endpoint: oauth2.Endpoint{AuthURL: "https://issuer.example/authorize", TokenURL: "https://issuer.example/token"}},
		Resolve: func(context.Context, *oauth2.Token, string) (auth.OAuthProfile, error) {
			return auth.OAuthProfile{}, errors.New("unused")
		},
		VerifyIDToken: func(_ context.Context, raw, _ string) (auth.OAuthProfile, time.Time, error) {
			claims := strings.Split(raw, "|")
			return auth.OAuthProfile{Subject: claims[0], Email: claims[1], EmailVerified: claims[2] == "1", Name: "Owner"}, time.Now().Add(time.Hour), nil
		},
	}
	var mu sync.Mutex
	var seen []string
	host := httptest.NewUnstartedServer(nil)
	base := "http://" + host.Listener.Addr().String()
	node, err := auth.New(auth.Options{Store: store, Secret: strings.Repeat("s", 40), BaseURL: base, EmailAndPassword: true, RateLimit: new(bool),
		SocialProviders: map[string]auth.OAuthProvider{"mobile": p},
		TrustedProvidersForRequest: func(r *http.Request) ([]string, error) {
			mu.Lock()
			seen = append(seen, r.Header.Get("X-Tenant"))
			mu.Unlock()
			if r.ContentLength != 0 || r.Body != http.NoBody {
				t.Error("the callback received the request body")
			}
			switch r.Header.Get("X-Tenant") {
			case "trusted":
				return []string{"mobile"}, nil
			case "unknown":
				return nil, &auth.APIError{Status: 403, Code: "UNKNOWN_TENANT", Message: "Unknown tenant"}
			}
			return nil, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	host.Config.Handler = node
	host.Start()
	defer host.Close()
	tenant := &tenantHeader{}
	newClient := func() *client.Client {
		c, err := client.New(base, &http.Client{Transport: tenant})
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	owner, visitor := newClient(), newClient()
	created, err := owner.SignUpEmail(ctx, client.SignUpRequest{Email: email, Name: "Owner", Password: "credential fixture"})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.VerifyAccountEmail(ctx, created.User.ID, email, time.Now()); err != nil {
		t.Fatal(err)
	}
	token := func(raw string) client.SocialSignInRequest {
		return client.SocialSignInRequest{Provider: "mobile", IDToken: &client.SocialIDToken{Token: raw, Nonce: "nonce"}}
	}
	code := func(err error) string {
		var api *auth.APIError
		if !errors.As(err, &api) {
			return ""
		}
		return api.Code
	}
	if _, err := owner.LinkSocial(ctx, token("one|"+email+"|0")); code(err) != "LINKING_NOT_ALLOWED" {
		t.Fatal("an untrusted unverified identity linked", err)
	}
	tenant.set("trusted")
	if got, err := owner.LinkSocial(ctx, token("one|"+email+"|0")); err != nil || !got.Status {
		t.Fatal("a trusted unverified identity did not link", got, err)
	}
	if _, err := owner.LinkSocial(ctx, token("two|else@example.test|1")); code(err) != "LINKING_DIFFERENT_EMAILS_NOT_ALLOWED" {
		t.Fatal("a different email linked", err)
	}
	if login, err := visitor.SignInSocial(ctx, token("three|"+email+"|0")); err != nil || login.User == nil || login.User.ID != created.User.ID {
		t.Fatal("a trusted sign-in did not link to the verified owner", login, err)
	}
	tenant.set("unknown")
	if _, err := visitor.SignInSocial(ctx, token("four|"+email+"|1")); code(err) != "UNKNOWN_TENANT" {
		t.Fatal("the callback's error did not fail the request", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if strings.Join(seen, ",") != ",trusted,trusted,trusted,unknown" {
		t.Fatal("unexpected trust lookups", seen)
	}
}
