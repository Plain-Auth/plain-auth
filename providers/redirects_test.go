package providers_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Plain-Org/plain-auth/providers"
)

// Discovery documents and signing keys must be served at their configured
// URL: a redirect is not followed, so a provider cannot steer these
// server-side requests to another address, and the sign-in fails.
func TestProviderRequestsDoNotFollowRedirects(t *testing.T) {
	var elsewhere atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		elsewhere.Add(1)
		http.NotFound(w, r)
	}))
	defer target.Close()

	var issuer *httptest.Server
	issuer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w, `{"issuer":%q,"authorization_endpoint":%q,"token_endpoint":%q,"jwks_uri":%q}`, issuer.URL, issuer.URL+"/authorize", issuer.URL+"/token", issuer.URL+"/keys")
		case "/keys":
			http.Redirect(w, r, target.URL+"/keys", http.StatusFound)
		}
	}))
	defer issuer.Close()
	p, err := providers.OpenIDConnect(t.Context(), issuer.URL, "client", "secret")
	if err != nil {
		t.Fatal(err)
	}
	segment := func(v any) string {
		raw, _ := json.Marshal(v)
		return base64.RawURLEncoding.EncodeToString(raw)
	}
	now := time.Now()
	token := segment(map[string]string{"alg": "RS256", "kid": "k"}) + "." +
		segment(map[string]any{"iss": issuer.URL, "aud": "client", "sub": "s", "email": "s@example.test", "nonce": "n", "iat": now.Unix(), "exp": now.Add(time.Hour).Unix()}) + "." +
		base64.RawURLEncoding.EncodeToString([]byte("signature"))
	if _, _, err := p.VerifyIDToken(t.Context(), token, "n"); err == nil {
		t.Fatal("an ID token verified against redirected keys")
	}
	if elsewhere.Load() != 0 {
		t.Fatal("the key request followed a redirect")
	}

	moved := httptest.NewServer(http.RedirectHandler(target.URL+"/.well-known/openid-configuration", http.StatusFound))
	defer moved.Close()
	if _, err := providers.OpenIDConnect(context.Background(), moved.URL, "client", "secret"); err == nil {
		t.Fatal("discovery followed a redirect")
	}
	if elsewhere.Load() != 0 {
		t.Fatal("the discovery request followed a redirect")
	}
}
