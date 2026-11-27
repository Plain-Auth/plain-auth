package goapi_test

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	authn "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/adapters/sqlstore"
	"github.com/Plain-Org/plain-auth/plugins/oauthprovider"
	"github.com/Plain-Org/plain-auth/schema"
)

type refusingTransport struct{ t *testing.T }

func (r refusingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	r.t.Error("the verifier made a request", req.URL)
	return nil, errors.New("no requests expected")
}

// LocalJWKS reports in-process keys only for a jwt plugin without a remote
// key set. A verifier given the auth instance defaults its issuer to the one
// the instance signs with and reads its keys in process without a request,
// or from its RemoteJWKSURL; without the jwt plugin or Remote it is refused.
func TestResourceVerifierAuthDefaults(t *testing.T) {
	ctx := t.Context()
	build := func(plugins ...authn.Plugin) *authn.Auth {
		t.Helper()
		store, err := sqlstore.OpenWithOptions(ctx, "sqlite", ":memory:", []string{"jwt"}, schema.Options{})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { store.Close() })
		a, err := authn.New(authn.Options{Store: store, BaseURL: "https://auth.example.test", Secret: strings.Repeat("v", 32), Plugins: plugins})
		if err != nil {
			t.Fatal(err)
		}
		return a
	}
	const audience = "https://api.example.test"
	sign := func(a *authn.Auth) string {
		t.Helper()
		now := time.Now()
		token, err := a.SignJWT(ctx, "user", authn.JWTSignOptions{Type: "at+jwt", Issuer: a.OAuthIssuer(), Audience: []string{audience}, IssuedAt: now, ExpiresAt: now.Add(time.Minute), Claims: map[string]any{"scope": "read"}})
		if err != nil {
			t.Fatal(err)
		}
		return token
	}
	if build().LocalJWKS() {
		t.Fatal("an instance without the jwt plugin reported local keys")
	}
	keys, err := authn.NewJWT(authn.JWTOptions{Issuer: "https://issuer.example.test"})
	if err != nil {
		t.Fatal(err)
	}
	local := build(keys)
	if !local.LocalJWKS() {
		t.Fatal("the default jwt plugin did not report local keys")
	}
	v, err := oauthprovider.NewAccessTokenVerifier(oauthprovider.AccessTokenVerifierOptions{Auth: local, Audience: []string{audience}, Transport: refusingTransport{t}})
	if err != nil {
		t.Fatal(err)
	}
	if claims, err := v.VerifyBearer(ctx, sign(local), "read"); err != nil || claims["iss"] != "https://issuer.example.test" {
		t.Fatal("an in-process token did not verify with the instance's defaults", claims, err)
	}
	// A remote key set is fetched from its URL.
	var remote *authn.Auth
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		set, err := remote.PublicJWKS(r.Context())
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(set)
	}))
	t.Cleanup(server.Close)
	remoteKeys, err := authn.NewJWT(authn.JWTOptions{Algorithm: "ES256", RemoteJWKSURL: server.URL + "/jwks.json"})
	if err != nil {
		t.Fatal(err)
	}
	remote = build(remoteKeys)
	if remote.LocalJWKS() {
		t.Fatal("a remote key set was reported local")
	}
	v, err = oauthprovider.NewAccessTokenVerifier(oauthprovider.AccessTokenVerifierOptions{Auth: remote, Audience: []string{audience}, Transport: server.Client().Transport})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.VerifyBearer(ctx, sign(remote)); err != nil {
		t.Fatal("a token did not verify against the remote key set", err)
	}
	// Without the jwt plugin, a verifier needs Remote.
	if _, err := oauthprovider.NewAccessTokenVerifier(oauthprovider.AccessTokenVerifierOptions{Auth: build(), Audience: []string{audience}}); err == nil {
		t.Fatal("a verifier without any key source was accepted")
	}
	if _, err := oauthprovider.NewAccessTokenVerifier(oauthprovider.AccessTokenVerifierOptions{Auth: build(), Audience: []string{audience}, Remote: &oauthprovider.RemoteVerification{ClientID: "api", ClientSecret: "secret"}}); err != nil {
		t.Fatal("Remote did not default its introspection URL", err)
	}
}
