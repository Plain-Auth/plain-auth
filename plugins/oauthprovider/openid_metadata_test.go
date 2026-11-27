package oauthprovider_test

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"

	auth "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/adapters/sqlstore"
	"github.com/Plain-Org/plain-auth/client"
	op "github.com/Plain-Org/plain-auth/plugins/oauthprovider"
	"github.com/Plain-Org/plain-auth/schema"
	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

func TestRelyingPartyDiscoversOpenIDIssuer(t *testing.T) {
	ctx := t.Context()
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	store, err := sqlstore.OpenWithOptions(ctx, "sqlite", ":memory:", []string{"jwt", "oauth-provider"}, schema.Options{})
	must(err)
	t.Cleanup(func() { store.Close() })
	mux := http.NewServeMux()
	server := httptest.NewUnstartedServer(mux)
	t.Cleanup(server.Close)
	base := "http://" + server.Listener.Addr().String()
	issuer := base + "/tenant/acme"
	jwt, err := auth.NewJWT(auth.JWTOptions{Algorithm: "RS256", Issuer: issuer, JWKSPath: "/public/keys"})
	must(err)
	plugin, err := op.New(op.Options{GrantTypes: []string{"authorization_code", "refresh_token"}, Scopes: []string{"openid", "email", "offline_access"}, PairwiseSecret: strings.Repeat("p", 32),
		Registration:  op.RegistrationOptions{Enabled: true, AllowUnauthenticated: true, AllowedScopes: []string{"openid", "email", "offline_access"}},
		Authorization: op.BrowserAuthorizationOptions{ConsentPage: "/approve", LoginPage: "/login"},
	})
	must(err)
	api, err := auth.New(auth.Options{Store: store, BaseURL: base, BasePath: "/identity", Secret: strings.Repeat("s", 40), Plugins: []auth.Plugin{plugin, jwt}, EmailAndPassword: true, RateLimit: new(bool)})
	must(err)
	mux.Handle("/identity/", api)
	for _, path := range api.WellKnownPaths() {
		mux.Handle(path, api)
	}
	server.Start()

	// The relying party starts with a configured issuer and obtains all protocol URLs there.
	provider, err := oidc.NewProvider(ctx, issuer)
	must(err)
	var doc op.OpenIDProviderMetadata
	must(provider.Claims(&doc))
	if doc.Issuer != issuer || doc.AuthorizationEndpoint != base+"/identity/oauth2/authorize" || doc.JWKSURI != base+"/identity/public/keys" ||
		!slices.Equal(doc.IDTokenSigningAlgorithms, []string{"RS256"}) || !slices.Equal(doc.SubjectTypesSupported, []string{"public", "pairwise"}) ||
		!slices.Equal(doc.GrantTypesSupported, []string{"authorization_code", "refresh_token"}) || !slices.Contains(doc.TokenEndpointAuthMethods, "none") {
		t.Fatal("wrong discovery metadata", doc)
	}
	paths := api.WellKnownPaths()
	if !slices.Equal(paths, []string{"/.well-known/oauth-authorization-server/tenant/acme", "/tenant/acme/.well-known/oauth-authorization-server", "/tenant/acme/.well-known/openid-configuration"}) {
		t.Fatal("unexpected discovery paths", paths)
	}
	first, _ := api.WellKnownJSON(paths[0])
	for _, path := range paths {
		raw, ok := api.WellKnownJSON(path)
		if !ok || !slices.Equal(raw, first) {
			t.Fatal("discovery aliases differ", path)
		}
	}
	native, err := op.GetOpenIDConfig(api)
	must(err)
	if !slices.Equal(native.ClaimsSupported, doc.ClaimsSupported) || !slices.Equal(native.PromptValuesSupported, []string{"login", "consent", "create", "none"}) {
		t.Fatal(native)
	}

	jar, err := cookiejar.New(nil)
	must(err)
	browser := &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	sdk, err := client.New(base+"/identity", browser)
	must(err)
	login, err := sdk.SignUpEmail(ctx, client.SignUpRequest{Name: "A Reader", Email: "reader@example.test", Password: "local discovery password"})
	must(err)
	const redirect = "https://rp.example.test/return"
	app, err := sdk.RegisterOAuthClient(ctx, op.RegistrationMetadata{RedirectURIs: []string{redirect}, ApplicationType: "native", TokenEndpointAuthMethod: "none", Scope: "openid email", SubjectType: "pairwise"})
	must(err)
	config := oauth2.Config{ClientID: app.ClientID, RedirectURL: redirect, Scopes: []string{oidc.ScopeOpenID, "email"}, Endpoint: provider.Endpoint()}
	config.Endpoint.AuthStyle = oauth2.AuthStyleInParams
	verifier, nonce, state := oauth2.GenerateVerifier(), oauth2.GenerateVerifier(), oauth2.GenerateVerifier()
	authURL := config.AuthCodeURL(state, oidc.Nonce(nonce), oauth2.S256ChallengeOption(verifier))
	req, err := http.NewRequestWithContext(ctx, "GET", authURL, nil)
	must(err)
	req.Header.Set("Accept", "application/json")
	res, err := browser.Do(req)
	must(err)
	defer res.Body.Close()
	var page struct{ URL string }
	must(json.NewDecoder(res.Body).Decode(&page))
	prompt, err := url.Parse(page.URL)
	must(err)
	if res.StatusCode != 200 || prompt.Path != "/approve" {
		t.Fatal("expected host consent page", res.StatusCode, page)
	}
	fields, err := api.VerifyOAuthPageQuery(prompt.RawQuery)
	must(err)
	target, err := sdk.DecideOAuthConsent(ctx, fields.Encode(), true, nil)
	must(err)
	callback, err := url.Parse(target)
	must(err)
	q := callback.Query()
	if callback.Scheme+"://"+callback.Host+callback.Path != redirect || q.Get("iss") != issuer || q.Get("state") != state || q.Get("code") == "" {
		t.Fatal("unexpected relying-party callback", callback.Path)
	}
	tokens, err := config.Exchange(ctx, q.Get("code"), oauth2.VerifierOption(verifier))
	must(err)
	raw, ok := tokens.Extra("id_token").(string)
	if !ok {
		t.Fatal("issuer omitted ID token")
	}
	identity, err := provider.Verifier(&oidc.Config{ClientID: app.ClientID}).Verify(ctx, raw)
	must(err)
	if identity.Nonce != nonce || identity.Subject == "" || identity.Subject == login.User.ID {
		t.Fatal("wrong nonce or pairwise subject")
	}
	must(identity.VerifyAccessToken(tokens.AccessToken))
	info, err := provider.UserInfo(ctx, oauth2.StaticTokenSource(tokens))
	must(err)
	if info.Subject != identity.Subject || info.Email != "reader@example.test" {
		t.Fatal("wrong UserInfo", info)
	}
}

func TestOpenIDMetadataCapabilities(t *testing.T) {
	store, err := sqlstore.OpenWithOptions(t.Context(), "sqlite", ":memory:", []string{"jwt", "oauth-provider"}, schema.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	sign, err := auth.NewJWT(auth.JWTOptions{})
	if err != nil {
		t.Fatal(err)
	}
	// A public client can be provisioned by an administrator with registration disabled.
	explicit, err := op.New(op.Options{GrantTypes: []string{"authorization_code"}, Metadata: op.IssuerMetadataOptions{TokenAuthMethods: []string{"none"}}})
	if err != nil {
		t.Fatal(err)
	}
	public, err := auth.New(auth.Options{BaseURL: "https://auth.example.test", Secret: strings.Repeat("s", 40), Store: store, Plugins: []auth.Plugin{explicit, sign}})
	if err != nil {
		t.Fatal(err)
	}
	profile, err := op.GetOpenIDConfig(public)
	if err != nil || !slices.Equal(profile.TokenEndpointAuthMethods, []string{"none"}) || profile.RegistrationEndpoint != "" || slices.Contains(profile.IntrospectionEndpointAuthMethods, "none") || len(profile.DPoPSigningAlgorithms) > 0 {
		t.Fatal("incorrect delegated-only public client metadata", profile, err)
	}
	for _, tc := range []struct {
		name              string
		scopes            []string
		grants            []string
		disabled          []string
		signer, discovery bool
	}{
		{"machine only", []string{"openid"}, []string{"client_credentials"}, nil, true, false},
		{"no keys", []string{"openid"}, []string{"authorization_code"}, nil, false, false},
		{"disabled JWKS", []string{"openid"}, nil, []string{"/jwks"}, true, false},
		{"disabled authorize", []string{"openid"}, nil, []string{"/oauth2/authorize"}, true, false},
		{"disabled token", []string{"openid"}, nil, []string{"/oauth2/token"}, true, false},
		{"OAuth only", []string{"reports"}, nil, nil, true, false},
		{"optional UserInfo disabled", []string{"openid"}, nil, []string{"/oauth2/userinfo"}, true, true},
		{"openid omitted from advertised scopes", []string{"openid"}, []string{"authorization_code"}, nil, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, err := op.New(op.Options{Scopes: tc.scopes, GrantTypes: tc.grants, Metadata: op.IssuerMetadataOptions{Scopes: []string{}}})
			if err != nil {
				t.Fatal(err)
			}
			plugins := []auth.Plugin{p}
			if tc.signer {
				plugins = append(plugins, sign)
			}
			api, err := auth.New(auth.Options{BaseURL: "https://auth.example.test", Secret: strings.Repeat("s", 40), Store: store, Plugins: plugins, DisabledPaths: tc.disabled})
			if err != nil {
				t.Fatal(err)
			}
			doc, err := op.GetOpenIDConfig(api)
			if !tc.discovery {
				if !errors.Is(err, auth.ErrNotFound) {
					t.Fatal("unexpected OpenID configuration", err)
				}
				return
			}
			if err != nil || len(doc.ScopesSupported) != 0 || !slices.Equal(doc.PromptValuesSupported, []string{"none"}) ||
				(slices.Contains(tc.disabled, "/oauth2/userinfo") != (doc.UserInfoEndpoint == "")) {
				t.Fatal(doc, err)
			}
		})
	}
}

// Without options the provider advertises the four default scopes; the
// configured UserInfo claims are advertised exactly; and option sets that
// cannot work are refused at construction, as another runtime refuses them.
func TestProviderOptionDefaultsAndRefusals(t *testing.T) {
	store, err := sqlstore.OpenWithOptions(t.Context(), "sqlite", ":memory:", []string{"jwt", "oauth-provider"}, schema.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	sign, err := auth.NewJWT(auth.JWTOptions{})
	if err != nil {
		t.Fatal(err)
	}
	config := func(opts op.Options) op.OpenIDProviderMetadata {
		t.Helper()
		p, err := op.New(opts)
		if err != nil {
			t.Fatal(err)
		}
		api, err := auth.New(auth.Options{BaseURL: "https://auth.example.test", Secret: strings.Repeat("s", 40), Store: store, Plugins: []auth.Plugin{p, sign}})
		if err != nil {
			t.Fatal(err)
		}
		doc, err := op.GetOpenIDConfig(api)
		if err != nil {
			t.Fatal(err)
		}
		return doc
	}
	if doc := config(op.Options{}); !slices.Equal(doc.ScopesSupported, []string{"openid", "profile", "email", "offline_access"}) {
		t.Fatal("the default scopes were not advertised", doc.ScopesSupported)
	}
	if doc := config(op.Options{UserInfo: op.UserInfoOptions{SupportedClaims: []string{"sub", "locale"}}}); !slices.Equal(doc.ClaimsSupported, []string{"sub", "locale"}) {
		t.Fatal("the configured UserInfo claims were not advertised exactly", doc.ClaimsSupported)
	}
	for name, opts := range map[string]op.Options{
		"registration scope outside the scopes": {Scopes: []string{"read"}, Registration: op.RegistrationOptions{AllowedScopes: []string{"write"}}},
		"refresh_token without a delegated grant": {GrantTypes: []string{"refresh_token"}},
		"short pairwise secret":                   {PairwiseSecret: strings.Repeat("p", 31)},
	} {
		if _, err := op.New(opts); err == nil {
			t.Fatal("an unusable provider configuration was accepted", name)
		}
	}
}
