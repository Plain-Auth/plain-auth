package sso

import (
	"io"
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"

	auth "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/adapters/memory"
	"github.com/Plain-Org/plain-auth/internal/publicnet"
	"golang.org/x/oauth2"
)

func TestEnterpriseIdentityTransport(t *testing.T) {
	host, err := auth.New(auth.Options{Store: memory.New(), BaseURL: "https://accounts.example.test", Secret: strings.Repeat("s", 32), TrustedOrigins: []string{"https://*.company.test", "https://login.company.test", "http://idp.company.test", "http://127.0.0.1:10999"}})
	if err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{"http://idp.company.test/authorize", "https://127.0.0.1:10999/token", "https://[::1]/keys", "https://metadata.google.internal/keys"} {
		if secureBrowserEndpoint(host, raw) == nil {
			t.Fatal("unsafe endpoint accepted", raw)
		}
	}
	for _, raw := range []string{"https://example.org/authorize", "http://127.0.0.1:10999/keys"} {
		if e := secureBrowserEndpoint(host, raw); e != nil {
			t.Fatal(e)
		}
	}
	for _, addr := range []string{"10.0.0.4", "127.0.0.1", "::ffff:10.0.0.4", "fd42::123", "169.254.0.4", "100.64.0.8", "2001:db8::1", "2002:c000:201::1", "64:ff9b::7f00:0001", "fe80::1"} {
		if publicnet.Address(netip.MustParseAddr(addr)) {
			t.Fatal("restricted address accepted", addr)
		}
	}
	if !publicnet.Address(netip.MustParseAddr("8.8.8.8")) || !publicnet.Address(netip.MustParseAddr("2606:4700:4700::1111")) {
		t.Fatal("public address rejected")
	}
	if conn, e := publicTransport.DialContext(t.Context(), "tcp", "localhost:10999"); e == nil || conn != nil {
		t.Fatal("public transport dialed local address")
	}
	var requests int
	wire := transportFunc(func(r *http.Request) (*http.Response, error) {
		requests++
		if d, ok := r.Context().Deadline(); !ok || time.Until(d) > 10*time.Second {
			t.Fatal("unbounded provider request")
		}
		res := &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader("{}")), Header: make(http.Header), Request: r}
		switch r.URL.Path {
		case "/redirect":
			res.StatusCode = 307
			res.Header.Set("location", "https://login.company.test/unexpected")
		case "/large":
			res.Body = io.NopCloser(strings.NewReader(strings.Repeat("a", (1<<20)+1)))
		}
		return res, nil
	})
	client := providerHTTP(host, &http.Client{Transport: wire})
	for _, path := range []string{"/redirect", "/large"} {
		if res, e := client.Get("https://login.company.test" + path); e == nil || res != nil {
			t.Fatal("invalid response accepted", path)
		}
	}
	if requests != 2 {
		t.Fatal("followed provider redirect")
	}
	if _, e := client.Get("https://127.0.0.1:10999/token"); e == nil || requests != 2 {
		t.Fatal("forwarded to an unapproved private origin")
	}
	if host.ExplicitlyTrustedOrigin("https://unlisted.company.test") {
		t.Fatal("browser wildcard granted confidential transport")
	}
}

// The email, name and image claims follow oidcConfig.mapping, default to
// email, name and picture, and a mapped email list yields its first
// nonempty address. The raw claims are kept.
func TestEnterpriseIdentityClaimMapping(t *testing.T) {
	var claims, bearer string
	client := &http.Client{Transport: transportFunc(func(r *http.Request) (*http.Response, error) {
		bearer = r.Header.Get("Authorization")
		return &http.Response{Request: r, StatusCode: 200, Body: io.NopCloser(strings.NewReader(claims)), Header: http.Header{}}, nil
	})}
	resolve := func(mapping map[string]any) auth.OAuthProfile {
		t.Helper()
		p := BrowserProvider{Provider: Provider{ProviderID: "acme", Issuer: "https://login.company.test", OIDC: &Config{UserInfoEndpoint: "https://login.company.test/userinfo", Mapping: mapping}}}
		profile, err := resolveIdentity(t.Context(), client, p, &oauth2.Token{AccessToken: "access-token"}, "")
		if err != nil {
			t.Fatal(err)
		}
		return profile
	}
	claims = `{"sub":"employee","email":"default@acme.example","name":"Default Name","picture":"https://img.acme.example/default.png","mail":"mapped@acme.example","display_name":"Mapped Name","avatar":"https://img.acme.example/mapped.png"}`
	mapped := resolve(map[string]any{"email": "mail", "name": "display_name", "image": "avatar"})
	if bearer != "Bearer access-token" {
		t.Fatal("UserInfo was requested without the access token", bearer)
	}
	if mapped.Subject != "employee" {
		t.Fatal("a mapped profile lost the UserInfo subject", mapped.Subject)
	}
	if mapped.Email != "mapped@acme.example" {
		t.Fatal("mapping.email did not select the mapped email claim", mapped.Email)
	}
	if mapped.Name != "Mapped Name" {
		t.Fatal("mapping.name did not select the mapped name claim", mapped.Name)
	}
	if mapped.Image == nil || *mapped.Image != "https://img.acme.example/mapped.png" {
		t.Fatal("mapping.image did not select the mapped image claim", mapped.Image)
	}
	if data, ok := mapped.Data.(map[string]any); !ok || data["mail"] != "mapped@acme.example" || data["email"] != "default@acme.example" {
		t.Fatal("a mapped profile did not keep every raw claim", mapped.Data)
	}
	if plain := resolve(nil); plain.Email != "default@acme.example" || plain.Name != "Default Name" || plain.Image == nil || *plain.Image != "https://img.acme.example/default.png" {
		t.Fatal("the default email, name and picture claims were not used without a mapping", plain)
	}
	claims = `{"sub":"employee","emails":[7,"","first@acme.example","second@acme.example"]}`
	if listed := resolve(map[string]any{"email": "emails"}); listed.Email != "first@acme.example" {
		t.Fatal("a mapped email list did not yield its first nonempty address", listed.Email)
	}
}

// Registration accepts only claim names in an OIDC mapping.
func TestOIDCMappingShape(t *testing.T) {
	if !validMapping(map[string]any{"email": "mail", "emailVerified": "v", "name": "n", "image": "i", "extraFields": map[string]any{"department": "dept"}}) || !validMapping(nil) {
		t.Fatal("a valid OIDC mapping was refused")
	}
	for _, m := range []map[string]any{{"nickname": "x"}, {"email": 1.0}, {"extraFields": map[string]any{"department": 7.0}}, {"extraFields": "dept"}} {
		if validMapping(m) {
			t.Fatal("an invalid OIDC mapping was accepted", m)
		}
	}
}
