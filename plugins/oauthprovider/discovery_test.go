package oauthprovider_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/Plain-Org/plain-auth/plugins/oauthprovider"
)

func TestProtectedResourceMetadataHTTP(t *testing.T) {
	const resource = "https://api.example.test/a%2Fb/v1/?team=north%2Fsouth"
	const path = "/.well-known/oauth-protected-resource/a%2Fb/v1"
	const target = path + "?team=north%2Fsouth"
	scopes := []string{"files:read"}
	disabled := false
	d, err := oauthprovider.NewResourceDiscovery(oauthprovider.ResourceMetadata{
		Resource: resource, ResourceName: "Files", AuthorizationServers: []string{"https://issuer.example.test/auth"},
		ScopesSupported: scopes, BearerMethodsSupported: []string{}, DPoPBoundAccessTokensRequired: &disabled,
	}, oauthprovider.DiscoveryOptions{ProviderScopes: scopes})
	if err != nil {
		t.Fatal(err)
	}
	if d.Path() != path || d.URL() != "https://api.example.test"+target {
		t.Fatal(d.Path(), d.URL())
	}
	scopes[0] = "changed"
	disabled = true
	published, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	var doc oauthprovider.ResourceMetadata
	if err = json.Unmarshal(published, &doc); err != nil || doc.Resource != resource ||
		!slices.Equal(doc.ScopesSupported, []string{"files:read"}) || doc.BearerMethodsSupported == nil ||
		doc.DPoPBoundAccessTokensRequired == nil || *doc.DPoPBoundAccessTokensRequired {
		t.Fatal("published metadata changed with caller configuration", doc, err)
	}
	copy, err := d.MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	copy[0] = '!'
	mux := http.NewServeMux()
	mux.Handle(d.Path(), d)
	server := httptest.NewTLSServer(mux)
	t.Cleanup(server.Close)
	for _, tc := range []struct {
		method, route string
		status        int
	}{
		{"GET", target, 200}, {"HEAD", target, 200}, {"OPTIONS", target, 204}, {"POST", target, 405},
		{"GET", path, 404}, {"GET", path + "?team=other", 404}, {"GET", "/.well-known/oauth-protected-resource/a/b/v1?team=north%2Fsouth", 404},
	} {
		req, err := http.NewRequestWithContext(t.Context(), tc.method, server.URL+tc.route, nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Forwarded", "host=untrusted.example.test;proto=http")
		req.Header.Set("Origin", "https://reader.example.test")
		res, err := server.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(res.Body)
		res.Body.Close()
		if err != nil || res.StatusCode != tc.status {
			t.Errorf("%s %s: %d, %v", tc.method, tc.route, res.StatusCode, err)
		}
		if tc.status == 200 && (res.ContentLength != int64(len(published)) ||
			res.Header.Get("Content-Type") != "application/json" || res.Header.Get("Access-Control-Allow-Origin") != "*") {
			t.Errorf("metadata headers: %v", res.Header)
		}
		if tc.status == 200 && tc.method == "GET" && string(body) != string(published) {
			t.Error("unexpected discovery document", string(body))
		}
		if (tc.method == "OPTIONS" || tc.method == "HEAD") && len(body) != 0 {
			t.Errorf("%s returned a body", tc.method)
		}
		if tc.status == 405 && !strings.Contains(res.Header.Get("Allow"), "GET") {
			t.Error("missing allowed methods")
		}
		if tc.status == 204 && res.Header.Get("Access-Control-Allow-Methods") != "GET, HEAD, OPTIONS" {
			t.Error("missing cross-origin discovery methods")
		}
	}
}

func TestResourceDiscoveryValidation(t *testing.T) {
	const resource = "https://api.example.test"
	const issuer = "https://login.example.test/auth"
	newDoc := func() oauthprovider.ResourceMetadata {
		return oauthprovider.ResourceMetadata{Resource: resource, AuthorizationServers: []string{issuer}}
	}
	for _, raw := range []string{"", "relative", "https://user@api.example.test/path", "https://api.example.test/#", "https://api.example.test/#notes", "http://api.example.test", "urn:resource:api", "https://api.example.test/bad%2", resource + "?tenant=%zz", resource + ":65536"} {
		if _, err := oauthprovider.NewResourceDiscovery(oauthprovider.ResourceMetadata{Resource: raw}, oauthprovider.DiscoveryOptions{}); err == nil {
			t.Errorf("accepted invalid resource %q", raw)
		}
	}
	for _, raw := range []string{issuer + "?", issuer + "?tenant=x", issuer + "#part", "http://login.example.test", "https://user@login.example.test"} {
		doc := newDoc()
		doc.AuthorizationServers = []string{raw}
		if _, err := oauthprovider.NewResourceDiscovery(doc, oauthprovider.DiscoveryOptions{}); err == nil {
			t.Errorf("accepted invalid issuer %q", raw)
		}
	}
	for _, scope := range []string{"openid", "", "two words", "unknown", "a\\b", "a\"b", "非ascii"} {
		doc := newDoc()
		doc.ScopesSupported = []string{scope}
		opts := oauthprovider.DiscoveryOptions{ProviderScopes: []string{scope}}
		if scope == "unknown" {
			opts.ProviderScopes = nil
		}
		if _, err := oauthprovider.NewResourceDiscovery(doc, opts); err == nil {
			t.Errorf("accepted invalid disclosure %q", scope)
		}
	}
	opts := oauthprovider.DiscoveryOptions{ProviderScopes: []string{"read"}, ExternalScopes: []string{"billing"}}
	if _, err := oauthprovider.NewResourceDiscovery(newDoc(), opts); err == nil {
		t.Error("accepted external scopes with a single local issuer")
	}
	for _, change := range []func(*oauthprovider.ResourceMetadata){
		func(d *oauthprovider.ResourceMetadata) { d.JWKSURI = "http://keys.example.test" },
		func(d *oauthprovider.ResourceMetadata) { d.BearerMethodsSupported = []string{"cookie"} },
		func(d *oauthprovider.ResourceMetadata) { d.ResourceSigningAlgorithms = []string{"none"} },
		func(d *oauthprovider.ResourceMetadata) { d.DPoPSigningAlgorithms = []string{"none"} },
		func(d *oauthprovider.ResourceMetadata) { d.DPoPSigningAlgorithms = []string{"HS256"} },
		func(d *oauthprovider.ResourceMetadata) {
			yes := true
			d.DPoPBoundAccessTokensRequired = &yes
			d.DPoPSigningAlgorithms = []string{}
		},
	} {
		doc := newDoc()
		change(&doc)
		if _, err := oauthprovider.NewResourceDiscovery(doc, oauthprovider.DiscoveryOptions{}); err == nil {
			t.Error("accepted an invalid metadata field", doc)
		}
	}
	for key, value := range map[string]json.RawMessage{"resource": json.RawMessage(`"other"`), "jwks_uri": json.RawMessage(`"unexpected"`), "other": json.RawMessage(`{`)} {
		if _, err := oauthprovider.NewResourceDiscovery(newDoc(), oauthprovider.DiscoveryOptions{Extra: map[string]json.RawMessage{key: value}}); err == nil {
			t.Errorf("accepted invalid extension %q", key)
		}
	}
	for _, raw := range []string{resource, resource + "/"} {
		d, err := oauthprovider.NewResourceDiscovery(oauthprovider.ResourceMetadata{Resource: raw}, oauthprovider.DiscoveryOptions{})
		if err != nil || d.Path() != "/.well-known/oauth-protected-resource" {
			t.Fatal("root metadata path", d, err)
		}
	}
}
