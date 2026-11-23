package oauthprovider_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Plain-Org/plain-auth/plugins/oauthprovider"
)

func TestResourceChallengeThroughHTTP(t *testing.T) {
	const resource = "https://api.example.test/files%2Fteam/?a=1"
	resources := []string{resource, "urn:example:tasks"}
	mappings := map[string]string{"urn:example:tasks": "https://discovery.example.test/tasks"}
	scopes := []string{"read", "read", "write"}
	algs := []string{"ES256"}
	c, err := oauthprovider.NewResourceChallenges(resources, oauthprovider.ChallengeOptions{
		MetadataMappings: mappings, Scopes: scopes, DPoPSigningAlgorithms: algs,
	})
	if err != nil {
		t.Fatal(err)
	}
	resources[0], mappings["urn:example:tasks"], scopes[0], algs[0] = "", "", "", ""
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Expose-Headers", "X-Request-ID")
		written, err := c.Write(w, r, oauthprovider.ResourceFailure{
			Status: http.StatusUnauthorized, Code: "invalid_token",
			Message: "Expired credential", Description: "Expired \"session\"\r\nfor\\team",
		})
		if err != nil || !written {
			t.Errorf("write challenge: %v, %v", written, err)
		}
	}))
	defer server.Close()
	const desc = `error="invalid_token", error_description="Expired 'session' for team"`
	for _, tc := range []struct{ scheme, want string }{
		{"Bearer", "Bearer " + desc + `, resource_metadata="https://api.example.test/.well-known/oauth-protected-resource/files%2Fteam?a=1", scope="read write", Bearer ` + desc + `, resource_metadata="https://discovery.example.test/tasks", scope="read write"`},
		{"dPoP", "DPoP " + desc + `, algs="ES256"`},
	} {
		req, err := http.NewRequestWithContext(t.Context(), "GET", server.URL+"/files", nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", tc.scheme+" fixture")
		response, err := server.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		var body map[string]string
		err = json.NewDecoder(response.Body).Decode(&body)
		response.Body.Close()
		if err != nil || response.StatusCode != 401 || response.Header.Get("WWW-Authenticate") != tc.want {
			t.Fatalf("%s challenge: %v %q, %v", tc.scheme, response.StatusCode, response.Header.Get("WWW-Authenticate"), err)
		}
		if expose := strings.Join(response.Header.Values("Access-Control-Expose-Headers"), ","); expose != "X-Request-ID,WWW-Authenticate" || body["error_description"] != "Expired \"session\"\r\nfor\\team" {
			t.Fatalf("lost application headers or public description: %q %#v", expose, body)
		}
	}
}

func TestResourceChallengeRejectsInvalidConfiguration(t *testing.T) {
	type options = oauthprovider.ChallengeOptions
	const resource = "https://api.example.test"
	for _, tc := range []struct {
		resources []string
		options   options
	}{
		{nil, options{}},
		{[]string{""}, options{}},
		{[]string{"urn:example:unmapped"}, options{}},
		{[]string{"app"}, options{MetadataMappings: map[string]string{"app": "http://api.example.test"}}},
		{[]string{"app"}, options{MetadataMappings: map[string]string{"app": resource + "/#fragment"}}},
		{[]string{"http://api.example.test"}, options{}},
		{[]string{resource + "/?tag=%x"}, options{}},
		{[]string{resource}, options{Scopes: []string{"a b"}}},
		{[]string{resource}, options{DPoPSigningAlgorithms: []string{"HS256"}}},
		{[]string{resource}, options{DPoPSigningAlgorithms: []string{"a\rb"}}},
	} {
		if _, err := oauthprovider.NewResourceChallenges(tc.resources, tc.options); err == nil {
			t.Errorf("accepted invalid challenge configuration %#v", tc)
		}
	}
	c, err := oauthprovider.NewResourceChallenges([]string{resource}, options{})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		failure oauthprovider.ResourceFailure
		invalid bool
	}{
		{oauthprovider.ResourceFailure{Status: 500}, false},
		{oauthprovider.ResourceFailure{Status: 403, Message: "Membership required"}, false},
		{oauthprovider.ResourceFailure{Status: 403, Code: "insufficient_scope"}, false},
		{oauthprovider.ResourceFailure{Status: 403, Code: "insufficient_scope", MissingScopes: []string{"bad scope"}}, true},
		{oauthprovider.ResourceFailure{Status: 401, Code: "bad\ncode"}, true},
	} {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("GET", "/files", nil)
		r.Header.Set("Authorization", "DPoP fixture")
		written, err := c.Write(w, r, tc.failure)
		if written || (err != nil) != tc.invalid || w.Body.Len() != 0 || len(w.Header()) != 0 {
			t.Fatalf("unexpected response for %#v: written=%v err=%v", tc.failure, written, err)
		}
	}
	w := httptest.NewRecorder()
	ok, err := c.Write(w, nil, oauthprovider.ResourceFailure{Status: 401, Code: "invalid_dpop_proof", Message: "Expired proof"})
	if !ok || err != nil || !strings.HasSuffix(w.Header().Get("WWW-Authenticate"), `algs="EdDSA ES256 ES512 PS256 RS256"`) {
		t.Fatalf("default DPoP challenge: %q %v", w.Header().Get("WWW-Authenticate"), err)
	}
}
