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

// A loopback HTTP resource gets a challenge with an HTTP metadata link;
// HTTP elsewhere is refused. Prepare computes what Write sends without
// writing, and nothing for a permission denial or a server failure.
func TestResourceChallengeLoopbackAndPrepare(t *testing.T) {
	c, err := oauthprovider.NewResourceChallenges([]string{"http://localhost:3000/mcp"}, oauthprovider.ChallengeOptions{})
	if err != nil {
		t.Fatal(err)
	}
	failure := oauthprovider.ResourceFailure{Status: 401, Code: "invalid_token", Message: "token expired", Description: "token expired"}
	prepared, err := c.Prepare(nil, failure)
	if err != nil || prepared == nil || !strings.Contains(prepared.WWWAuthenticate, `resource_metadata="http://localhost:3000/.well-known/oauth-protected-resource/mcp"`) {
		t.Fatal("a loopback resource did not get its metadata link", prepared, err)
	}
	w := httptest.NewRecorder()
	if written, err := c.Write(w, nil, failure); !written || err != nil {
		t.Fatal(err)
	}
	if w.Code != prepared.Status || w.Header().Get("WWW-Authenticate") != prepared.WWWAuthenticate {
		t.Fatal("Write did not send the prepared challenge", w.Code, w.Header())
	}
	var body map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil || body["message"] != prepared.Message || body["error"] != prepared.Code || body["error_description"] != prepared.Description {
		t.Fatal("Write's body differed from the prepared challenge", body, prepared)
	}
	for _, denied := range []oauthprovider.ResourceFailure{{Status: 403, Message: "forbidden"}, {Status: 500, Message: "broken"}} {
		if prepared, err := c.Prepare(nil, denied); prepared != nil || err != nil {
			t.Fatal("a non-challenge failure was prepared", denied, prepared, err)
		}
	}
	for _, resource := range []string{"http://127.0.0.1:8080/api", "http://[::1]:8080/api", "http://app.localhost/api"} {
		if _, err := oauthprovider.NewResourceChallenges([]string{resource}, oauthprovider.ChallengeOptions{}); err != nil {
			t.Error("a loopback resource was refused", resource, err)
		}
	}
	for _, resource := range []string{"http://api.example.test/mcp", "http://127.example.com/mcp"} {
		if _, err := oauthprovider.NewResourceChallenges([]string{resource}, oauthprovider.ChallengeOptions{}); err == nil {
			t.Error("a non-loopback HTTP resource was accepted", resource)
		}
	}
}
