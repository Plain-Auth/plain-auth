package oauthprovider

import (
	"encoding/json"
	"errors"
	"slices"
	"testing"

	auth "github.com/Plain-Auth/plain-auth"
)

func TestAuthorizationCodePKCERequirement(t *testing.T) {
	on, off := true, false
	for _, tc := range []struct {
		name, method string
		configured   *bool
		scopes       []string
		nonce, want  string
	}{
		{"public", "none", &off, nil, "", "pkce is required for public clients"},
		{"public OIDC", "none", &off, []string{"offline_access", "openid"}, "nonce", "pkce is required for public clients"},
		{"default", "client_secret_basic", nil, nil, "", "pkce is required for this client"},
		{"explicit", "private_key_jwt", &on, []string{"openid"}, "nonce", "pkce is required for this client"},
		{"relaxed", "client_secret_post", &off, []string{"reports"}, "", ""},
		{"offline", "client_secret_post", &off, []string{"offline_access"}, "nonce", "pkce or OIDC nonce is required when requesting offline_access scope"},
		{"offline OIDC no nonce", "private_key_jwt", &off, []string{"offline_access", "openid"}, "", "pkce or OIDC nonce is required when requesting offline_access scope"},
		{"offline OIDC nonce", "private_key_jwt", &off, []string{"offline_access", "openid"}, "nonce", ""},
		{"offline OIDC required", "client_secret_basic", &on, []string{"offline_access", "openid"}, "nonce", "pkce is required for this client"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client := AuthorizationCodeClient{MachineClient: MachineClient{AuthMethod: tc.method}, RequirePKCE: tc.configured}
			if got := client.PKCERequirement(tc.scopes, tc.nonce); got != tc.want {
				t.Fatalf("reason=%q, want %q", got, tc.want)
			}
		})
	}
}

func TestAuthorizationCodeGrantBoundaries(t *testing.T) {
	off := false
	client := AuthorizationCodeClient{MachineClient: MachineClient{ClientID: "app", AuthMethod: "client_secret_post"}, RequirePKCE: &off}
	in := tokenRequest{id: "app", method: "client_secret_post", secret: "secret"}
	check := func(raw, verifier string, status int, wire string) {
		t.Helper()
		var code storedAuthorizationCode
		if err := json.Unmarshal([]byte(raw), &code); err != nil {
			t.Fatal(err)
		}
		scopes, err := code.scopesForExchange(client, in, verifier, "")
		if status == 200 {
			if err != nil || !slices.Equal(scopes, []string{"read"}) {
				t.Fatal(scopes, err)
			}
			return
		}
		var p *auth.OAuthError
		if !errors.As(err, &p) || p.Status != status || p.Code != wire {
			t.Fatalf("expected %d %s, got %v", status, wire, err)
		}
	}
	const basic = `{"query":{"client_id":"app","scope":"read"}}`
	check(basic, "", 200, "")
	check(basic, "unexpected", 400, "invalid_request")
	check(`{"query":{"client_id":"app","scope":"offline_access"}}`, "", 400, "invalid_request")
	check(`{"query":{"client_id":"app","scope":"openid"}}`, "", 501, "server_error")
	check(`{"query":{"client_id":"app","scope":"read","dpop_jkt":"thumbprint"}}`, "", 400, "invalid_dpop_proof")
	check(`{"resource":["urn:protected"],"query":{"client_id":"app","scope":"read"}}`, "", 501, "server_error")
	check(`{"query":{"client_id":"app","scope":"read","resource":"urn:protected"}}`, "", 501, "server_error")
	in.resources = []string{"urn:protected"}
	check(basic, "", 501, "server_error")
	in.resources = nil
	in.proof = "proof"
	check(basic, "", 501, "server_error")
	in.proof = ""
	client.RequirePKCE = nil
	check(basic, "", 400, "invalid_request")
}
