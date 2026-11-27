package oauthprovider

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"slices"
	"testing"
	"time"

	auth "github.com/Plain-Org/plain-auth"
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
	check(`{"query":{"client_id":"app","scope":"read","dpop_jkt":"thumbprint"}}`, "", 400, "invalid_dpop_proof")
	check(`{"resource":["urn:protected"],"query":{"client_id":"app","scope":"read"}}`, "", 200, "")
	// A code's resources come from its top-level list or a legacy
	// query.resource; a request may name only resources the code authorized,
	// any when it authorized none.
	for _, tc := range []struct {
		raw                  string
		requested, effective []string
		refused              bool
	}{
		{`{"resource":["urn:a","urn:b"],"query":{}}`, nil, []string{"urn:a", "urn:b"}, false},
		{`{"query":{"resource":"urn:a"}}`, nil, []string{"urn:a"}, false},
		{`{"query":{"resource":["urn:a"]}}`, []string{"urn:a"}, []string{"urn:a"}, false},
		{`{"resource":["urn:a","urn:b"],"query":{}}`, []string{"urn:b"}, []string{"urn:b"}, false},
		{`{"resource":["urn:a"],"query":{}}`, []string{"urn:c"}, nil, true},
		{`{"resource":[],"query":{}}`, []string{"urn:c"}, []string{"urn:c"}, false},
	} {
		var code storedAuthorizationCode
		if err := json.Unmarshal([]byte(tc.raw), &code); err != nil {
			t.Fatal(err)
		}
		effective, _, err := code.resources(tc.requested)
		var p *auth.OAuthError
		if tc.refused != (errors.As(err, &p) && p.Code == "invalid_target") || !tc.refused && !slices.Equal(effective, tc.effective) {
			t.Fatal("wrong code resources", tc.raw, tc.requested, effective, err)
		}
	}
	in.proof = "proof"
	check(basic, "", 501, "server_error")
	in.proof = ""
	client.RequirePKCE = nil
	check(basic, "", 400, "invalid_request")
}

// An authorization code's verification record is named by the row ID the
// SQL store gives the code, and expires to the millisecond in UTC.
func TestAuthorizationCodeRecord(t *testing.T) {
	sum := sha256.Sum256([]byte("oauth-code/stored-identifier"))
	id := AuthorizationCodeRecordID("stored-identifier")
	if id != hex.EncodeToString(sum[:16]) {
		t.Fatal("the record ID is", id)
	}
	at := time.Date(2030, 1, 2, 4, 4, 5, 123456789, time.FixedZone("UTC+1", 3600))
	rec := AuthorizationCodeRecord(id, "owner", at)
	if rec.Identifier != "authorization-code" || rec.UserID != "owner" || rec.ID != id || rec.ExpiresAt != time.Date(2030, 1, 2, 3, 4, 5, 123000000, time.UTC) {
		t.Fatal("the record is", rec)
	}
}
