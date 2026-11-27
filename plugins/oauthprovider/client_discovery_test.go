package oauthprovider

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"slices"
	"strings"
	"testing"

	auth "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/adapters/memory"
)

// discoveredClients is a map-backed DiscoveredClientStore that records each
// save.
type discoveredClients struct {
	rows  map[string]DiscoveredClient
	saved []DiscoveredClientRecord
}

func (s *discoveredClients) LookupDiscoveredClient(_ context.Context, id string) (DiscoveredClient, error) {
	if c, ok := s.rows[id]; ok {
		return c, nil
	}
	return DiscoveredClient{}, ErrClientNotFound
}

func (s *discoveredClients) SaveDiscoveredClient(_ context.Context, r DiscoveredClientRecord) (DiscoveredClient, bool, error) {
	s.saved = append(s.saved, r)
	_, found := s.rows[r.ClientID]
	c := DiscoveredClient{RowID: r.ID, DiscoveryID: r.DiscoveryID}
	c.ClientID = r.ClientID
	method, app := r.Metadata.TokenEndpointAuthMethod, r.Metadata.ApplicationType
	c.TokenEndpointAuthMethod, c.GrantTypes, c.RedirectURIs = &method, r.Metadata.GrantTypes, r.Metadata.RedirectURIs
	if app != "" {
		c.ApplicationType = &app
	}
	s.rows[r.ClientID] = c
	return c, !found, nil
}

// Document registration refuses back-channel logout targets, shared
// secrets, clients of another discovery and unknown scopes; defaults the
// auth method to none; keeps an omitted application type empty under the
// union of web and native redirect rules; stores a declared grant union
// when one grant is mutual; ignores document resources for the default
// ones; and admits a jwks_uri on the client ID's origin, a trusted origin
// or one the discovery's hook allows.
func TestRegisterMetadataDocument(t *testing.T) {
	var logs bytes.Buffer
	host, err := auth.New(auth.Options{Store: memory.New(), BaseURL: "https://issuer.example.test", Secret: strings.Repeat("d", 40),
		TrustedOrigins: []string{"https://keys.example.test"}, Logger: slog.New(slog.NewTextHandler(&logs, nil))})
	if err != nil {
		t.Fatal(err)
	}
	opts := Options{GrantTypes: []string{"authorization_code", "refresh_token", "client_credentials"}, Scopes: []string{"openid", "mcp:read"},
		Registration: RegistrationOptions{AllowedScopes: []string{"openid", "mcp:read"}, DefaultResources: []string{"urn:default"}, DefaultApplicationType: "web"}}
	const id = "https://app.example.test/client.json"
	var asked []string
	hook := func(_ context.Context, clientID, jwksURI string) (bool, error) {
		asked = append(asked, jwksURI)
		switch {
		case strings.Contains(jwksURI, "allowed"):
			return true, nil
		case strings.Contains(jwksURI, "broken"):
			return true, errors.New("hook down")
		}
		return false, nil
	}
	discovery := &ClientDiscovery{ID: "cimd", AllowCrossOriginJWKSURI: hook}
	register := func(raw string, existing *DiscoveredClient) (*discoveredClients, ClientRegistrationResult, error) {
		t.Helper()
		doc, err := ParseClientMetadataDocument([]byte(raw))
		if err != nil {
			t.Fatal(err)
		}
		store := &discoveredClients{rows: map[string]DiscoveredClient{}}
		result, err := opts.registerMetadataDocument(t.Context(), host, store, discovery, id, existing, doc)
		return store, result, err
	}
	refused := func(raw string, existing *DiscoveredClient, description string) {
		t.Helper()
		store, _, err := register(raw, existing)
		var oauthErr *auth.OAuthError
		if !errors.As(err, &oauthErr) || oauthErr.Description != description || len(store.saved) != 0 {
			t.Fatal("wanted a refusal", description, err)
		}
	}
	const base = `"client_id":"` + id + `","redirect_uris":["https://app.example.test/cb"]`
	refused(`{`+base+`,"backchannel_logout_uri":"https://app.example.test/logout"}`, nil, "Client ID Metadata Documents cannot register a back-channel logout target")
	refused(`{`+base+`,"backchannel_logout_session_required":false}`, nil, "Client ID Metadata Documents cannot register a back-channel logout target")
	refused(`{`+base+`,"token_endpoint_auth_method":"client_secret_basic"}`, nil, "Client ID Metadata Document clients cannot use a shared secret")
	refused(`{`+base+`}`, &DiscoveredClient{DiscoveryID: "other"}, "client_id is already owned by a different registration source")
	refused(`{`+base+`}`, &DiscoveredClient{}, "client_id is already owned by a different registration source")
	refused(`{`+base+`,"scope":"admin"}`, nil, "cannot request scope admin")
	refused(`{`+base+`,"grant_types":["urn:x:grant"]}`, nil, "no mutually supported grant_type among urn:x:grant")
	refused(`{"client_id":"`+id+`","redirect_uris":["http://app.example.test/cb"]}`, nil, "native clients may use http only on the exact loopback hosts localhost, 127.0.0.1, or [::1]: http://app.example.test/cb")
	refused(`{"client_id":"`+id+`","application_type":"web","redirect_uris":["http://127.0.0.1:7777/cb"]}`, nil, "web clients require https redirect URIs on non-loopback hosts: http://127.0.0.1:7777/cb")

	// The defaults: auth method none, empty application type, code response,
	// the registration scopes and the default resources only.
	store, result, err := register(`{`+base+`,"resources":["urn:own"],"redirect_uris":["https://app.example.test/cb","http://127.0.0.1:7777/cb","com.example.app:/cb","myapp://host/cb"]}`, nil)
	if err != nil {
		t.Fatal(err)
	}
	saved := store.saved[0]
	if saved.DiscoveryID != "cimd" || saved.ClientID != id || saved.ID == "" || saved.Metadata.TokenEndpointAuthMethod != "none" || saved.Metadata.ApplicationType != "" ||
		!slices.Equal(saved.Metadata.GrantTypes, []string{"authorization_code"}) || !slices.Equal(saved.Metadata.ResponseTypes, []string{"code"}) ||
		!slices.Equal(saved.Scopes, []string{"openid", "mcp:read"}) || !slices.Equal(saved.Metadata.Resources, []string{"urn:default"}) || saved.Now.Nanosecond() != 0 {
		t.Fatal("the document was not saved with the defaults", saved)
	}
	if !result.Created || !slices.Equal(result.Resources, []string{"urn:default"}) || result.Client.ClientID != id {
		t.Fatal("the result was wrong", result)
	}
	// A declared grant union is stored whole when one grant is mutual.
	store, _, err = register(`{`+base+`,"grant_types":["urn:x:grant","authorization_code"]}`, nil)
	if err != nil || !slices.Equal(store.saved[0].Metadata.GrantTypes, []string{"urn:x:grant", "authorization_code"}) {
		t.Fatal("the grant union was not stored", err, store.saved)
	}
	// A server without the code grant still stores a union naming it.
	codeless := opts
	codeless.GrantTypes = []string{"client_credentials"}
	doc, err := ParseClientMetadataDocument([]byte(`{` + base + `,"grant_types":["authorization_code","client_credentials"],"token_endpoint_auth_method":"private_key_jwt","jwks_uri":"https://app.example.test/jwks"}`))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := codeless.registerMetadataDocument(t.Context(), host, &discoveredClients{rows: map[string]DiscoveredClient{}}, discovery, id, nil, doc); err != nil {
		t.Fatal("a union naming an unsupported code grant was refused", err)
	}
	// A client_credentials document needs no redirect URIs.
	store, _, err = register(`{"client_id":"`+id+`","grant_types":["client_credentials"],"token_endpoint_auth_method":"private_key_jwt","jwks_uri":"https://app.example.test/jwks"}`, nil)
	if err != nil || !slices.Equal(store.saved[0].Metadata.GrantTypes, []string{"client_credentials"}) || len(store.saved[0].Metadata.RedirectURIs) != 0 {
		t.Fatal("a client_credentials document was refused", err)
	}
	// jwks_uri: the client ID's origin, a trusted origin, or the hook.
	keys := func(uri string) error {
		_, _, err := register(`{`+base+`,"token_endpoint_auth_method":"private_key_jwt","jwks_uri":"`+uri+`"}`, nil)
		return err
	}
	asked = nil
	for _, uri := range []string{"https://app.example.test/jwks", "https://APP.example.test:443/jwks", "https://keys.example.test/jwks"} {
		if err := keys(uri); err != nil {
			t.Fatal("a same-origin or trusted jwks_uri was refused", uri, err)
		}
	}
	if len(asked) != 0 {
		t.Fatal("the hook was asked about a same-origin or trusted jwks_uri", asked)
	}
	if err := keys("https://cdn.example.test/allowed/jwks"); err != nil || len(asked) != 1 {
		t.Fatal("an allowed cross-origin jwks_uri was refused", err, asked)
	}
	for _, uri := range []string{"https://cdn.example.test/jwks", "https://cdn.example.test/broken/jwks", "https://app.example.test:8443/jwks"} {
		var oauthErr *auth.OAuthError
		if err := keys(uri); !errors.As(err, &oauthErr) || oauthErr.Description != "jwks_uri must belong to a trusted origin or the Client ID Metadata Document origin" {
			t.Fatal("a cross-origin jwks_uri was accepted", uri, err)
		}
	}
	if !strings.Contains(logs.String(), `oauth-provider: client discovery \"cimd\" AllowCrossOriginJWKSURI failed`) || !strings.Contains(logs.String(), "hook down") {
		t.Fatal("the hook failure was not logged", logs.String())
	}
	// A private host is refused before the hook is asked.
	asked = nil
	var oauthErr *auth.OAuthError
	if err := keys("https://10.0.0.1/allowed/jwks"); !errors.As(err, &oauthErr) || oauthErr.Description != "jwks_uri must not point to a private or reserved address" || len(asked) != 0 {
		t.Fatal("a private jwks_uri was accepted", err, asked)
	}
	// Registration without a document keeps the trusted-origin rule.
	m := RegistrationMetadata{RedirectURIs: []string{"https://app.example.test/cb"}, TokenEndpointAuthMethod: "private_key_jwt", JWKSURI: new("https://app.example.test/jwks")}
	if err := opts.prepareMetadata(host, &m, authenticatedRegistration); !errors.As(err, &oauthErr) || oauthErr.Description != "jwks_uri must belong to a trusted origin or the Client ID Metadata Document origin" {
		t.Fatal("dynamic registration accepted an untrusted jwks_uri", err)
	}
}
