package oauthprovider

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"reflect"
	"slices"
	"strings"
	"sync"

	auth "github.com/Plain-Org/plain-auth"
)

// Extension adds capabilities to the provider without changing its core,
// as another runtime's provider extensions do.
type Extension struct {
	// Metadata returns discovery fields to add to a served document. It runs
	// when the host starts, outside any store transaction. A field the
	// provider defines is never replaced, and an earlier extension's field
	// wins over a later one's. A nil Metadata adds nothing.
	Metadata func(MetadataInput) map[string]any
	// AccessTokenClaims contributes claims to signed access tokens, below the
	// host's CustomAccessTokenClaims and the resource's claims.
	AccessTokenClaims TokenClaimsFunc
	// IDTokenClaims adds claims to ID tokens. It cannot set a claim the
	// token already has, a reserved claim or a standard profile or email
	// claim; the first extension keeps a shared name.
	IDTokenClaims TokenClaimsFunc
	// UserInfoClaims adds UserInfo claims after UserInfo.Extensions, under
	// the same rules: standard claims win and the first contributor keeps
	// a name.
	UserInfoClaims UserInfoClaimsFunc
	// ClientAuthentication adds token_endpoint_auth_method values, keyed by
	// method name, whose clients authenticate with a client assertion the
	// strategy checks.
	ClientAuthentication map[string]ClientAuthenticationStrategy
}

// Confirmation is an RFC 7800 sender constraint. Exactly one member is set.
type Confirmation struct {
	JKT     string `json:"jkt,omitempty"`
	X5TS256 string `json:"x5t#S256,omitempty"`
}

// ClientAuthenticationStrategy authenticates clients that send a
// client_assertion of one of its AssertionTypes.
type ClientAuthenticationStrategy struct {
	// AssertionTypes are absolute URIs. Nil means the method name, which
	// must then be one.
	AssertionTypes []string
	// Authenticate checks the assertion and names the client it proves. It
	// runs before any store call, outside store transactions. An
	// *auth.OAuthError it returns is the answer; any other error is a
	// server error.
	Authenticate func(context.Context, ClientAuthenticationInput) (ClientAuthenticationResult, error)
}

// ClientAuthenticationInput is one assertion presented to a strategy.
type ClientAuthenticationInput struct {
	Assertion, AssertionType string
	// ClientID is the form's client_id, which may be empty.
	ClientID string
	// ExpectedAudience is the public URL of the endpoint serving the request.
	ExpectedAudience string
	// Header is a copy of the request headers.
	Header http.Header
}

// ClientAuthenticationResult names the proven client, and a confirmation
// grants that forward it may stamp.
type ClientAuthenticationResult struct {
	ClientID     string
	Confirmation *Confirmation
}

// clientAuthStrategy finds the extension method for an assertion type.
func (opts Options) clientAuthStrategy(assertionType string) (string, ClientAuthenticationStrategy, bool) {
	for _, extension := range opts.Extensions {
		for method, strategy := range extension.ClientAuthentication {
			types := strategy.AssertionTypes
			if types == nil {
				types = []string{method}
			}
			if slices.Contains(types, assertionType) {
				return method, strategy, true
			}
		}
	}
	return "", ClientAuthenticationStrategy{}, false
}

// extensionAuthMethods lists the extensions' authentication methods.
func (opts Options) extensionAuthMethods() []string {
	var methods []string
	for _, extension := range opts.Extensions {
		for method := range extension.ClientAuthentication {
			methods = append(methods, method)
		}
	}
	slices.Sort(methods)
	return methods
}

// checkClientAuthentication refuses an extension method or assertion type
// that is reserved, malformed or claimed twice, as another runtime does.
func (opts Options) checkClientAuthentication() error {
	methods, types := map[string]bool{}, map[string]bool{}
	for _, extension := range opts.Extensions {
		for method, strategy := range extension.ClientAuthentication {
			name := strings.TrimSpace(method)
			switch {
			case name == "" || name != method:
				return fmt.Errorf("oauthprovider: invalid extension authentication method %q", method)
			case method == "none" || method == "client_secret_basic" || method == "client_secret_post" || method == "private_key_jwt":
				return fmt.Errorf("oauthprovider: extension authentication method %q is reserved", method)
			case strategy.Authenticate == nil:
				return fmt.Errorf("oauthprovider: extension authentication method %q has no Authenticate", method)
			case methods[method]:
				return fmt.Errorf("oauthprovider: extension authentication method %q is defined twice", method)
			}
			methods[method] = true
			assertionTypes := strategy.AssertionTypes
			if assertionTypes == nil {
				assertionTypes = []string{method}
			} else if len(assertionTypes) == 0 {
				return fmt.Errorf("oauthprovider: extension authentication method %q has no assertion types", method)
			}
			for _, kind := range assertionTypes {
				u, err := url.Parse(kind)
				if err != nil || !u.IsAbs() || kind == ClientAssertionType {
					return fmt.Errorf("oauthprovider: invalid client assertion type %q", kind)
				}
				if types[kind] {
					return fmt.Errorf("oauthprovider: client assertion type %q is defined twice", kind)
				}
				types[kind] = true
			}
		}
	}
	return nil
}

// The discovery document types an Extension's Metadata is called for.
const (
	MetadataAuthorizationServer = "oauth-authorization-server"
	MetadataOpenIDConfiguration = "openid-configuration"
)

// MetadataInput is a served discovery document before any extension field is
// added. OpenID is set when the served document is the OpenID one, which the
// authorization-server paths also serve while OpenID is advertised. Another
// runtime also passes the request context and provider options; this one
// publishes discovery once when the host starts.
type MetadataInput struct {
	Type   string
	Server AuthorizationServerMetadata
	OpenID *OpenIDProviderMetadata
}

// providerMetadataFields lists every JSON field the served document's type
// declares, so an extension cannot add one the provider omitted, such as the
// endpoint of a route it does not serve. Another runtime keeps the keys its
// document object holds, including ones left undefined.
func providerMetadataFields(openID bool) map[string]bool {
	if openID {
		return openIDMetadataFields()
	}
	return serverMetadataFields()
}

var serverMetadataFields = sync.OnceValue(func() map[string]bool {
	return metadataFields(reflect.TypeFor[AuthorizationServerMetadata]())
})

var openIDMetadataFields = sync.OnceValue(func() map[string]bool {
	return metadataFields(reflect.TypeFor[OpenIDProviderMetadata]())
})

func metadataFields(t reflect.Type) map[string]bool {
	fields := map[string]bool{}
	var collect func(reflect.Type)
	collect = func(t reflect.Type) {
		for i := range t.NumField() {
			f := t.Field(i)
			if f.Anonymous {
				collect(f.Type)
				continue
			}
			if name, _, _ := strings.Cut(f.Tag.Get("json"), ","); name != "" && name != "-" {
				fields[name] = true
			}
		}
	}
	collect(t)
	return fields
}

// extendMetadata adds the extensions' fields to a served document. Each
// extension sees the base document, not the running result.
func (opts Options) extendMetadata(a *auth.Auth, document any, input MetadataInput) (any, error) {
	if len(opts.Extensions) == 0 {
		return document, nil
	}
	raw, err := json.Marshal(document)
	if err != nil {
		return nil, err
	}
	var merged map[string]json.RawMessage
	if err := json.Unmarshal(raw, &merged); err != nil {
		return nil, err
	}
	added := map[string]bool{}
	for _, extension := range opts.Extensions {
		if extension.Metadata == nil {
			continue
		}
		for name, value := range extension.Metadata(input) {
			if providerMetadataFields(input.OpenID != nil)[name] {
				continue
			}
			if added[name] {
				a.Logger().Warn("OAuth provider extensions supplied the same discovery field", "field", name, "document", input.Type)
				continue
			}
			encoded, err := json.Marshal(value)
			if err != nil {
				return nil, err
			}
			merged[name], added[name] = encoded, true
		}
	}
	return merged, nil
}
