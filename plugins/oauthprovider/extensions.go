package oauthprovider

import (
	"encoding/json"
	"reflect"
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

// providerMetadataFields lists every JSON field the provider's discovery
// types declare, so an extension cannot add one the provider omitted, such
// as the endpoint of a route it does not serve.
var providerMetadataFields = sync.OnceValue(func() map[string]bool {
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
	collect(reflect.TypeFor[OpenIDProviderMetadata]())
	return fields
})

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
			if providerMetadataFields()[name] {
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
