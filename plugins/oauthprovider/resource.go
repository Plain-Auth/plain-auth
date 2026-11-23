package oauthprovider

import (
	"encoding/json"
	"math"
	"net/http"
	"slices"
	"time"

	auth "github.com/Plain-Org/plain-auth"
)

// Resource is the stored policy for one OAuth audience. Token lifetimes are in seconds.
// Nil settings inherit provider defaults. An empty allowedScopes array is distinct from null.
type Resource struct {
	ID                            string                     `json:"id"`
	Identifier                    string                     `json:"identifier"`
	Name                          string                     `json:"name"`
	AccessTokenTTL                *int64                     `json:"accessTokenTtl"`
	RefreshTokenTTL               *int64                     `json:"refreshTokenTtl"`
	SigningAlgorithm              *string                    `json:"signingAlgorithm"`
	SigningKeyID                  *string                    `json:"signingKeyId"`
	AllowedScopes                 []string                   `json:"allowedScopes"`
	CustomClaims                  map[string]json.RawMessage `json:"customClaims"`
	DPoPBoundAccessTokensRequired bool                       `json:"dpopBoundAccessTokensRequired"`
	Disabled                      bool                       `json:"disabled"`
	PolicyVersion                 int                        `json:"policyVersion"`
	Metadata                      map[string]json.RawMessage `json:"metadata"`
	CreatedAt                     time.Time                  `json:"createdAt"`
	UpdatedAt                     time.Time                  `json:"updatedAt"`
}

// Setting distinguishes a missing patch field from a value or an explicit JSON null.
type Setting[T any] struct {
	present bool
	value   *T
}

// Set supplies a value, including false, an empty string, or an empty list.
func Set[T any](v T) Setting[T] { return Setting[T]{present: true, value: &v} }

// Clear restores inheritance for a nullable policy setting.
func Clear[T any]() Setting[T] { return Setting[T]{present: true} }

func (s Setting[T]) IsZero() bool                 { return !s.present }
func (s Setting[T]) MarshalJSON() ([]byte, error) { return json.Marshal(s.value) }
func (s *Setting[T]) UnmarshalJSON(b []byte) error {
	var v *T
	if err := json.Unmarshal(b, &v); err != nil {
		return err
	}
	*s = Setting[T]{present: true, value: v}
	return nil
}

func (s Setting[T]) assign(dst *T) {
	if s.present {
		var zero T
		*dst = zero
		if s.value != nil {
			*dst = *s.value
		}
	}
}

func (s Setting[T]) assignNullable(dst **T) {
	if s.present {
		*dst = s.value
	}
}

// ResourcePatch contains the mutable resource fields for creation or an update.
// The zero value preserves all existing fields on update.
type ResourcePatch struct {
	Name                          Setting[string]                     `json:"name,omitzero"`
	AccessTokenTTL                Setting[int64]                      `json:"accessTokenTtl,omitzero"`
	RefreshTokenTTL               Setting[int64]                      `json:"refreshTokenTtl,omitzero"`
	SigningAlgorithm              Setting[string]                     `json:"signingAlgorithm,omitzero"`
	SigningKeyID                  Setting[string]                     `json:"signingKeyId,omitzero"`
	AllowedScopes                 Setting[[]string]                   `json:"allowedScopes,omitzero"`
	CustomClaims                  Setting[map[string]json.RawMessage] `json:"customClaims,omitzero"`
	DPoPBoundAccessTokensRequired Setting[bool]                       `json:"dpopBoundAccessTokensRequired,omitzero"`
	Disabled                      Setting[bool]                       `json:"disabled,omitzero"`
	Metadata                      Setting[map[string]json.RawMessage] `json:"metadata,omitzero"`
}

// UnmarshalJSON preserves null and empty scope lists. A null element is not a
// scope string. encoding/json normally accepts it as the empty string.
func (p *ResourcePatch) UnmarshalJSON(b []byte) error {
	type fields ResourcePatch
	var decoded fields
	wire := struct {
		*fields
		Scopes Setting[[]*string] `json:"allowedScopes"`
	}{fields: &decoded}
	if err := json.Unmarshal(b, &wire); err != nil {
		return err
	}
	if scopes := wire.Scopes.value; scopes != nil {
		names := make([]string, len(*scopes))
		for i, name := range *scopes {
			if name == nil {
				return invalidResource("allowedScopes must contain strings")
			}
			names[i] = *name
		}
		decoded.AllowedScopes = Set(names)
	} else if wire.Scopes.present {
		decoded.AllowedScopes = Clear[[]string]()
	}
	*p = ResourcePatch(decoded)
	return nil
}

func invalidResource(msg string) error {
	return &auth.APIError{Status: http.StatusBadRequest, Code: "invalid_request", Message: msg}
}

// Apply validates a patch and applies it to the locked resource in a storage adapter.
func (p ResourcePatch) Apply(r *Resource) error {
	if p.Name.present && p.Name.value == nil || p.Disabled.present && p.Disabled.value == nil ||
		p.DPoPBoundAccessTokensRequired.present && p.DPoPBoundAccessTokensRequired.value == nil {
		return invalidResource("name, disabled and dpopBoundAccessTokensRequired cannot be null")
	}
	for _, ttl := range []*int64{p.AccessTokenTTL.value, p.RefreshTokenTTL.value} {
		if ttl != nil && (*ttl <= 0 || *ttl > math.MaxInt32) {
			return invalidResource("token lifetime must be a positive 32-bit number of seconds")
		}
	}
	if alg := p.SigningAlgorithm.value; alg != nil && !slices.Contains(resourceSigningAlgorithms(), *alg) {
		return invalidResource("unsupported resource signing algorithm")
	}
	for _, object := range []Setting[map[string]json.RawMessage]{p.CustomClaims, p.Metadata} {
		if object.value != nil {
			if _, err := json.Marshal(*object.value); err != nil {
				return invalidResource("resource object contains invalid JSON")
			}
		}
	}
	p.Name.assign(&r.Name)
	p.AccessTokenTTL.assignNullable(&r.AccessTokenTTL)
	p.RefreshTokenTTL.assignNullable(&r.RefreshTokenTTL)
	p.SigningAlgorithm.assignNullable(&r.SigningAlgorithm)
	p.SigningKeyID.assignNullable(&r.SigningKeyID)
	p.AllowedScopes.assign(&r.AllowedScopes)
	p.CustomClaims.assign(&r.CustomClaims)
	p.DPoPBoundAccessTokensRequired.assign(&r.DPoPBoundAccessTokensRequired)
	p.Disabled.assign(&r.Disabled)
	p.Metadata.assign(&r.Metadata)
	return nil
}
