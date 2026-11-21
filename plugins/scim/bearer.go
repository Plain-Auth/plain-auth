package scim

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"strings"
	"time"
)

const managedConnectionPrefix = "ba_scim_connection_"
const managedCredentialPrefix = "ba_scim_credential_"

var allScopes = []string{UsersRead, UsersWrite, GroupsRead, GroupsWrite}

// BearerInput is passed only to the application's trusted verifier. Path is
// relative to the auth mount and uses the SCIM route template for item routes.
type BearerInput struct {
	Token, Method, Path string
	Headers             http.Header
}

// BearerVerification names one declared connection or supplies one application-
// resolved directory. Returning nil means the token was not accepted.
type BearerVerification struct {
	ConnectionID string
	Connection   *Directory
	CredentialID string
	Scopes       []string
	ExpiresAt    time.Time
}
type VerifyBearerToken func(context.Context, BearerInput) (*BearerVerification, error)

type Principal struct {
	Kind string
	Directory
	CredentialID string
	Scopes       []string
	ExpiresAt    time.Time
}
type principalKey struct{}

// PrincipalFromContext reports the authenticated directory identity while
// processing a resource operation. The bearer credential is never attached.
func PrincipalFromContext(ctx context.Context) (Principal, bool) {
	p, ok := ctx.Value(principalKey{}).(Principal)
	p.Scopes = slices.Clone(p.Scopes)
	return p, ok
}
func validScopes(scopes []string) bool {
	if len(scopes) == 0 || len(scopes) > len(allScopes) {
		return false
	}
	for i, s := range scopes {
		if !slices.Contains(allScopes, s) || slices.Contains(scopes[:i], s) {
			return false
		}
	}
	return true
}
func (h *Handler) verifyDynamic(ctx context.Context, input BearerInput) (*Principal, error) {
	verified, e := h.verify(ctx, input)
	if e != nil {
		return nil, errors.New("scim: directory credential verification failed")
	}
	if verified == nil || !identifier(verified.CredentialID) || !validScopes(verified.Scopes) || !verified.ExpiresAt.IsZero() && !verified.ExpiresAt.After(time.Now()) {
		return nil, nil
	}
	var d Directory
	if verified.Connection == nil {
		var found bool
		d, found = h.declared[verified.ConnectionID]
		if !found {
			return nil, nil
		}
	} else {
		d = *verified.Connection
		_, collision := h.declared[d.ID]
		if verified.ConnectionID != "" || collision || !identifier(d.ID) || !identifier(d.ProvisioningDomainID) || strings.HasPrefix(d.ID, managedConnectionPrefix) {
			return nil, nil
		}
	}
	return &Principal{Kind: "oauth-bearer", Directory: d, CredentialID: verified.CredentialID, Scopes: slices.Clone(verified.Scopes), ExpiresAt: verified.ExpiresAt}, nil
}
