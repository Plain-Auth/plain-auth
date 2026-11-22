package sso

import (
	"context"
	"slices"
	"strings"

	auth "github.com/Stonewrit/stonewrit-auth"
)

// ProviderMutation contains the locked provider identity and a snapshot of its
// exact provider namespace. Reference excludes the confidential client secret.
type ProviderMutation struct {
	Action, ID, ProviderID, Reference string
	OrganizationID                    *string
	LinkedAccounts                    int
	AuthenticationBoundaryChanged     bool
}

// MutationGuard runs inside a transaction and may be retried after a database
// conflict. Return an error to deny the operation. Keep the callback read-only.
type MutationGuard func(context.Context, ProviderMutation) error

// DeletionStore performs a direct-session and tenant authorization check, then
// atomically deletes exactly the named record and its account links.
type DeletionStore interface {
	DeleteSSOProvider(ctx context.Context, actor Actor, providerID, recordID string, guard MutationGuard) error
}

// ErrUnclassifiedAccounts requires a trusted operator to establish the
// origin of preexisting canonical account rows before a provider can be deleted.
var ErrUnclassifiedAccounts = &auth.APIError{Status: 409, Code: "SSO_ACCOUNT_ORIGIN_REQUIRED", Message: "An existing account link requires source reconciliation"}

var ErrMutationRejected = &auth.APIError{Status: 409, Code: "SSO_PROVIDER_MUTATION_REJECTED", Message: "SSO provider mutation is not allowed"}

// MutableProviderID reports whether an identifier can belong to an enterprise
// directory. Host-configured social provider names are checked separately.
func MutableProviderID(id string) bool {
	return slug.MatchString(id) && !strings.Contains(id, "..") && !slices.Contains(reserved, strings.ToLower(id))
}

func (o Options) deleteProvider(c auth.EndpointContext, store Store, actor Actor) (any, error) {
	id, ok := c.Body["providerId"].(string)
	if !ok {
		return nil, apiError(400, "providerId is required")
	}
	if !MutableProviderID(id) || c.Auth.HasOAuthProvider(id) {
		return nil, ErrMissing
	}
	deletion, ok := store.(DeletionStore)
	if !ok {
		if o.GuardProviderMutation != nil {
			return nil, &auth.APIError{Status: 501, Code: "SSO_PROVIDER_MUTATION_GUARD_REQUIRES_NATIVE_TRANSACTIONS", Message: "SSO provider mutation guards require a database adapter with native transaction support"}
		}
		return nil, apiError(501, "The configured store does not support enterprise provider deletion")
	}
	ctx := c.Request.Context()
	providers, err := store.ReadSSOProviders(ctx, actor, id)
	if err != nil {
		return nil, err
	}
	if len(providers) != 1 || providers[0].ProviderID != id || providers[0].ID == "" {
		return nil, ErrMissing
	}
	if err = deletion.DeleteSSOProvider(ctx, actor, id, providers[0].ID, o.GuardProviderMutation); err != nil {
		return nil, err
	}
	return map[string]bool{"success": true}, nil
}
