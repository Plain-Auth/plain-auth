package organization

import (
	"context"
	"errors"

	authn "github.com/Plain-Auth/plain-auth"
)

var (
	ErrCreateDenied      = problem(403, "YOU_ARE_NOT_ALLOWED_TO_CREATE_A_NEW_ORGANIZATION", "You are not allowed to create a new organization")
	ErrOrganizationLimit = problem(403, "YOU_HAVE_REACHED_THE_MAXIMUM_NUMBER_OF_ORGANIZATIONS", "You have reached the maximum number of organizations")
)

// OrganizationLimitStoreProvider returns a view of the store that counts the
// creator's memberships in the creating transaction.
type OrganizationLimitStoreProvider interface {
	WithOrganizationLimit(limit int) (Store, error)
}

func (o *Options) configureCreationPolicy() error {
	if o.OrganizationLimit < 0 {
		return errors.New("organization: OrganizationLimit cannot be negative")
	}
	if o.OrganizationLimit > 0 && o.OrganizationLimitReached != nil {
		return errors.New("organization: choose a fixed organization limit or OrganizationLimitReached")
	}
	if o.OrganizationLimit == 0 {
		return nil
	}
	provider, ok := o.Store.(OrganizationLimitStoreProvider)
	if !ok {
		return errors.New("organization: OrganizationLimit requires an OrganizationLimitStoreProvider")
	}
	store, err := provider.WithOrganizationLimit(o.OrganizationLimit)
	if err != nil {
		return err
	}
	o.Store = store
	return nil
}

// checkCreationPolicy asks the host whether a signed-in user may create
// another organization. A fixed limit is counted by the store instead.
func (o Options) checkCreationPolicy(ctx context.Context, user authn.User) error {
	if allow := o.AllowUserToCreateOrganization; allow != nil {
		allowed, err := allow(ctx, user)
		if err != nil {
			return err
		}
		if !allowed {
			return ErrCreateDenied
		}
	}
	if reached := o.OrganizationLimitReached; reached != nil {
		full, err := reached(ctx, user)
		if err != nil {
			return err
		}
		if full {
			return ErrOrganizationLimit
		}
	}
	return nil
}
