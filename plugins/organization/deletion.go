package organization

import (
	"context"
	"net/http"

	auth "github.com/Plain-Auth/plain-auth"
)

// OrganizationDeletion describes an organization being deleted and the
// signed-in user deleting it.
type OrganizationDeletion struct {
	Organization Organization
	User         auth.User
}

// OrganizationDeletionStore deletes an organization together with its members,
// invitations, teams and stored roles.
type OrganizationDeletionStore interface {
	// PrepareOrganizationDeletion checks the caller's organization.delete
	// permission and returns the organization without changing anything.
	PrepareOrganizationDeletion(ctx context.Context, actor auth.Session, organizationID string) (OrganizationDeletion, error)
	// DeleteOrganization checks the permission again and deletes in one
	// transaction. Every session that selected the organization loses that
	// selection and its active team.
	DeleteOrganization(ctx context.Context, actor auth.Session, organizationID string) (OrganizationDeletion, error)
}

var (
	ErrDeletionDisabled = problem(404, "ORGANIZATION_DELETION_DISABLED", "Organization deletion is disabled")
	ErrDeleteNotMember  = problem(400, "USER_IS_NOT_A_MEMBER_OF_THE_ORGANIZATION", "User is not a member of the organization")
	ErrDeleteDenied     = problem(403, "YOU_ARE_NOT_ALLOWED_TO_DELETE_THIS_ORGANIZATION", "You are not allowed to delete this organization")
)

func (o Options) deleteOrganizationEndpoint(store OrganizationDeletionStore) auth.Endpoint {
	return auth.Endpoint{Method: http.MethodPost, Path: "/organization/delete", Handler: func(c auth.EndpointContext) (any, error) {
		value, present := c.Body["organizationId"]
		id, ok := value.(string)
		if !ok {
			return nil, problem(400, "VALIDATION_ERROR", bodyTypeIssue("organizationId", "string", value, present))
		}
		if o.DisableOrganizationDeletion {
			return nil, ErrDeletionDisabled
		}
		session, err := endpointSession(c, http.MethodPost, "delete")
		if err != nil {
			return nil, err
		}
		if id == "" {
			return nil, ErrNotFound
		}
		ctx := c.Request.Context()
		if o.BeforeDeleteOrganization != nil {
			pending, err := store.PrepareOrganizationDeletion(ctx, session.Session, id)
			if err != nil {
				return nil, err
			}
			if err = o.BeforeDeleteOrganization(ctx, pending); err != nil {
				return nil, err
			}
		}
		deleted, err := store.DeleteOrganization(ctx, session.Session, id)
		if err != nil {
			return nil, err
		}
		if o.AfterDeleteOrganization != nil {
			if err = o.AfterDeleteOrganization(ctx, deleted); err != nil {
				return nil, err
			}
		}
		return deleted.Organization, nil
	}}
}
