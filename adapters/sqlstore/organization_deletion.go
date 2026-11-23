package sqlstore

import (
	"context"
	"errors"

	auth "github.com/Plain-Org/plain-auth"
	org "github.com/Plain-Org/plain-auth/plugins/organization"
)

// PrepareOrganizationDeletion checks the caller's permission for a deletion
// hook and leaves the organization unchanged.
func (s *Store) PrepareOrganizationDeletion(ctx context.Context, actor auth.Session, organizationID string) (org.OrganizationDeletion, error) {
	return s.retryOrganizationDeletion(ctx, actor, organizationID, false)
}

// DeleteOrganization removes the organization with its members, invitations,
// teams, team members, stored roles and organization API keys in one
// transaction. Every session that selected it, or one of its teams, loses
// that selection.
func (s *Store) DeleteOrganization(ctx context.Context, actor auth.Session, organizationID string) (org.OrganizationDeletion, error) {
	return s.retryOrganizationDeletion(ctx, actor, organizationID, true)
}

func (s *Store) retryOrganizationDeletion(ctx context.Context, actor auth.Session, organizationID string, commit bool) (org.OrganizationDeletion, error) {
	var deleted org.OrganizationDeletion
	var err error
	for range 3 {
		deleted, err = s.organizationDeletion(ctx, actor, organizationID, commit)
		if !retryIdentity(err) {
			break
		}
	}
	return deleted, err
}

func (s *Store) organizationDeletion(ctx context.Context, actor auth.Session, organizationID string, commit bool) (org.OrganizationDeletion, error) {
	var deleted org.OrganizationDeletion
	if actor.RequireOwner() != nil || actor.UserID == "" || actor.Token == "" {
		return deleted, org.ErrUnauthenticated
	}
	tx, err := s.beginMembershipChange(ctx)
	if err != nil {
		return deleted, err
	}
	defer tx.Rollback()
	account, err := s.organizationSessionAccount(ctx, tx, actor)
	if err != nil {
		return deleted, err
	}
	// An unknown organization has no membership for the caller.
	if err = s.lockOrganization(ctx, tx, organizationID); errors.Is(err, org.ErrNotFound) {
		return deleted, org.ErrDeleteNotMember
	} else if err != nil {
		return deleted, err
	}
	member, err := s.memberForChange(ctx, tx, organizationID, `m."userId"=`+s.exactSQLValue("?"), actor.UserID)
	if errors.Is(err, org.ErrMemberMissing) {
		return deleted, org.ErrDeleteNotMember
	} else if err != nil {
		return deleted, err
	}
	if err = s.requireOrganizationAction(ctx, tx, organizationID, member.Role, "organization", "delete", org.ErrDeleteDenied); err != nil {
		return deleted, err
	}
	group, err := readOrg(tx.QueryRowContext(ctx, s.bind(`SELECT `+orgFields+` FROM "organization" o WHERE o."id"=`+s.exactSQLValue("?")), organizationID))
	if err != nil {
		return deleted, err
	}
	deleted = org.OrganizationDeletion{Organization: *group, User: account.user}
	if !commit {
		return deleted, tx.Commit()
	}
	if err = s.deleteOrganizationKeys(ctx, tx, organizationID); err != nil {
		return org.OrganizationDeletion{}, err
	}
	if err = s.deleteOrganizationRows(ctx, tx, organizationID); err != nil {
		return org.OrganizationDeletion{}, err
	}
	if err = tx.Commit(); err != nil {
		return org.OrganizationDeletion{}, err
	}
	return deleted, nil
}
