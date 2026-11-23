package sqlstore

import (
	"context"
	"errors"
	"slices"
	"strings"

	auth "github.com/Plain-Auth/plain-auth"
	org "github.com/Plain-Auth/plain-auth/plugins/organization"
)

var _ org.MemberRoleStore = (*Store)(nil)

// OrganizationRolePolicy returns the immutable policy in effect for this adapter.
func (s *Store) OrganizationRolePolicy() org.RolePolicy { return s.organizationRoles }

// WithOrganizationRolePolicy scopes grants to this service while sharing the pool.
func (s *Store) WithOrganizationRolePolicy(policy org.RolePolicy) (org.Store, error) {
	scoped := *s
	scoped.organizationRoles = policy
	return &scoped, nil
}

// UpdateOrganizationMemberRole uses the same account and tenant locks as
// membership removal. Each retry authorizes the actor against current data.
func (s *Store) UpdateOrganizationMemberRole(ctx context.Context, userID, token string, request org.UpdateMemberRoleRequest) (*org.Member, error) {
	var m *org.Member
	var err error
	for range 3 {
		m, err = s.updateMemberRoleOnce(ctx, userID, token, request)
		if !retryIdentity(err) {
			break
		}
	}
	return m, err
}

func (s *Store) updateMemberRoleOnce(ctx context.Context, userID, token string, request org.UpdateMemberRoleRequest) (*org.Member, error) {
	tx, err := s.beginMembershipChange(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	arg := s.exactSQLValue("?")
	filter := `m."id"=` + arg
	targetUser, err := s.lockMembershipAccounts(ctx, tx, userID, token, request.OrganizationID, filter, request.MemberID)
	if err != nil {
		return nil, err
	}
	group, err := s.lockMembershipScope(ctx, tx, userID, token, request.OrganizationID)
	if err != nil {
		return nil, err
	}
	roles := request.NormalizedRoles()
	if len(roles) == 0 {
		return nil, org.ErrEmptyRole
	}
	actor, err := s.lockMembershipActor(ctx, tx, userID, group)
	if err != nil {
		return nil, err
	}
	m, err := s.memberForChange(ctx, tx, group, filter, request.MemberID)
	if errors.Is(err, org.ErrMemberMissing) {
		// The wire contract distinguishes a foreign membership from a missing
		// one. Only the membership's existence is needed for this distinction.
		var foreign bool
		err = tx.QueryRowContext(ctx, s.bind(`SELECT EXISTS(SELECT 1 FROM "member" WHERE "id"=`+arg+` AND "organizationId"<>`+arg+`)`), request.MemberID, group).Scan(&foreign)
		if err != nil {
			return nil, err
		}
		if foreign {
			return nil, org.ErrMemberRoleDenied
		}
		return nil, org.ErrMemberMissing
	}
	if err != nil {
		return nil, err
	}
	if m.UserID != targetUser {
		return nil, org.ErrMemberMissing
	}
	policy, err := s.resolveOrganizationRoles(ctx, tx, group)
	if err != nil {
		return nil, err
	}
	creator := policy.CreatorRole()
	owner := membershipHasRole(actor.Role, creator)
	targetOwner := membershipHasRole(m.Role, creator)
	setOwner := slices.Contains(roles, creator)
	if !owner && (targetOwner || setOwner || !policy.HasAction(actor.Role, "member", "update")) {
		return nil, org.ErrMemberRoleDenied
	}
	if targetOwner && !setOwner {
		other, err := s.hasOtherOwner(ctx, tx, group, m.ID)
		if err != nil {
			return nil, err
		}
		if !other {
			return nil, org.ErrSoleOwnerDemotion
		}
	}
	var unknown []string
	for _, r := range roles {
		if !policy.Recognizes(r) {
			unknown = append(unknown, r)
		}
	}
	if len(unknown) > 0 {
		return nil, &auth.APIError{Status: 400, Code: "ROLE_NOT_FOUND", Message: "ROLE_NOT_FOUND: " + strings.Join(unknown, ", ")}
	}
	m.Role = strings.Join(roles, ",")
	_, err = tx.ExecContext(ctx, s.bind(`UPDATE "member" SET "role"=? WHERE "id"=`+arg+` AND "organizationId"=`+arg+` AND "userId"=`+arg), m.Role, m.ID, group, m.UserID)
	if err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return &m.Member, nil
}
