package sqlstore

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	org "github.com/Plain-Auth/plain-auth/plugins/organization"
)

// WithOrganizationInvitationLimit scopes the issuance policy to this service.
func (s *Store) WithOrganizationInvitationLimit(policy org.InvitationLimit) (org.Store, error) {
	if err := policy.Validate(); err != nil {
		return nil, err
	}
	scoped := *s
	scoped.invitationLimit = &policy
	return &scoped, nil
}

var errResolveInvitationLimit = errors.New("resolve invitation limit outside transaction")

type invitationCapacity struct {
	input    org.InvitationLimitInput
	expected []byte
	maximum  int
}

func (s *Store) issueOrganizationInvitation(ctx context.Context, inv org.Invitation, issue invitationIssue) (org.Invitation, error) {
	var capacity invitationCapacity
	saved, err := s.issueInvitationTx(ctx, inv, issue, &capacity)
	if err != errResolveInvitationLimit {
		return saved, err
	}
	capacity.maximum, err = s.invitationLimit.Resolve(ctx, capacity.input)
	if err != nil {
		return org.Invitation{}, err
	}
	// Start the issued lifetime after the host has made its decision.
	lifetime := inv.ExpiresAt.Sub(inv.CreatedAt)
	now := time.Now().UTC().Truncate(time.Millisecond)
	if now.After(inv.CreatedAt) {
		inv.CreatedAt, inv.ExpiresAt = now, now.Add(lifetime)
	}
	return s.issueInvitationTx(ctx, inv, issue, &capacity)
}

func (s *Store) invitationIssuer(ctx context.Context, tx *sql.Tx, member org.Member) (org.InvitationLimitInput, error) {
	input := org.InvitationLimitInput{Member: member}
	exact := s.exactSQLValue("?")
	group, err := readOrg(tx.QueryRowContext(ctx, s.bind(`SELECT `+orgFields+` FROM "organization" o WHERE o."id"=`+exact), member.OrganizationID))
	if err != nil {
		return input, err
	}
	input.Organization = *group
	query := `SELECT ` + userColumns + ` FROM "user" u WHERE u."id"=` + exact
	err = tx.QueryRowContext(ctx, s.bind(query), member.UserID).Scan(userFields(&input.User)...)
	return input, err
}

// Called with the organization lock held. A provisional replacement is part
// of this transaction, so it occupies no additional slot.
func (s *Store) checkInvitationCapacity(ctx context.Context, tx *sql.Tx, inv org.Invitation, member org.Member, capacity *invitationCapacity) error {
	maximum := 100
	policy := s.invitationLimit
	if policy != nil {
		maximum = policy.Maximum
	}
	exact := s.exactSQLValue("?")
	if policy != nil && policy.Resolve != nil {
		input, err := s.invitationIssuer(ctx, tx, member)
		if err != nil {
			return err
		}
		current, err := json.Marshal(input)
		if err != nil {
			return err
		}
		if capacity.expected == nil {
			capacity.input, capacity.expected = input, current
			return errResolveInvitationLimit
		}
		if !bytes.Equal(capacity.expected, current) {
			return org.ErrInvitationLimitChanged
		}
		maximum = capacity.maximum
	}
	var count int
	err := tx.QueryRowContext(ctx, s.bind(`SELECT COUNT(*) FROM "invitation" WHERE "organizationId"=`+exact+` AND "status"='pending' AND "expiresAt">?`), inv.OrganizationID, s.date(time.Now())).Scan(&count)
	if err != nil {
		return err
	}
	if count >= maximum {
		return org.ErrInvitationLimit
	}
	return nil
}
