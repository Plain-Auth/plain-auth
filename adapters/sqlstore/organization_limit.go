package sqlstore

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	auth "github.com/Plain-Auth/plain-auth"
	org "github.com/Plain-Auth/plain-auth/plugins/organization"
)

// WithMembershipLimit returns a policy-scoped view of the same database.
// Use it as the host's store to apply one policy to organizations and SSO.
func (s *Store) WithMembershipLimit(policy org.MembershipLimit) (*Store, error) {
	if err := policy.Validate(); err != nil {
		return nil, err
	}
	scoped := *s
	scoped.membershipLimit = policy
	return &scoped, nil
}

// WithOrganizationMembershipLimit implements the organization plugin's adapter interface.
func (s *Store) WithOrganizationMembershipLimit(policy org.MembershipLimit) (org.Store, error) {
	return s.WithMembershipLimit(policy)
}

var errResolveMemberAdmission = errors.New("resolve membership limit outside transaction")

type memberAdmission struct {
	user     auth.User
	group    org.Organization
	snapshot string
	maximum  int
}

// Recheck time-sensitive permissions after the host callback returns.
func (d *memberAdmission) checkedAt(start time.Time) time.Time {
	if d.snapshot != "" {
		if now := time.Now().UTC(); now.After(start) {
			return now
		}
	}
	return start
}

// The first pass performs all authorization checks and rolls back before
// calling the host. The second rechecks those inputs and counts seats while
// holding the organization lock. Fixed limits need only one pass.
func (s *Store) withMemberAdmission(ctx context.Context, attempt func(*memberAdmission) error) error {
	var decision memberAdmission
	err := attempt(&decision)
	if err != errResolveMemberAdmission {
		return err
	}
	decision.maximum, err = s.membershipLimit.Resolve(ctx, decision.user, decision.group)
	if err != nil {
		return err
	}
	return attempt(&decision)
}

func (s *Store) admissionCapacity(ctx context.Context, tx *sql.Tx, userID, groupID string, decision *memberAdmission, invitation *org.Invitation) (int, error) {
	if s.membershipLimit.Resolve == nil {
		return s.membershipLimit.DefaultPageSize(), nil
	}
	var user auth.User
	q := `SELECT ` + userColumns + ` FROM "user" u WHERE u."id"=` + s.exactSQLValue("?")
	if err := tx.QueryRowContext(ctx, s.readForUpdate(q), userID).Scan(userFields(&user)...); err != nil {
		return 0, err
	}
	group, err := readOrg(tx.QueryRowContext(ctx, s.bind(`SELECT `+orgFields+` FROM "organization" o WHERE o."id"=`+s.exactSQLValue("?")), groupID))
	if err != nil {
		return 0, err
	}
	data, err := json.Marshal(struct {
		User         auth.User
		Organization *org.Organization
		Invitation   *org.Invitation
	}{user, group, invitation})
	if err != nil {
		return 0, err
	}
	if decision.snapshot == "" {
		decision.user, decision.group, decision.snapshot = user, *group, string(data)
		return 0, errResolveMemberAdmission
	}
	if decision.snapshot != string(data) {
		return 0, org.ErrMembershipPolicyChanged
	}
	return decision.maximum, nil
}
