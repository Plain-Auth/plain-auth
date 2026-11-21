package sqlstore

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"

	auth "github.com/Stonewrit/stonewrit-auth"
	org "github.com/Stonewrit/stonewrit-auth/plugins/organization"
)

// Opaque identifiers use byte-exact comparison even on a case-insensitive MySQL database.
func (s *Store) exactSQLValue(value string) string {
	if s.dialect == "mysql" {
		return "BINARY " + value
	}
	return value
}

func (s *Store) RemoveOrganizationMember(ctx context.Context, userID, token, group, target string) (*org.RemovedMember, error) {
	return s.removeMembership(ctx, userID, token, group, target, false)
}
func (s *Store) LeaveOrganization(ctx context.Context, userID, token, group string) (*org.RemovedMember, error) {
	if group == "" {
		return nil, org.ErrMemberMissing
	}
	return s.removeMembership(ctx, userID, token, group, "", true)
}

func (s *Store) removeMembership(ctx context.Context, userID, token, group, target string, leave bool) (*org.RemovedMember, error) {
	var member *org.RemovedMember
	var err error
	for range 3 {
		member, err = s.removeMembershipOnce(ctx, userID, token, group, target, leave)
		if !retryIdentity(err) {
			break
		}
	}
	return member, err
}

func (s *Store) removeMembershipOnce(ctx context.Context, userID, token, group, target string, leave bool) (*org.RemovedMember, error) {
	tx, err := s.beginMembershipChange(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if err = s.lockActiveAccount(ctx, tx, userID, token, time.Now()); err != nil {
		if errors.Is(err, auth.ErrNotFound) {
			return nil, org.ErrUnauthenticated
		}
		return nil, err
	}
	value := s.exactSQLValue("?")
	var active *string
	err = tx.QueryRowContext(ctx, s.bind(`SELECT "activeOrganizationId" FROM "session" WHERE "userId"=`+value+` AND "token"=`+value), userID, token).Scan(&active)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, org.ErrUnauthenticated
	}
	if err != nil {
		return nil, err
	}
	if group == "" {
		if active == nil || *active == "" {
			return nil, org.ErrNoActiveOrg
		}
		group = *active
	}
	if err = s.lockOrganization(ctx, tx, group); err != nil {
		if errors.Is(err, org.ErrNotFound) {
			return nil, org.ErrMemberMissing
		}
		return nil, err
	}
	actor, err := s.memberForRemoval(ctx, tx, group, `m."userId"=`+value, userID)
	if err != nil {
		return nil, err
	}
	member := actor
	if !leave {
		filter := `m."id"=` + value
		byEmail := strings.Contains(target, "@")
		if byEmail {
			filter = `LOWER(u."email")=` + value
			target = strings.ToLower(target)
		}
		member, err = s.memberForRemoval(ctx, tx, group, filter, target)
		if err != nil {
			return nil, err
		}
		if !byEmail {
			member.User = nil
		}
	}
	actorIsOwner := membershipHasRole(actor.Role, "owner")
	if membershipHasRole(member.Role, "owner") {
		if !actorIsOwner {
			return nil, org.ErrLastOwner
		}
		another, err := s.hasOtherOwner(ctx, tx, group, member.ID)
		if err != nil {
			return nil, err
		}
		if !another {
			return nil, org.ErrLastOwner
		}
	}
	if !leave && !actorIsOwner && !membershipHasRole(actor.Role, "admin") {
		return nil, org.ErrMemberRemove
	}
	if member.UserID != userID {
		if err = s.lockAccount(ctx, tx, member.UserID); err != nil {
			if errors.Is(err, auth.ErrNotFound) {
				return nil, org.ErrMemberMissing
			}
			return nil, err
		}
		// The account could have been deleted or renamed during the wait for its lock.
		current, err := s.memberForRemoval(ctx, tx, group, `m."id"=`+value, member.ID)
		if err != nil {
			return nil, err
		}
		if current.UserID != member.UserID || (member.User != nil && strings.ToLower(current.User.Email) != target) {
			return nil, org.ErrMemberMissing
		}
		if member.User != nil {
			member.User = current.User
		}
	}
	teams, err := s.hasKeyOwnerTable(ctx, tx, "teamMember")
	if err != nil {
		return nil, err
	}
	if teams {
		if err = s.clearMemberTeams(ctx, tx, group, member.UserID); err != nil {
			return nil, err
		}
	}
	if _, err = tx.ExecContext(ctx, s.bind(`UPDATE "session" SET "activeOrganizationId"=NULL WHERE "userId"=`+value+` AND "activeOrganizationId"=`+value), member.UserID, group); err != nil {
		return nil, err
	}
	if _, err = tx.ExecContext(ctx, s.bind(`DELETE FROM "member" WHERE "id"=`+value+` AND "organizationId"=`+value+` AND "userId"=`+value), member.ID, group, member.UserID); err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return member, nil
}

func (s *Store) memberForRemoval(ctx context.Context, tx *sql.Tx, group, filter, value string) (*org.RemovedMember, error) {
	m := org.RemovedMember{User: &org.MemberUser{}}
	query := `SELECT m."id",m."organizationId",m."userId",m."role",m."createdAt",u."id",u."name",u."email",u."image" FROM "member" m JOIN "user" u ON u."id"=` + s.exactSQLValue(`m."userId"`) + ` WHERE m."organizationId"=` + s.exactSQLValue("?") + ` AND ` + filter
	err := tx.QueryRowContext(ctx, s.bind(query), group, value).Scan(&m.ID, &m.OrganizationID, &m.UserID, &m.Role, &m.CreatedAt, &m.User.ID, &m.User.Name, &m.User.Email, &m.User.Image)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, org.ErrMemberMissing
	}
	return &m, err
}

func membershipHasRole(roles, want string) bool {
	for role := range strings.SplitSeq(roles, ",") {
		if strings.TrimSpace(role) == want {
			return true
		}
	}
	return false
}

func (s *Store) hasOtherOwner(ctx context.Context, tx *sql.Tx, group, member string) (bool, error) {
	arg := s.exactSQLValue("?")
	rows, err := tx.QueryContext(ctx, s.bind(`SELECT "role" FROM "member" WHERE "organizationId"=`+arg+` AND "id"<>`+arg), group, member)
	if err != nil {
		return false, err
	}
	defer rows.Close()
	for rows.Next() {
		var role string
		if err = rows.Scan(&role); err != nil {
			return false, err
		}
		if membershipHasRole(role, "owner") {
			return true, nil
		}
	}
	return false, rows.Err()
}

func (s *Store) clearMemberTeams(ctx context.Context, tx *sql.Tx, group, user string) error {
	arg := s.exactSQLValue("?")
	teams := `SELECT "id" FROM "team" WHERE "organizationId"=` + arg
	// Count the remaining real memberships only for teams that lose this user.
	byTeam := `tm."teamId"=` + s.exactSQLValue(`"team"."id"`)
	recount := `UPDATE "team" SET "memberCount"=(SELECT COUNT(*) FROM "teamMember" tm WHERE ` + byTeam + ` AND tm."userId"<>` + arg +
		`) WHERE "organizationId"=` + arg + ` AND EXISTS (SELECT 1 FROM "teamMember" tm WHERE ` + byTeam + ` AND tm."userId"=` + arg + `)`
	if _, err := tx.ExecContext(ctx, s.bind(recount), user, group, user); err != nil {
		return err
	}
	for _, q := range []string{
		`UPDATE "session" SET "activeTeamId"=NULL WHERE "userId"=` + arg + ` AND ` + s.exactSQLValue(`"activeTeamId"`) + ` IN (` + teams + `)`,
		`DELETE FROM "teamMember" WHERE "userId"=` + arg + ` AND ` + s.exactSQLValue(`"teamId"`) + ` IN (` + teams + `)`,
	} {
		if _, err := tx.ExecContext(ctx, s.bind(q), user, group); err != nil {
			return err
		}
	}
	return nil
}
