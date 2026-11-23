package sqlstore

import (
	"context"
	"database/sql"
	"errors"
	"slices"
	"strings"
	"time"

	auth "github.com/Plain-Auth/plain-auth"
	org "github.com/Plain-Auth/plain-auth/plugins/organization"
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
	value := s.exactSQLValue("?")
	filter := `m."id"=` + value
	byEmail := strings.Contains(target, "@")
	if byEmail {
		filter = `LOWER(u."email")=` + value
		target = strings.ToLower(target)
	}
	var lockedTarget string
	if !leave {
		lockedTarget, err = s.lockMembershipAccounts(ctx, tx, userID, token, group, filter, target)
		if err != nil {
			return nil, err
		}
	}
	group, err = s.lockMembershipScope(ctx, tx, userID, token, group)
	if err != nil {
		return nil, err
	}
	actor, err := s.lockMembershipActor(ctx, tx, userID, group)
	if err != nil {
		return nil, err
	}
	member := actor
	if !leave {
		member, err = s.memberForChange(ctx, tx, group, filter, target)
		if err != nil {
			return nil, err
		}
		if member.UserID != lockedTarget {
			return nil, org.ErrMemberMissing
		}
		if !byEmail {
			member.User = nil
		}
	}
	creator := s.organizationRoles.CreatorRole()
	if membershipHasRole(member.Role, creator) {
		if !membershipHasRole(actor.Role, creator) {
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
	if !leave && !s.organizationRoles.HasAction(actor.Role, "member", "delete") {
		return nil, org.ErrMemberRemove
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
	if err = s.dirtyOrganizationSeats(ctx, tx, group); err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return member, nil
}

// Resolve an optional tenant ID while holding the live owner session lock.
func (s *Store) lockMembershipScope(ctx context.Context, tx *sql.Tx, userID, token, group string) (string, error) {
	value := s.exactSQLValue("?")
	if err := s.lockActiveAccount(ctx, tx, userID, token, time.Now()); err != nil {
		if errors.Is(err, auth.ErrNotFound) {
			return "", org.ErrUnauthenticated
		}
		return "", err
	}
	var active *string
	err := tx.QueryRowContext(ctx, s.bind(`SELECT "activeOrganizationId" FROM "session" WHERE "userId"=`+value+` AND "token"=`+value), userID, token).Scan(&active)
	if errors.Is(err, sql.ErrNoRows) {
		return "", org.ErrUnauthenticated
	}
	if err != nil {
		return "", err
	}
	if group == "" {
		if active == nil || *active == "" {
			return "", org.ErrNoActiveOrg
		}
		group = *active
	}
	return group, nil
}

// Serialize changes within the tenant before checking the actor's current role.
func (s *Store) lockMembershipActor(ctx context.Context, tx *sql.Tx, userID, group string) (*org.RemovedMember, error) {
	if err := s.lockOrganization(ctx, tx, group); err != nil {
		if errors.Is(err, org.ErrNotFound) {
			return nil, org.ErrMemberMissing
		}
		return nil, err
	}
	return s.memberForChange(ctx, tx, group, `m."userId"=`+s.exactSQLValue("?"), userID)
}

// Discover the target without taking locks. Acquire both accounts in the same
// order as team and administrative changes, before locking the session and
// organization. The caller checks the session, scope and membership again
// under those locks before authorizing any change.
func (s *Store) lockMembershipAccounts(ctx context.Context, tx *sql.Tx, userID, token, group, filter, target string) (string, error) {
	value := s.exactSQLValue("?")
	scope := s.exactSQLValue(`COALESCE(NULLIF(?, ''), ss."activeOrganizationId")`)
	query := `SELECT m."userId" FROM "session" ss JOIN "member" m ON m."organizationId"=` + scope +
		` JOIN "user" u ON u."id"=` + s.exactSQLValue(`m."userId"`) +
		` WHERE ss."userId"=` + value + ` AND ss."token"=` + value + ` AND ` + filter
	var candidate string
	err := tx.QueryRowContext(ctx, s.bind(query), group, userID, token, target).Scan(&candidate)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	if err != nil || candidate == userID {
		return candidate, err
	}
	accounts := []string{userID, candidate}
	slices.Sort(accounts)
	for _, id := range accounts {
		err := s.lockAccount(ctx, tx, id)
		if errors.Is(err, auth.ErrNotFound) {
			if id == userID {
				return "", org.ErrUnauthenticated
			}
			return "", nil
		}
		if err != nil {
			return "", err
		}
	}
	return candidate, nil
}

func (s *Store) memberForChange(ctx context.Context, tx *sql.Tx, group, filter, value string) (*org.RemovedMember, error) {
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
		if membershipHasRole(role, s.organizationRoles.CreatorRole()) {
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
