package sqlstore

import (
	"context"
	"crypto/rand"
	"database/sql"
	"errors"
	"strings"
	"time"

	authn "github.com/Plain-Auth/plain-auth"
	ak "github.com/Plain-Auth/plain-auth/plugins/apikey"
	org "github.com/Plain-Auth/plain-auth/plugins/organization"
	"github.com/go-sql-driver/mysql"
)

var _ org.Store = (*Store)(nil)

// Re-read the account and session under the same locks as account deletion.
// Invitation acceptance uses the current email and verification status.
func (s *Store) organizationActor(ctx context.Context, tx *sql.Tx, userID, sessionID string, now time.Time) (authn.User, error) {
	var user authn.User
	_, err := s.lockAllowedAccount(ctx, tx, userID, now)
	if errors.Is(err, authn.ErrNotFound) {
		return user, org.ErrUnauthenticated
	}
	if err != nil {
		return user, err
	}
	exact := s.exactSQLValue
	query := `SELECT u."id",u."email",u."emailVerified" FROM "user" u JOIN "session" ss ON ss."userId"=` + exact(`u."id"`) + ` WHERE u."id"=` + exact("?") + ` AND ss."id"=` + exact("?") + ` AND ss."expiresAt">?`
	err = tx.QueryRowContext(ctx, s.readForUpdate(query), userID, sessionID, s.date(now)).Scan(&user.ID, &user.Email, &user.EmailVerified)
	if errors.Is(err, sql.ErrNoRows) {
		return user, org.ErrUnauthenticated
	}
	return user, err
}

func (s *Store) CreateOrganization(ctx context.Context, o org.Organization, owner org.Member, sessionID string, keep bool) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := s.organizationActor(ctx, tx, owner.UserID, sessionID, time.Now()); err != nil {
		return err
	}
	query := `INSERT INTO "organization" ("id","name","slug","logo","metadata","createdAt") VALUES(?,?,?,?,?,?)`
	if s.dialect != "mysql" {
		query += ` ON CONFLICT ("slug") DO NOTHING`
	}
	var metadata any
	if len(o.Metadata) > 0 {
		metadata = string(o.Metadata)
	}
	r, err := tx.ExecContext(ctx, s.bind(query), o.ID, o.Name, o.Slug, o.Logo, metadata, s.date(o.CreatedAt))
	if err != nil {
		var duplicate *mysql.MySQLError
		if errors.As(err, &duplicate) && duplicate.Number == 1062 {
			return org.ErrDuplicate
		}
		return err
	}
	n, err := r.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return org.ErrDuplicate
	}
	if err = s.addMember(ctx, tx, owner); err != nil {
		return err
	}
	var initialTeam *string
	if s.teamOptions != nil && !s.teamOptions.DisableDefaultTeam {
		team, err := s.insertTeam(ctx, tx, o.ID, o.Name, false)
		if err != nil {
			return err
		}
		if _, err = s.insertTeamMember(ctx, tx, team.ID, owner.UserID, false); err != nil {
			return err
		}
		initialTeam = &team.ID
	}
	if !keep {
		if err = s.selectOrganizationAndTeam(ctx, tx, sessionID, owner.UserID, &o.ID, initialTeam); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) addMember(ctx context.Context, tx *sql.Tx, m org.Member) error {
	_, err := tx.ExecContext(ctx, s.bind(`INSERT INTO "member" ("id","userId","organizationId","role","createdAt") VALUES(?,?,?,?,?)`), m.ID, m.UserID, m.OrganizationID, m.Role, s.date(m.CreatedAt))
	if err != nil {
		return err
	}
	return s.dirtyOrganizationSeats(ctx, tx, m.OrganizationID)
}

const orgFields = `o."id",o."name",o."slug",o."logo",o."createdAt",o."metadata"`

type rowScanner interface{ Scan(...any) error }

func readOrg(row rowScanner, extra ...any) (*org.Organization, error) {
	var o org.Organization
	var metadata sql.NullString
	fields := []any{&o.ID, &o.Name, &o.Slug, &o.Logo, &o.CreatedAt, &metadata}
	if err := row.Scan(append(fields, extra...)...); err != nil {
		return nil, err
	}
	if metadata.Valid {
		o.Metadata = []byte(metadata.String)
	}
	return &o, nil
}

func (s *Store) OrganizationsForUser(ctx context.Context, user string) ([]org.Organization, error) {
	query := `SELECT ` + orgFields + ` FROM "organization" o WHERE EXISTS(SELECT 1 FROM "member" m WHERE m."organizationId"=o."id" AND m."userId"=?) ORDER BY o."createdAt",o."id"`
	rows, err := s.db.QueryContext(ctx, s.bind(query), user)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []org.Organization{}
	for rows.Next() {
		o, err := readOrg(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, *o)
	}
	return result, rows.Err()
}

func (s *Store) OrganizationForMember(ctx context.Context, user, id, slug string) (*org.Organization, error) {
	field, value := `o."id"`, id
	if slug != "" {
		field, value = `o."slug"`, slug
	}
	query := `SELECT ` + orgFields + `, EXISTS(SELECT 1 FROM "member" m WHERE m."organizationId"=o."id" AND m."userId"=?) FROM "organization" o WHERE ` + field + `=?`
	var member bool
	o, err := readOrg(s.db.QueryRowContext(ctx, s.bind(query), user, value), &member)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, org.ErrNotFound
	}
	if err == nil && !member {
		return nil, org.ErrNotMember
	}
	return o, err
}

func (s *Store) ActiveOrganization(ctx context.Context, sessionID, userID string) (*string, error) {
	var id *string
	query := `SELECT m."organizationId" FROM "session" s LEFT JOIN "member" m ON m."organizationId"=s."activeOrganizationId" AND m."userId"=s."userId" WHERE s."id"=? AND s."userId"=?`
	err := s.db.QueryRowContext(ctx, s.bind(query), sessionID, userID).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return id, err
}

// All invitation/membership decisions for an organization use the same row
// lock. This also protects the membership limit and duplicate-invitation check.
func (s *Store) lockOrganization(ctx context.Context, tx *sql.Tx, id string) error {
	query := `SELECT "id" FROM "organization" WHERE "id"=?`
	if s.dialect == "sqlite" {
		if _, err := tx.ExecContext(ctx, `UPDATE "organization" SET "name"="name" WHERE "id"=?`, id); err != nil {
			return err
		}
	} else {
		query += " FOR UPDATE"
	}
	var found string
	err := tx.QueryRowContext(ctx, s.bind(query), id).Scan(&found)
	// Custom policies and billing metadata use opaque, case-sensitive IDs,
	// including when the database resolves lookup keys with a looser collation.
	if errors.Is(err, sql.ErrNoRows) || err == nil && found != id {
		return org.ErrNotFound
	}
	return err
}

const invitationFields = `"id","organizationId","inviterId","email","role","status","expiresAt","createdAt"`

func invitationColumns(teamField bool) string {
	if teamField {
		return invitationFields + `,"teamId"`
	}
	return invitationFields
}
func scanInvitation(r rowScanner, teamField bool, extra ...any) (org.Invitation, error) {
	var inv org.Invitation
	var role sql.NullString
	fields := []any{&inv.ID, &inv.OrganizationID, &inv.InviterID, &inv.Email, &role, &inv.Status, &inv.ExpiresAt, &inv.CreatedAt}
	if teamField {
		fields = append(fields, &inv.TeamID)
	}
	err := r.Scan(append(fields, extra...)...)
	inv.Role = role.String
	return inv, err
}

func (s *Store) InviteOrganizationMember(ctx context.Context, inv org.Invitation, sessionID string, resend bool) (org.Invitation, error) {
	return s.issueOrganizationInvitation(ctx, inv, invitationIssue{sessionID: sessionID, resend: resend})
}

// ReplaceOrganizationInvitation installs a fresh invitation. A failed issue
// leaves the previous grant usable.
func (s *Store) ReplaceOrganizationInvitation(ctx context.Context, inv org.Invitation, sessionID string) (org.Invitation, error) {
	return s.issueOrganizationInvitation(ctx, inv, invitationIssue{sessionID: sessionID, replace: true})
}

type invitationIssue struct {
	sessionID     string
	resend        bool
	replace       bool
	delivery      *invitationDelivery
	preparation   *invitationPreparation
	targets       *org.InvitationTeamTargets
	validateRoles bool
}

func (s *Store) issueInvitationTx(ctx context.Context, inv org.Invitation, issue invitationIssue, capacity *invitationCapacity) (org.Invitation, error) {
	tx, err := s.beginMembershipChange(ctx)
	if err != nil {
		return org.Invitation{}, err
	}
	defer tx.Rollback()
	if proof, ok := ak.SessionProofFrom(ctx); ok {
		if proof.ID != issue.sessionID || proof.UserID != inv.InviterID {
			return inv, org.ErrUnauthenticated
		}
		if err := s.lockKeySession(ctx, tx, proof, "invitation", "create", time.Now()); err != nil {
			return inv, err
		}
	} else if issue.delivery != nil {
		if err := issue.delivery.actor.RequireOwner(); err != nil {
			return org.Invitation{}, err
		}
		if _, err := s.lockInvitationSession(ctx, tx, issue.delivery.actor); err != nil {
			return org.Invitation{}, err
		}
	} else if _, err := s.organizationActor(ctx, tx, inv.InviterID, issue.sessionID, time.Now()); err != nil {
		return org.Invitation{}, err
	}
	if err = s.lockOrganization(ctx, tx, inv.OrganizationID); err != nil {
		if errors.Is(err, org.ErrNotFound) {
			return org.Invitation{}, org.ErrMemberMissing
		}
		return org.Invitation{}, err
	}
	member, err := s.memberForChange(ctx, tx, inv.OrganizationID, `m."userId"=`+s.exactSQLValue("?"), inv.InviterID)
	if err != nil {
		return org.Invitation{}, err
	}
	policy, err := s.resolveOrganizationRoles(ctx, tx, inv.OrganizationID)
	if err != nil {
		return org.Invitation{}, err
	}
	creator := policy.CreatorRole()
	owner := membershipHasRole(member.Role, creator)
	if !policy.HasAction(member.Role, "invitation", "create") {
		return org.Invitation{}, org.ErrInviteDenied
	}
	if issue.validateRoles {
		inv.Role, err = policy.ParseInvitationRoles(inv.Role)
		if err != nil {
			return org.Invitation{}, err
		}
	}
	if !owner && membershipHasRole(inv.Role, creator) {
		return org.Invitation{}, org.ErrRoleDenied
	}
	teamField, err := s.organizationTeamField(ctx, tx, "invitation", "teamId")
	if err != nil {
		return org.Invitation{}, err
	}
	pending, err := s.invitationRecipient(ctx, tx, inv, teamField)
	if err != nil {
		return org.Invitation{}, err
	}
	prep := issue.preparation
	if prep != nil {
		if err := prep.checkScope(ctx, s, tx, issue.delivery.actor, inv.OrganizationID, pending); err != nil {
			return org.Invitation{}, err
		}
	}
	exact := s.exactSQLValue("?")
	switch {
	case pending == nil:
		// Issue a fresh invitation.
	case issue.resend:
		if !owner && membershipHasRole(pending.Role, creator) {
			return org.Invitation{}, org.ErrRoleDenied
		}
		pending.ExpiresAt = inv.ExpiresAt
		_, err = tx.ExecContext(ctx, s.bind(`UPDATE "invitation" SET "expiresAt"=? WHERE "id"=`+exact+` AND "organizationId"=`+exact), s.date(pending.ExpiresAt), pending.ID, inv.OrganizationID)
		if err != nil {
			return org.Invitation{}, err
		}
		return s.commitIssuedInvitation(ctx, tx, *pending, member.Member, issue.delivery, true)
	case issue.replace:
		replaced := *pending
		if err := s.updateInvitationStatus(ctx, tx, &replaced, "canceled"); err != nil {
			return org.Invitation{}, err
		}
	default:
		return org.Invitation{}, org.ErrAlreadyInvited
	}
	if err := s.checkInvitationCapacity(ctx, tx, inv, member.Member, capacity); err != nil {
		return org.Invitation{}, err
	}
	if issue.targets != nil {
		inv.TeamID = nil
		if s.teamOptions != nil {
			inv.TeamID, err = issue.targets.StoredValue()
			if err != nil {
				return org.Invitation{}, err
			}
		}
	}
	if err := s.checkInvitationTeams(ctx, tx, inv); err != nil {
		return org.Invitation{}, err
	}
	if prep != nil {
		inv, err = prep.prepareGrant(ctx, s, tx, inv, pending, member.Member, teamField, policy)
		if err != nil {
			return org.Invitation{}, err
		}
	}
	args := []any{inv.ID, inv.OrganizationID, inv.InviterID, inv.Email, inv.Role, inv.Status, s.date(inv.ExpiresAt), s.date(inv.CreatedAt)}
	if teamField {
		args = append(args, inv.TeamID)
	}
	params := strings.TrimSuffix(strings.Repeat("?,", len(args)), ",")
	_, err = tx.ExecContext(ctx, s.bind(`INSERT INTO "invitation" (`+invitationColumns(teamField)+`) VALUES(`+params+`)`), args...)
	if err != nil {
		return org.Invitation{}, err
	}
	return s.commitIssuedInvitation(ctx, tx, inv, member.Member, issue.delivery, false)
}

func (s *Store) AcceptOrganizationInvitation(ctx context.Context, id, sessionID string, u authn.User, now time.Time, requireVerified bool) (org.Invitation, org.Member, error) {
	var invitation org.Invitation
	var member org.Member
	err := s.withMemberAdmission(ctx, func(admission *memberAdmission) error {
		var err error
		invitation, member, err = s.acceptOrganizationInvitation(ctx, id, sessionID, u, admission.checkedAt(now), requireVerified, admission)
		return err
	})
	return invitation, member, err
}

func (s *Store) acceptOrganizationInvitation(ctx context.Context, id, sessionID string, u authn.User, now time.Time, requireVerified bool, admission *memberAdmission) (org.Invitation, org.Member, error) {
	tx, err := s.beginMembershipChange(ctx)
	if err != nil {
		return org.Invitation{}, org.Member{}, err
	}
	defer tx.Rollback()
	u, err = s.organizationActor(ctx, tx, u.ID, sessionID, now)
	if err != nil {
		return org.Invitation{}, org.Member{}, err
	}
	inv, err := s.lockInvitation(ctx, tx, id)
	if err != nil {
		return org.Invitation{}, org.Member{}, err
	}
	if err := s.checkInvitationAcceptance(ctx, tx, inv, u, now, requireVerified, admission); err != nil {
		return org.Invitation{}, org.Member{}, err
	}
	m, err := s.grantInvitedMembership(ctx, tx, &inv, sessionID, u.ID, now)
	if err != nil {
		return org.Invitation{}, org.Member{}, err
	}
	if err := tx.Commit(); err != nil {
		return org.Invitation{}, org.Member{}, err
	}
	return inv, m, nil
}

func (s *Store) checkInvitationAcceptance(ctx context.Context, tx *sql.Tx, inv org.Invitation, u authn.User, now time.Time, requireVerified bool, admission *memberAdmission) error {
	if inv.Status != "pending" || now.After(inv.ExpiresAt) {
		return org.ErrInvitation
	}
	if strings.ToLower(inv.Email) != strings.ToLower(u.Email) {
		return org.ErrRecipient
	}
	if requireVerified && !u.EmailVerified {
		return org.ErrUnverified
	}
	if inv.TeamID != nil && *inv.TeamID != "" && s.teamOptions == nil {
		return org.ErrTeamPolicyRequired
	}
	return s.checkNewMember(ctx, tx, inv.OrganizationID, u.ID, admission, &inv)
}

func (s *Store) grantInvitedMembership(ctx context.Context, tx *sql.Tx, inv *org.Invitation, sessionID, userID string, now time.Time) (org.Member, error) {
	if err := s.updateInvitationStatus(ctx, tx, inv, "accepted"); err != nil {
		return org.Member{}, err
	}
	m := org.Member{ID: rand.Text(), OrganizationID: inv.OrganizationID, UserID: userID, Role: strings.Join(org.NormalizeRoles(inv.Role), ","), CreatedAt: now}
	if err := s.addMember(ctx, tx, m); err != nil {
		return org.Member{}, err
	}
	var activeTeam *string
	if inv.TeamID != nil && *inv.TeamID != "" {
		ids := strings.Split(*inv.TeamID, ",")
		for _, id := range ids {
			if _, err := s.findTeam(ctx, tx, inv.OrganizationID, id); err != nil {
				return org.Member{}, err
			}
			if _, err := s.insertTeamMember(ctx, tx, id, userID, true); err != nil {
				return org.Member{}, err
			}
		}
		if len(ids) == 1 {
			activeTeam = &ids[0]
		}
	}
	if err := s.selectOrganizationAndTeam(ctx, tx, sessionID, userID, &inv.OrganizationID, activeTeam); err != nil {
		return org.Member{}, err
	}
	return m, nil
}

// Check the physical session schema inside the deletion transaction. A process
// opened with the core profile can share a database with an organization app.
func (s *Store) cleanupOrganizationAccount(ctx context.Context, tx *sql.Tx, userID string) error {
	var names string
	switch s.dialect {
	case "sqlite":
		names = `SELECT name FROM pragma_table_info('session')`
	case "postgres":
		names = `SELECT column_name AS name FROM information_schema.columns WHERE table_schema=current_schema() AND table_name='session'`
	case "mysql":
		names = `SELECT column_name AS name FROM information_schema.columns WHERE table_schema=database() AND table_name='session'`
	}
	var organizations, teams int
	err := tx.QueryRowContext(ctx, `SELECT COUNT(CASE WHEN name='activeOrganizationId' THEN 1 END), COUNT(CASE WHEN name='activeTeamId' THEN 1 END) FROM (`+names+`) AS session_fields`).Scan(&organizations, &teams)
	if err != nil {
		return err
	}
	if organizations > 0 {
		if err := s.dirtyDeletedMemberSeats(ctx, tx, userID); err != nil {
			return err
		}
	}
	if teams > 0 {
		if err := s.removeOrganizationTeamMemberships(ctx, tx, userID); err != nil {
			return err
		}
	}
	if organizations > 0 {
		// An invitation references its sender by ID. Its recipient can be an
		// email address that has never had an account.
		for _, query := range []string{`DELETE FROM "invitation" WHERE "inviterId"=?`, `DELETE FROM "member" WHERE "userId"=?`} {
			if _, err := tx.ExecContext(ctx, s.bind(query), userID); err != nil {
				return err
			}
		}
	}
	return nil
}

func (s *Store) removeOrganizationTeamMemberships(ctx context.Context, tx *sql.Tx, userID string) error {
	rows, err := tx.QueryContext(ctx, s.bind(`SELECT "teamId",COUNT(*) FROM "teamMember" WHERE "userId"=? GROUP BY "teamId" ORDER BY "teamId"`), userID)
	if err != nil {
		return err
	}
	type membership struct {
		team  string
		count int
	}
	var memberships []membership
	for rows.Next() {
		var m membership
		if err := rows.Scan(&m.team, &m.count); err != nil {
			rows.Close()
			return err
		}
		memberships = append(memberships, m)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	if err := rows.Close(); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, s.bind(`DELETE FROM "teamMember" WHERE "userId"=?`), userID); err != nil {
		return err
	}
	for _, m := range memberships {
		if _, err := tx.ExecContext(ctx, s.bind(`UPDATE "team" SET "memberCount"=CASE WHEN "memberCount">=? THEN "memberCount"-? ELSE 0 END WHERE "id"=?`), m.count, m.count, m.team); err != nil {
			return err
		}
	}
	return nil
}
