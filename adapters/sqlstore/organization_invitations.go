package sqlstore

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"

	auth "github.com/Plain-Auth/plain-auth"
	org "github.com/Plain-Auth/plain-auth/plugins/organization"
)

// ListOrganizationInvitations resolves the live session and current role in
// the same snapshot as the invitation rows, without changing the selection.
func (s *Store) ListOrganizationInvitations(ctx context.Context, sessionID, userID, organizationID string, includeTeams bool) ([]org.Invitation, error) {
	tx, err := s.beginReadSnapshot(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	group, role, err := s.organizationRole(ctx, tx, sessionID, userID, org.MemberRoleQuery{OrganizationID: organizationID})
	switch {
	case errors.Is(err, org.ErrNoActiveOrg):
		return nil, org.ErrInvitationOrganizationRequired
	case errors.Is(err, org.ErrRoleReadDenied):
		return nil, org.ErrInvitationListNonmember
	case err != nil:
		return nil, err
	}
	owner := membershipHasRole(role, "owner")
	if !owner && !membershipHasRole(role, "admin") {
		return nil, org.ErrInvitationListDenied
	}
	items, err := s.visibleOrganizationInvitations(ctx, tx, group, owner, includeTeams)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return items, nil
}

func (s *Store) visibleOrganizationInvitations(ctx context.Context, tx *sql.Tx, group string, owner, teams bool) ([]org.Invitation, error) {
	query := `SELECT ` + invitationColumns(teams) + ` FROM "invitation" WHERE "organizationId"=` + s.exactSQLValue("?") + ` ORDER BY "createdAt","id" LIMIT 100`
	rows, err := tx.QueryContext(ctx, s.bind(query), group)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []org.Invitation{}
	for rows.Next() {
		invite, err := scanInvitation(rows, teams)
		if err != nil {
			return nil, err
		}
		if owner || !membershipHasRole(invite.Role, "owner") {
			out = append(out, invite)
		}
	}
	return out, rows.Err()
}

// ListReceivedInvitations reads the live, verified account and the mailbox's
// invitation rows in the same snapshot. Session data supplied by a client
// cannot choose the email address.
func (s *Store) ListReceivedInvitations(ctx context.Context, sessionID, userID string, teams bool) ([]org.ReceivedInvitation, error) {
	return s.receivedInvitations(ctx, sessionID, userID, "", teams)
}

// ListInvitationsForEmail is a trusted in-process operation.
func (s *Store) ListInvitationsForEmail(ctx context.Context, email string, teams bool) ([]org.ReceivedInvitation, error) {
	if email == "" {
		return nil, org.ErrInvitationEmailRequired
	}
	return s.receivedInvitations(ctx, "", "", email, teams)
}

func (s *Store) receivedInvitations(ctx context.Context, sessionID, userID, email string, teams bool) ([]org.ReceivedInvitation, error) {
	tx, err := s.beginReadSnapshot(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	exact := s.exactSQLValue
	if email == "" {
		var verified bool
		email, verified, err = s.invitationSessionEmail(ctx, tx, sessionID, userID)
		if errors.Is(err, org.ErrInvitationSignIn) {
			return nil, org.ErrInvitationEmailRequired
		}
		if err != nil {
			return nil, err
		}
		if !verified {
			return nil, org.ErrInvitationAccountUnverified
		}
	}
	// Limit the mailbox page before selecting its pending entries. Expiry is
	// enforced when a recipient acts on an invitation.
	query := `SELECT ` + invitationColumns(teams) + `, (SELECT o."name" FROM "organization" o WHERE o."id"=` + exact(`i."organizationId"`) + `)
		FROM "invitation" i WHERE i."email"=` + exact("?") + ` ORDER BY i."createdAt",i."id" LIMIT 100`
	rows, err := tx.QueryContext(ctx, s.bind(query), strings.ToLower(email))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []org.ReceivedInvitation{}
	for rows.Next() {
		var name string
		inv, err := scanInvitation(rows, teams, &name)
		if err != nil {
			return nil, err
		}
		if inv.Status == "pending" {
			out = append(out, org.ReceivedInvitation{Invitation: inv, OrganizationName: name})
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return out, nil
}

func (s *Store) invitationSessionEmail(ctx context.Context, tx *sql.Tx, sessionID, userID string) (string, bool, error) {
	exact := s.exactSQLValue
	query := `SELECT u."email",u."emailVerified" FROM "session" ss JOIN "user" u ON u."id"=` + exact(`ss."userId"`) + ` WHERE ss."id"=` + exact("?") + ` AND ss."userId"=` + exact("?") + ` AND ss."expiresAt">?`
	var email string
	var verified bool
	err := tx.QueryRowContext(ctx, s.bind(query), sessionID, userID, s.date(time.Now())).Scan(&email, &verified)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, org.ErrInvitationSignIn
	}
	return email, verified, err
}

// OrganizationInvitation resolves an actionable invitation and its current
// inviter from the same snapshot as the recipient account.
func (s *Store) OrganizationInvitation(ctx context.Context, sessionID, userID, id string, requireVerified, teams bool) (*org.InvitationDetails, error) {
	tx, err := s.beginReadSnapshot(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	email, verified, err := s.invitationSessionEmail(ctx, tx, sessionID, userID)
	if err != nil {
		return nil, err
	}
	exact := s.exactSQLValue
	query := `SELECT ` + invitationColumns(teams) + ` FROM "invitation" WHERE "id"=` + exact("?") + ` AND "status"='pending' AND "expiresAt">=?`
	inv, err := scanInvitation(tx.QueryRowContext(ctx, s.bind(query), id, s.date(time.Now())), teams)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, org.ErrInvitation
	}
	if err != nil {
		return nil, err
	}
	if strings.ToLower(inv.Email) != strings.ToLower(email) {
		return nil, org.ErrRecipient
	}
	if requireVerified && !verified {
		return nil, org.ErrInvitationAccountUnverified
	}
	view := &org.InvitationDetails{ReceivedInvitation: org.ReceivedInvitation{Invitation: inv}}
	var sender sql.NullString
	query = `SELECT o."name",o."slug",(SELECT u."email" FROM "member" m JOIN "user" u ON u."id"=` + exact(`m."userId"`) +
		` WHERE m."organizationId"=` + exact(`o."id"`) + ` AND m."userId"=` + exact("?") + `) FROM "organization" o WHERE o."id"=` + exact("?")
	err = tx.QueryRowContext(ctx, s.bind(query), inv.InviterID, inv.OrganizationID).Scan(&view.OrganizationName, &view.OrganizationSlug, &sender)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return nil, org.ErrNotFound
	case err != nil:
		return nil, err
	case !sender.Valid:
		return nil, org.ErrInviterRemoved
	}
	view.InviterEmail = sender.String
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return view, nil
}

// All invitation decisions serialize with grants and membership changes in the same organization.
func (s *Store) lockInvitation(ctx context.Context, tx *sql.Tx, id string) (org.Invitation, error) {
	var organizationID string
	exact := s.exactSQLValue("?")
	err := tx.QueryRowContext(ctx, s.bind(`SELECT "organizationId" FROM "invitation" WHERE "id"=`+exact), id).Scan(&organizationID)
	if errors.Is(err, sql.ErrNoRows) {
		return org.Invitation{}, org.ErrInvitation
	}
	if err != nil {
		return org.Invitation{}, err
	}
	if err = s.lockOrganization(ctx, tx, organizationID); err != nil {
		return org.Invitation{}, err
	}
	teamField, err := s.organizationTeamField(ctx, tx, "invitation", "teamId")
	if err != nil {
		return org.Invitation{}, err
	}
	inv, err := scanInvitation(tx.QueryRowContext(ctx, s.bind(`SELECT `+invitationColumns(teamField)+` FROM "invitation" WHERE "id"=`+exact+` AND "organizationId"=`+exact), id, organizationID), teamField)
	if errors.Is(err, sql.ErrNoRows) {
		return org.Invitation{}, org.ErrInvitation
	}
	if err != nil {
		return org.Invitation{}, err
	}
	return inv, nil
}

// RejectOrganizationInvitation changes only a pending invitation's status. Expiry
// limits admission and does not prevent the recipient from declining it.
func (s *Store) RejectOrganizationInvitation(ctx context.Context, actor auth.Session, id string, requireVerified bool) (*org.Invitation, error) {
	if err := actor.RequireOwner(); err != nil {
		return nil, err
	}
	tx, err := s.beginMembershipChange(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if err = s.lockActiveAccount(ctx, tx, actor.UserID, actor.Token, time.Now()); err != nil {
		if errors.Is(err, auth.ErrNotFound) {
			return nil, org.ErrUnauthenticated
		}
		return nil, err
	}
	inv, err := s.lockInvitation(ctx, tx, id)
	if err != nil {
		return nil, err
	}
	account, err := s.organizationSessionAccount(ctx, tx, actor)
	if err != nil {
		return nil, err
	}
	if inv.Status != "pending" {
		return nil, org.ErrInvitation
	}
	if strings.ToLower(inv.Email) != strings.ToLower(account.user.Email) {
		return nil, org.ErrRecipient
	}
	if requireVerified && !account.user.EmailVerified {
		return nil, org.ErrUnverified
	}
	value := s.exactSQLValue("?")
	result, err := tx.ExecContext(ctx, s.bind(`UPDATE "invitation" SET "status"='rejected' WHERE "id"=`+value+` AND "organizationId"=`+value+` AND "status"='pending'`), inv.ID, inv.OrganizationID)
	if err != nil {
		return nil, err
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return nil, err
	}
	if changed != 1 {
		return nil, org.ErrInvitation
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	inv.Status = "rejected"
	return &inv, nil
}
