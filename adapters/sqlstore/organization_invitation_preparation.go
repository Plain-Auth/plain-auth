package sqlstore

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"time"

	auth "github.com/Plain-Auth/plain-auth"
	org "github.com/Plain-Auth/plain-auth/plugins/organization"
)

var errPrepareInvitation = errors.New("prepare invitation outside transaction")

type invitationPreparation struct {
	before    org.InvitationCreationHook
	useActive bool
	event     org.InvitationCreationEvent
	issuer    []byte
	prior     *org.Invitation
	changes   *org.InvitationChanges
}

func (s *Store) IssuePreparedInvitation(ctx context.Context, inv org.Invitation, actor auth.Session, how org.InvitationIssueOptions, before org.InvitationCreationHook) (*org.InvitationDelivery, error) {
	if actor.UserID != inv.InviterID || actor.ID == "" {
		return nil, org.ErrUnauthenticated
	}
	if before == nil {
		return nil, errors.New("organization: missing invitation creation hook")
	}
	delivery := invitationDelivery{actor: actor}
	prep := invitationPreparation{before: before, useActive: how.UseActiveOrganization}
	_, err := s.issueOrganizationInvitation(ctx, inv, invitationIssue{sessionID: actor.ID, resend: how.Resend, replace: how.Replace, delivery: &delivery, preparation: &prep})
	if err != nil {
		return nil, err
	}
	return &delivery.message, nil
}

func (p *invitationPreparation) checkScope(ctx context.Context, s *Store, tx *sql.Tx, actor auth.Session, group string, prior *org.Invitation) error {
	if p.useActive {
		active, err := s.lockMembershipScope(ctx, tx, actor.UserID, actor.Token, "")
		if err != nil {
			return err
		}
		if active != group {
			return org.ErrInvitationCreationChanged
		}
	}
	if p.issuer != nil && !reflect.DeepEqual(p.prior, prior) {
		return org.ErrInvitationCreationChanged
	}
	return nil
}

// The first pass captures the issuer and proposed values after all admission
// checks. The second checks the same grant and applies the host's overrides.
func (p *invitationPreparation) prepareGrant(ctx context.Context, s *Store, tx *sql.Tx, inv org.Invitation, prior *org.Invitation, member org.Member, teamField bool) (org.Invitation, error) {
	issuer, err := s.invitationIssuer(ctx, tx, member)
	if err != nil {
		return inv, err
	}
	current, err := json.Marshal(issuer)
	if err != nil {
		return inv, err
	}
	if p.issuer == nil {
		p.prior, p.issuer = prior, current
		draft := org.InvitationDraft{Email: inv.Email, Role: inv.Role, OrganizationID: inv.OrganizationID, InviterID: inv.InviterID, TeamIDs: []string{}}
		if inv.TeamID != nil {
			draft.TeamIDs = strings.Split(*inv.TeamID, ",")
			first := draft.TeamIDs[0]
			draft.TeamID = &first
		}
		p.event = org.InvitationCreationEvent{Invitation: draft, Inviter: issuer.User, Organization: issuer.Organization}
		return inv, errPrepareInvitation
	}
	if !bytes.Equal(current, p.issuer) {
		return inv, org.ErrInvitationCreationChanged
	}
	updated, err := p.changes.Apply(inv)
	if err != nil {
		return inv, err
	}
	if membershipHasRole(updated.Role, "owner") && !membershipHasRole(member.Role, "owner") {
		return inv, org.ErrRoleDenied
	}
	if updated.Email != inv.Email {
		pending, err := s.invitationRecipient(ctx, tx, updated, teamField)
		if err != nil {
			return inv, err
		}
		if pending != nil {
			return inv, org.ErrAlreadyInvited
		}
	}
	if p.changes != nil && p.changes.TeamIDs != nil {
		if err := s.checkInvitationTeams(ctx, tx, updated); err != nil {
			return inv, err
		}
	}
	return updated, nil
}

func (s *Store) invitationRecipient(ctx context.Context, tx *sql.Tx, inv org.Invitation, teamField bool) (*org.Invitation, error) {
	exact := s.exactSQLValue("?")
	var member bool
	q := `SELECT EXISTS(SELECT 1 FROM "member" m JOIN "user" u ON u."id"=m."userId" WHERE m."organizationId"=` + exact + ` AND LOWER(u."email")=?)`
	if err := tx.QueryRowContext(ctx, s.bind(q), inv.OrganizationID, inv.Email).Scan(&member); err != nil {
		return nil, err
	}
	if member {
		return nil, org.ErrAlreadyMember
	}
	q = `SELECT ` + invitationColumns(teamField) + ` FROM "invitation" WHERE "organizationId"=` + exact + ` AND LOWER("email")=? AND "status"='pending' AND "expiresAt">? ORDER BY "createdAt" DESC LIMIT 1`
	pending, err := scanInvitation(tx.QueryRowContext(ctx, s.bind(q), inv.OrganizationID, inv.Email, s.date(time.Now())), teamField)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &pending, nil
}

func (s *Store) checkInvitationTeams(ctx context.Context, tx *sql.Tx, inv org.Invitation) error {
	if inv.TeamID == nil {
		return nil
	}
	if s.teamOptions == nil {
		return org.ErrTeamNotFound
	}
	for _, id := range strings.Split(*inv.TeamID, ",") {
		if _, err := s.findTeam(ctx, tx, inv.OrganizationID, id); err != nil {
			return err
		}
		if _, err := s.teamCapacity(ctx, tx, id); err != nil {
			return err
		}
	}
	return nil
}
