package sqlstore

import (
	"context"
	"database/sql"
	"strings"

	auth "github.com/Plain-Auth/plain-auth"
	org "github.com/Plain-Auth/plain-auth/plugins/organization"
)

type invitationDelivery struct {
	actor   auth.Session
	message org.InvitationDelivery
}

func (s *Store) IssueInvitationForDelivery(ctx context.Context, inv org.Invitation, actor auth.Session, resend, replace bool) (*org.InvitationDelivery, error) {
	if actor.UserID != inv.InviterID || actor.ID == "" {
		return nil, org.ErrUnauthenticated
	}
	delivery := invitationDelivery{actor: actor}
	_, err := s.issueOrganizationInvitation(ctx, inv, invitationIssue{sessionID: actor.ID, resend: resend, replace: replace, delivery: &delivery})
	if err != nil {
		return nil, err
	}
	return &delivery.message, nil
}

func (s *Store) commitIssuedInvitation(ctx context.Context, tx *sql.Tx, inv org.Invitation, member org.Member, delivery *invitationDelivery) (org.Invitation, error) {
	if delivery != nil {
		issuer, err := s.invitationIssuer(ctx, tx, member)
		if err != nil {
			return org.Invitation{}, err
		}
		delivery.message = org.InvitationDelivery{
			Invitation: inv, Email: strings.ToLower(inv.Email), Organization: issuer.Organization,
			Inviter: org.InvitationSender{Member: member, User: issuer.User},
		}
	}
	if err := tx.Commit(); err != nil {
		return org.Invitation{}, err
	}
	return inv, nil
}
