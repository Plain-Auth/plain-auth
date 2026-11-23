package sqlstore

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"

	auth "github.com/Plain-Auth/plain-auth"
	org "github.com/Plain-Auth/plain-auth/plugins/organization"
)

// RejectOrganizationInvitation changes only a pending invitation's status. Expiry
// limits admission and does not prevent the recipient from declining it.
func (s *Store) RejectOrganizationInvitation(ctx context.Context, actor auth.Session, id string, requireVerified bool) (*org.Invitation, error) {
	return s.unobservedInvitationDecision(ctx, actor, id, org.RejectInvitation, requireVerified)
}

// CancelOrganizationInvitation withdraws an invitation of any status. Access
// already granted by an earlier acceptance is managed through the member API.
func (s *Store) CancelOrganizationInvitation(ctx context.Context, actor auth.Session, id string) (*org.Invitation, error) {
	return s.unobservedInvitationDecision(ctx, actor, id, org.CancelInvitation, false)
}

type invitationDecisionScope struct {
	org.InvitationDecisionEvent
	SessionID        string
	SessionCreatedAt time.Time
	Membership       *org.Member
}

type invitationDecisionPhase int

const (
	directDecision invitationDecisionPhase = iota
	prepareObservedDecision
	commitObservedDecision
)

func (s *Store) unobservedInvitationDecision(ctx context.Context, actor auth.Session, id string, decision org.InvitationDecision, requireVerified bool) (*org.Invitation, error) {
	scope, err := s.invitationDecisionTx(ctx, actor, id, decision, requireVerified, directDecision, nil)
	if err != nil {
		return nil, err
	}
	return &scope.Invitation, nil
}

func (s *Store) ObserveInvitationDecision(ctx context.Context, actor auth.Session, id string, decision org.InvitationDecision, requireVerified bool, before org.InvitationDecisionHook) (*org.InvitationDecisionEvent, error) {
	var expected []byte
	if before != nil {
		scope, err := s.invitationDecisionTx(ctx, actor, id, decision, requireVerified, prepareObservedDecision, nil)
		if err != nil {
			return nil, err
		}
		expected, err = json.Marshal(scope)
		if err != nil {
			return nil, err
		}
		if err = before(ctx, scope.InvitationDecisionEvent); err != nil {
			return nil, err
		}
	}
	scope, err := s.invitationDecisionTx(ctx, actor, id, decision, requireVerified, commitObservedDecision, expected)
	if err != nil {
		return nil, err
	}
	return &scope.InvitationDecisionEvent, nil
}

func (s *Store) invitationDecisionTx(ctx context.Context, actor auth.Session, id string, decision org.InvitationDecision, requireVerified bool, phase invitationDecisionPhase, expected []byte) (*invitationDecisionScope, error) {
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
	scope := &invitationDecisionScope{InvitationDecisionEvent: org.InvitationDecisionEvent{Invitation: inv, Actor: account.user}, SessionID: account.id, SessionCreatedAt: account.createdAt}
	switch decision {
	case org.RejectInvitation:
		if inv.Status != "pending" {
			return nil, org.ErrInvitation
		}
		if strings.ToLower(inv.Email) != strings.ToLower(account.user.Email) {
			return nil, org.ErrRecipient
		}
		if requireVerified && !account.user.EmailVerified {
			return nil, org.ErrUnverified
		}
	case org.CancelInvitation:
		m, err := s.memberForChange(ctx, tx, inv.OrganizationID, `m."userId"=`+s.exactSQLValue("?"), actor.UserID)
		if err != nil {
			return nil, err
		}
		if !membershipHasRole(m.Role, "owner") && !membershipHasRole(m.Role, "admin") {
			return nil, org.ErrCancelDenied
		}
		scope.Membership = &m.Member
	default:
		return nil, errors.New("unknown invitation decision")
	}
	if phase != directDecision {
		group, err := readOrg(tx.QueryRowContext(ctx, s.bind(`SELECT `+orgFields+` FROM "organization" o WHERE o."id"=`+s.exactSQLValue("?")), inv.OrganizationID))
		if err != nil {
			return nil, err
		}
		scope.Organization = *group
	}
	if expected != nil {
		current, err := json.Marshal(scope)
		if err != nil {
			return nil, err
		}
		if !bytes.Equal(expected, current) {
			return nil, org.ErrInvitationDecisionChanged
		}
	}
	if phase != prepareObservedDecision {
		if err := s.updateInvitationStatus(ctx, tx, &scope.Invitation, string(decision)); err != nil {
			return nil, err
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return scope, nil
}

// The caller holds the tenant lock and has checked the transition and authority.
func (s *Store) updateInvitationStatus(ctx context.Context, tx *sql.Tx, inv *org.Invitation, status string) error {
	if inv.Status == status {
		return nil
	}
	value := s.exactSQLValue("?")
	result, err := tx.ExecContext(ctx, s.bind(`UPDATE "invitation" SET "status"=? WHERE "id"=`+value+` AND "organizationId"=`+value+` AND "status"=?`), status, inv.ID, inv.OrganizationID, inv.Status)
	if err != nil {
		return err
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if changed != 1 {
		return org.ErrInvitation
	}
	inv.Status = status
	return nil
}
