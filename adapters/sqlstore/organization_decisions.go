package sqlstore

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"

	auth "github.com/Plain-Org/plain-auth"
	org "github.com/Plain-Org/plain-auth/plugins/organization"
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

// Acceptance also reserves a membership seat. The same admission decision is
// retained across preparation and commit so the host resolver runs once.
const acceptInvitation org.InvitationDecision = "accepted"

type invitationDecisionRequest struct {
	actor           auth.Session
	id              string
	decision        org.InvitationDecision
	requireVerified bool
	admission       *memberAdmission
	seats           *teamSeats
}

type invitationDecisionPhase int

const (
	directDecision invitationDecisionPhase = iota
	prepareObservedDecision
	commitObservedDecision
)

func (s *Store) unobservedInvitationDecision(ctx context.Context, actor auth.Session, id string, decision org.InvitationDecision, requireVerified bool) (*org.Invitation, error) {
	request := invitationDecisionRequest{actor: actor, id: id, decision: decision, requireVerified: requireVerified}
	scope, err := s.invitationDecisionTx(ctx, request, directDecision, nil)
	if err != nil {
		return nil, err
	}
	return &scope.Invitation, nil
}

func (s *Store) ObserveInvitationDecision(ctx context.Context, actor auth.Session, id string, decision org.InvitationDecision, requireVerified bool, before org.InvitationDecisionHook) (*org.InvitationDecisionEvent, error) {
	request := invitationDecisionRequest{actor: actor, id: id, decision: decision, requireVerified: requireVerified}
	return s.observeDecision(ctx, request, before)
}

func (s *Store) ObserveInvitationAcceptance(ctx context.Context, actor auth.Session, id string, requireVerified bool, before org.InvitationDecisionHook) (*org.InvitationDecisionEvent, error) {
	var event *org.InvitationDecisionEvent
	seats := teamSeats{sessionID: actor.ID, userID: actor.UserID}
	err := s.withMemberAdmission(ctx, func(admission *memberAdmission) error {
		return s.withTeamSeats(ctx, &seats, func() error {
			request := invitationDecisionRequest{actor: actor, id: id, decision: acceptInvitation, requireVerified: requireVerified, admission: admission, seats: &seats}
			var err error
			event, err = s.observeDecision(ctx, request, before)
			return err
		})
	})
	return event, err
}

func (s *Store) observeDecision(ctx context.Context, request invitationDecisionRequest, before org.InvitationDecisionHook) (*org.InvitationDecisionEvent, error) {
	var expected []byte
	if before != nil {
		scope, err := s.invitationDecisionTx(ctx, request, prepareObservedDecision, nil)
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
	scope, err := s.invitationDecisionTx(ctx, request, commitObservedDecision, expected)
	if err != nil {
		return nil, err
	}
	return &scope.InvitationDecisionEvent, nil
}

func (s *Store) invitationDecisionTx(ctx context.Context, request invitationDecisionRequest, phase invitationDecisionPhase, expected []byte) (*invitationDecisionScope, error) {
	actor := request.actor
	if err := actor.RequireOwner(); err != nil {
		return nil, err
	}
	tx, err := s.beginMembershipChange(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	account, err := s.lockInvitationSession(ctx, tx, actor)
	if err != nil {
		return nil, err
	}
	inv, err := s.lockInvitation(ctx, tx, request.id)
	if err != nil {
		return nil, err
	}
	scope := &invitationDecisionScope{InvitationDecisionEvent: org.InvitationDecisionEvent{Invitation: inv, Actor: account.user}, SessionID: account.id, SessionCreatedAt: account.createdAt}
	now := time.Now().UTC().Truncate(time.Millisecond)
	switch request.decision {
	case acceptInvitation:
		if request.admission == nil {
			return nil, errors.New("acceptance requires a membership admission decision")
		}
		if err := s.checkInvitationAcceptance(ctx, tx, inv, account.user, now, request.requireVerified, request.admission); err != nil {
			return nil, err
		}
		// Settle every team cap before the host's hook sees the acceptance.
		if phase == prepareObservedDecision {
			if err := s.checkInvitationTeams(ctx, tx, inv, request.seats); err != nil {
				return nil, err
			}
		}
	case org.RejectInvitation:
		if inv.Status != "pending" {
			return nil, org.ErrInvitation
		}
		if strings.ToLower(inv.Email) != strings.ToLower(account.user.Email) {
			return nil, org.ErrRecipient
		}
		if request.requireVerified && !account.user.EmailVerified {
			return nil, org.ErrUnverified
		}
	case org.CancelInvitation:
		m, err := s.memberForChange(ctx, tx, inv.OrganizationID, `m."userId"=`+s.exactSQLValue("?"), actor.UserID)
		if err != nil {
			return nil, err
		}
		if err := s.requireOrganizationAction(ctx, tx, inv.OrganizationID, m.Role, "invitation", "cancel", org.ErrCancelDenied); err != nil {
			return nil, err
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
		if request.decision == acceptInvitation {
			member, err := s.grantInvitedMembership(ctx, tx, &scope.Invitation, account.id, account.user.ID, now, request.seats)
			if err != nil {
				return nil, err
			}
			scope.Member = &member
		} else if err := s.updateInvitationStatus(ctx, tx, &scope.Invitation, string(request.decision)); err != nil {
			return nil, err
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return scope, nil
}

func (s *Store) lockInvitationSession(ctx context.Context, tx *sql.Tx, actor auth.Session) (orgSessionAccount, error) {
	err := s.lockActiveAccount(ctx, tx, actor.UserID, actor.Token, time.Now())
	if errors.Is(err, auth.ErrNotFound) {
		return orgSessionAccount{}, org.ErrUnauthenticated
	}
	if err != nil {
		return orgSessionAccount{}, err
	}
	account, err := s.organizationSessionAccount(ctx, tx, actor)
	if err == nil && !actor.CreatedAt.IsZero() && !account.createdAt.Equal(actor.CreatedAt) {
		return orgSessionAccount{}, org.ErrUnauthenticated
	}
	return account, err
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
