package organization

import (
	"context"
	"errors"
	"net/http"
	"strings"

	auth "github.com/Plain-Auth/plain-auth"
)

// InvitationSender is the member who issued or resent this delivery.
type InvitationSender struct {
	Member
	User auth.User `json:"user"`
}

// InvitationDelivery describes one committed invitation for a host mailer.
// Email is the normalized delivery address. Request holds HTTP metadata.
type InvitationDelivery struct {
	Email        string           `json:"email"`
	Invitation   Invitation       `json:"invitation"`
	Organization Organization     `json:"organization"`
	Inviter      InvitationSender `json:"inviter"`
	Request      *http.Request    `json:"-"`
}

// InvitationDeliveryStore returns the sender, destination and invitation as
// they were in the transaction that issued the grant or renewed its deadline.
type InvitationDeliveryStore interface {
	IssueInvitationForDelivery(ctx context.Context, invitation Invitation, actor auth.Session, resend, replace bool) (*InvitationDelivery, error)
}

var errInvitationDelivery = errors.New("organization: invitation delivery failed")

func (o Options) deliverInvitation(c auth.EndpointContext, session *auth.SessionResult, inv Invitation, resend bool) (Invitation, error) {
	ctx := c.Request.Context()
	store := o.Store.(InvitationDeliveryStore)
	event, err := store.IssueInvitationForDelivery(ctx, inv, session.Session, resend, o.CancelPendingInvitationsOnReInvite && !resend)
	if err != nil {
		return Invitation{}, err
	}
	if event == nil {
		return Invitation{}, errors.New("organization: invitation store returned no delivery")
	}
	actor, err := invitationActor(session.User, event.Inviter.User)
	if err != nil {
		return Invitation{}, err
	}
	event.Inviter.User = actor
	event.Email = strings.ToLower(event.Invitation.Email)
	message, err := detachedInvitationEvent(*event)
	if err != nil {
		return Invitation{}, err
	}
	message.Request = c.RequestMetadata()
	if err := o.SendInvitationEmail(ctx, message); err != nil {
		c.Auth.Logger().ErrorContext(ctx, "Could not deliver organization invitation email")
	}
	return event.Invitation, nil
}
