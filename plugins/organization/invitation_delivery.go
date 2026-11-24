package organization

import (
	"context"
	"errors"
	"net/http"
	"strings"

	auth "github.com/Plain-Org/plain-auth"
)

// InvitationSender is the member who issued or resent this delivery.
type InvitationSender struct {
	Member
	User auth.User `json:"user"`
}

// InvitationDelivery describes one committed invitation for a host mailer.
// Email is the normalized delivery address. Request holds HTTP metadata.
type InvitationDelivery struct {
	// Resent identifies renewal of an existing invitation. A replacement is new.
	Resent       bool             `json:"resent"`
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

func (o Options) issueObservedInvitation(c auth.EndpointContext, session *auth.SessionResult, inv Invitation, how InvitationIssueOptions) (Invitation, error) {
	ctx := c.Request.Context()
	var event *InvitationDelivery
	var err error
	if store, ok := o.Store.(PreparedInvitationStore); ok {
		event, err = store.IssuePreparedInvitation(ctx, inv, session.Session, how, o.creationHook(session.User))
	} else {
		event, err = o.Store.(InvitationDeliveryStore).IssueInvitationForDelivery(ctx, inv, session.Session, how.Resend, how.Replace)
	}
	if err != nil {
		return Invitation{}, err
	}
	if event == nil {
		return Invitation{}, errors.New("organization: invitation store returned no delivery")
	}
	if o.SendInvitationEmail != nil {
		if err := o.deliverInvitationEmail(c, session.User, *event); err != nil {
			return Invitation{}, err
		}
	} else if err := o.sendSimpleInvitation(ctx, event.Invitation); err != nil {
		return Invitation{}, err
	}
	if !event.Resent && o.AfterCreateInvitation != nil {
		created := InvitationDecisionEvent{Actor: event.Inviter.User, Organization: event.Organization, Invitation: event.Invitation}
		if err := decisionHook(o.AfterCreateInvitation, session.User)(ctx, created); err != nil {
			return Invitation{}, err
		}
	}
	return event.Invitation, nil
}

func (o Options) deliverInvitationEmail(c auth.EndpointContext, user auth.User, event InvitationDelivery) error {
	actor, err := invitationActor(user, event.Inviter.User)
	if err != nil {
		return err
	}
	event.Inviter.User = actor
	event.Email = strings.ToLower(event.Invitation.Email)
	message, err := detachedInvitationEvent(event)
	if err != nil {
		return err
	}
	message.Request = c.RequestMetadata()
	// Delivery is logged, not returned, and with BackgroundTasks it runs
	// after the response.
	c.Auth.RunInBackgroundOrAwait(c.Request.Context(), func(ctx context.Context) error {
		if message.Request != nil {
			message.Request = message.Request.WithContext(ctx)
		}
		if err := o.SendInvitationEmail(ctx, message); err != nil {
			c.Auth.Logger().ErrorContext(ctx, "Could not deliver organization invitation email")
		}
		return nil
	})
	return nil
}

func (o Options) sendSimpleInvitation(ctx context.Context, inv Invitation) error {
	if o.SendInvitation == nil {
		return nil
	}
	if inv.TeamID != nil {
		teamID := *inv.TeamID
		inv.TeamID = &teamID
	}
	if err := o.SendInvitation(ctx, inv); err != nil {
		return errInvitationDelivery
	}
	return nil
}
