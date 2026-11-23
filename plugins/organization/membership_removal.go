package organization

import (
	"bytes"
	"context"
	"net/http"
	"strings"

	auth "github.com/Plain-Auth/plain-auth"
)

// MemberUser is the public user returned by email lookup and self-leave.
type MemberUser struct {
	ID    string  `json:"id"`
	Name  string  `json:"name"`
	Email string  `json:"email"`
	Image *string `json:"image"`
}

type RemovedMember struct {
	Member
	User *MemberUser `json:"user,omitempty"`
}

type MemberRemovalStore interface {
	RemoveOrganizationMember(ctx context.Context, userID, sessionToken, organizationID, memberIDOrEmail string) (*RemovedMember, error)
	LeaveOrganization(ctx context.Context, userID, sessionToken, organizationID string) (*RemovedMember, error)
}

// MemberRemoval describes a membership being removed, the account that held
// it and its organization.
type MemberRemoval struct {
	Member       Member
	User         auth.User
	Organization Organization
}

// ObservedMemberRemovalStore checks a removal without writing so the host's
// hooks see only removals that can proceed, then removes that exact member.
type ObservedMemberRemovalStore interface {
	PrepareMemberRemoval(ctx context.Context, userID, sessionToken, organizationID, memberIDOrEmail string) (MemberRemoval, error)
	CommitMemberRemoval(ctx context.Context, userID, sessionToken, organizationID, memberID string) (*RemovedMember, error)
}

var (
	ErrMemberMissing = problem(400, "MEMBER_NOT_FOUND", "Member not found")
	ErrLastOwner     = problem(400, "YOU_CANNOT_LEAVE_THE_ORGANIZATION_AS_THE_ONLY_OWNER", "You cannot leave the organization as the only owner")
	ErrMemberRemove  = problem(401, "YOU_ARE_NOT_ALLOWED_TO_DELETE_THIS_MEMBER", "You are not allowed to delete this member")
)

func (o Options) memberRemovalEndpoints(store MemberRemovalStore) []auth.Endpoint {
	return []auth.Endpoint{
		o.endpoint(http.MethodPost, "remove-member", func(c auth.EndpointContext, s *auth.SessionResult) (any, error) {
			target, ok := c.Body["memberIdOrEmail"].(string)
			if !ok {
				return nil, validation("memberIdOrEmail")
			}
			group, ok := c.Body["organizationId"].(string)
			if _, provided := c.Body["organizationId"]; provided && !ok {
				return nil, validation("organizationId")
			}
			if o.BeforeRemoveMember == nil && o.AfterRemoveMember == nil {
				m, err := store.RemoveOrganizationMember(c.Request.Context(), s.User.ID, s.Session.Token, group, target)
				if err != nil {
					return nil, err
				}
				return map[string]any{"member": m}, nil
			}
			return o.observedMemberRemoval(c.Request.Context(), store.(ObservedMemberRemovalStore), s, group, target)
		}),
		o.endpoint(http.MethodPost, "leave", func(c auth.EndpointContext, s *auth.SessionResult) (any, error) {
			group, ok := c.Body["organizationId"].(string)
			if !ok {
				return nil, validation("organizationId")
			}
			return store.LeaveOrganization(c.Request.Context(), s.User.ID, s.Session.Token, group)
		}),
	}
}

func (o Options) observedMemberRemoval(ctx context.Context, store ObservedMemberRemovalStore, s *auth.SessionResult, group, target string) (any, error) {
	prepared, err := store.PrepareMemberRemoval(ctx, s.User.ID, s.Session.Token, group, target)
	if err != nil {
		return nil, err
	}
	event := func() (MemberRemoval, error) {
		user, err := detachedUser(prepared.User)
		in := prepared
		in.User = user
		in.Organization.Metadata = bytes.Clone(prepared.Organization.Metadata)
		return in, err
	}
	if before := o.BeforeRemoveMember; before != nil {
		in, err := event()
		if err != nil {
			return nil, err
		}
		if err = before(ctx, in); err != nil {
			return nil, err
		}
	}
	removed, err := store.CommitMemberRemoval(ctx, s.User.ID, s.Session.Token, prepared.Organization.ID, prepared.Member.ID)
	if err != nil {
		return nil, err
	}
	if strings.Contains(target, "@") {
		u := prepared.User
		removed.User = &MemberUser{ID: u.ID, Name: u.Name, Email: u.Email, Image: u.Image}
	}
	if after := o.AfterRemoveMember; after != nil {
		in, err := event()
		if err != nil {
			return nil, err
		}
		if err = after(ctx, in); err != nil {
			return nil, err
		}
	}
	return map[string]any{"member": removed}, nil
}
