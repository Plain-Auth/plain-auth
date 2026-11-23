package organization

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"time"

	authn "github.com/Plain-Auth/plain-auth"
)

// CreateOrganizationRequest creates an organization from trusted server code.
// The application authorizes the call. UserID names the creator, who becomes
// the first member with the creator role. No session selects the result.
type CreateOrganizationRequest struct {
	UserID   string
	Name     string
	Slug     string
	Logo     *string
	Metadata map[string]any
}

// CreatedOrganization is a new organization with its creator's membership.
type CreatedOrganization struct {
	Organization
	Members []Member `json:"members"`
}

// BeforeOrganizationCreation describes a proposed organization and its creator.
type BeforeOrganizationCreation struct {
	Organization Organization
	User         authn.User
}

// AfterOrganizationCreation describes a committed organization.
type AfterOrganizationCreation struct {
	Organization Organization
	User         authn.User
	Member       Member
}

// OrganizationCreatorStore reads the account named by a trusted creation.
type OrganizationCreatorStore interface {
	OrganizationCreator(ctx context.Context, userID string) (authn.User, error)
}

// CreateOrganization creates an organization owned by request.UserID. It
// applies the organization limits and creation hooks but not
// AllowUserToCreateOrganization, which governs signed-in users.
func (s *Service) CreateOrganization(ctx context.Context, request CreateOrganizationRequest) (*CreatedOrganization, error) {
	o := s.options
	if request.UserID == "" {
		return nil, validation("userId")
	}
	if request.Name == "" {
		return nil, validation("name")
	}
	if request.Slug == "" {
		return nil, validation("slug")
	}
	group, err := newOrganization(request.Name, request.Slug, request.Logo, request.Metadata)
	if err != nil {
		return nil, err
	}
	user := authn.User{ID: request.UserID}
	if lookup, ok := o.Store.(OrganizationCreatorStore); ok {
		if user, err = lookup.OrganizationCreator(ctx, request.UserID); err != nil {
			return nil, err
		}
	} else if o.BeforeCreateOrganization != nil || o.AfterCreateOrganization != nil || o.OrganizationLimitReached != nil {
		return nil, errors.New("organization: trusted creation with callbacks requires an OrganizationCreatorStore")
	}
	if err = o.checkOrganizationLimit(ctx, user); err != nil {
		return nil, err
	}
	return o.createOrganization(ctx, user, group, "", true)
}

func newOrganization(name, slug string, logo *string, metadata map[string]any) (Organization, error) {
	group := Organization{ID: rand.Text(), Name: name, Slug: slug, Logo: logo, CreatedAt: time.Now().UTC().Truncate(time.Millisecond)}
	if metadata != nil {
		raw, err := json.Marshal(metadata)
		if err != nil {
			return Organization{}, validation("metadata")
		}
		group.Metadata = raw
	}
	return group, nil
}

// createOrganization runs the creation hooks around one store write. An
// empty sessionID marks a trusted creation that selects nothing.
func (o Options) createOrganization(ctx context.Context, user authn.User, group Organization, sessionID string, keep bool) (*CreatedOrganization, error) {
	if before := o.BeforeCreateOrganization; before != nil {
		proposed := group
		proposed.Metadata = bytes.Clone(group.Metadata)
		creator, err := detachedUser(user)
		if err != nil {
			return nil, err
		}
		override, err := before(ctx, BeforeOrganizationCreation{Organization: proposed, User: creator})
		if err != nil {
			return nil, err
		}
		if override != nil {
			if group, err = applyCreationOverride(group, *override); err != nil {
				return nil, err
			}
		}
	}
	member := Member{ID: rand.Text(), OrganizationID: group.ID, UserID: user.ID, Role: o.rolePolicy.CreatorRole(), CreatedAt: group.CreatedAt}
	if err := o.Store.CreateOrganization(ctx, group, member, sessionID, keep); err != nil {
		return nil, err
	}
	if after := o.AfterCreateOrganization; after != nil {
		committed := group
		committed.Metadata = bytes.Clone(group.Metadata)
		creator, err := detachedUser(user)
		if err != nil {
			return nil, err
		}
		if err = after(ctx, AfterOrganizationCreation{Organization: committed, User: creator, Member: member}); err != nil {
			return nil, err
		}
	}
	return &CreatedOrganization{Organization: group, Members: []Member{member}}, nil
}

func applyCreationOverride(group Organization, override ProfileUpdate) (Organization, error) {
	change, err := override.Snapshot()
	if err != nil {
		return group, err
	}
	if change.Name != nil {
		group.Name = *change.Name
	}
	if change.Slug != nil {
		group.Slug = *change.Slug
	}
	if change.ClearLogo {
		group.Logo = nil
	} else if change.Logo != nil {
		logo := *change.Logo
		group.Logo = &logo
	}
	if change.Metadata != nil {
		if group.Metadata, err = json.Marshal(change.Metadata); err != nil {
			return group, validation("metadata")
		}
	}
	return group, nil
}
