package organization

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	auth "github.com/Plain-Auth/plain-auth"
)

// ProfileUpdate contains the organization fields to replace. Set ClearLogo to
// remove the logo, and supply an empty metadata object to clear its contents.
type ProfileUpdate struct {
	Name, Slug, Logo *string
	ClearLogo        bool
	Metadata         map[string]any
}

// MarshalJSON preserves the difference between omitting logo and clearing it.
func (p ProfileUpdate) MarshalJSON() ([]byte, error) {
	values := make(map[string]any)
	if p.Name != nil {
		values["name"] = *p.Name
	}
	if p.Slug != nil {
		values["slug"] = *p.Slug
	}
	if p.Logo != nil && p.ClearLogo {
		return nil, validation("logo")
	}
	if p.ClearLogo {
		values["logo"] = nil
	} else if p.Logo != nil {
		values["logo"] = *p.Logo
	}
	if p.Metadata != nil {
		values["metadata"] = p.Metadata
	}
	return json.Marshal(values)
}

func profileUpdate(body map[string]any) (ProfileUpdate, error) {
	var p ProfileUpdate
	for _, f := range []struct {
		key string
		dst **string
	}{{"name", &p.Name}, {"slug", &p.Slug}, {"logo", &p.Logo}} {
		v, present := body[f.key]
		if !present {
			continue
		}
		if f.key == "logo" && v == nil {
			p.ClearLogo = true
			continue
		}
		s, ok := v.(string)
		if !ok || (f.key != "logo" && s == "") {
			return p, validation(f.key)
		}
		*f.dst = &s
	}
	if m, present := body["metadata"]; present {
		obj, ok := m.(map[string]any)
		if !ok {
			return p, validation("metadata")
		}
		p.Metadata = obj
	}
	return p, nil
}

// ProfileStore updates the organization only under a current owner or admin membership.
type ProfileStore interface {
	UpdateOrganizationProfile(ctx context.Context, userID, token, organizationID string, update ProfileUpdate) (*Organization, error)
	OrganizationSlugAvailable(ctx context.Context, slug string) (bool, error)
}

var ErrSlugTaken = problem(400, "ORGANIZATION_SLUG_ALREADY_TAKEN", "Organization slug already taken")
var ErrUpdateDenied = problem(403, "YOU_ARE_NOT_ALLOWED_TO_UPDATE_THIS_ORGANIZATION", "You are not allowed to update this organization")
var ErrUpdateNotMember = problem(400, "USER_IS_NOT_A_MEMBER_OF_THE_ORGANIZATION", "User is not a member of the organization")

func (s *Service) UpdateOrganization(ctx context.Context, session auth.Session, id string, change ProfileUpdate) (*Organization, error) {
	return s.updateOrganization(ctx, session, nil, id, change)
}

func (s *Service) updateOrganization(ctx context.Context, session auth.Session, actor *auth.User, id string, change ProfileUpdate) (*Organization, error) {
	store, ok := s.options.Store.(ProfileStore)
	if !ok {
		return nil, errors.New("organization: store does not support profile updates")
	}
	if session.IsApplicationCredential() || session.UserID == "" || session.Token == "" {
		return nil, ErrUnauthenticated
	}
	if err := session.RequireOwner(); err != nil {
		return nil, err
	}
	if err := validateProfileChange(change); err != nil {
		return nil, err
	}
	if s.options.BeforeUpdateOrganization != nil || s.options.AfterUpdateOrganization != nil {
		return s.observedProfileUpdate(ctx, session, actor, id, change)
	}
	return store.UpdateOrganizationProfile(ctx, session.UserID, session.Token, id, change)
}

func (s *Service) profileEndpoints(store ProfileStore) []auth.Endpoint {
	o := s.options
	return []auth.Endpoint{
		o.endpoint(http.MethodPost, "update", func(c auth.EndpointContext, actor *auth.SessionResult) (any, error) {
			data, ok := c.Body["data"].(map[string]any)
			if !ok {
				return nil, validation("data")
			}
			id, ok := c.Body["organizationId"].(string)
			if _, present := c.Body["organizationId"]; present && !ok {
				return nil, validation("organizationId")
			}
			changes, err := profileUpdate(data)
			if err != nil {
				return nil, err
			}
			return s.updateOrganization(c.Request.Context(), actor.Session, &actor.User, id, changes)
		}),
		o.endpoint(http.MethodPost, "check-slug", func(c auth.EndpointContext, _ *auth.SessionResult) (any, error) {
			slug, ok := c.Body["slug"].(string)
			if !ok {
				return nil, validation("slug")
			}
			available, err := store.OrganizationSlugAvailable(c.Request.Context(), slug)
			if err != nil {
				return nil, err
			}
			if !available {
				return nil, ErrSlugTaken
			}
			return map[string]bool{"status": true}, nil
		}),
	}
}
