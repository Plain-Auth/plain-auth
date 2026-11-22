package organization

import (
	"bytes"
	"context"
	"encoding/json"
	"time"

	auth "github.com/Plain-Auth/plain-auth"
)

// BeforeProfileUpdate contains the supplied fields and the authenticated user and membership.
type BeforeProfileUpdate struct {
	Organization ProfileUpdate
	User         auth.User
	Member       Member
}

// AfterProfileUpdate describes a successfully committed profile change.
type AfterProfileUpdate struct {
	Organization *Organization
	User         auth.User
	Member       Member
}

// ProfileScope binds the two storage operations to the originally authorized
// account, login, membership and tenant. A blank requested ID selects the current tenant.
type ProfileScope struct {
	RequestedID           string
	OrganizationID        string
	OrganizationCreatedAt time.Time
	SessionID             string
	SessionCreatedAt      time.Time
	User                  auth.User
	Member                Member
}

// ObservedProfileStore releases its transaction before returning a prepared
// scope and rechecks that scope in the transaction that writes the profile.
type ObservedProfileStore interface {
	ProfileStore
	PrepareOrganizationProfile(ctx context.Context, actor auth.Session, requestedID string, slug *string) (ProfileScope, error)
	CommitOrganizationProfile(ctx context.Context, actor auth.Session, original ProfileScope, update ProfileUpdate) (*Organization, error)
}

func validateProfileChange(change ProfileUpdate) error {
	if change.Name != nil && *change.Name == "" {
		return validation("name")
	}
	if change.Slug != nil && *change.Slug == "" {
		return validation("slug")
	}
	if change.Logo != nil && change.ClearLogo {
		return validation("logo")
	}
	return nil
}

// Snapshot validates the change and detaches native metadata before a transaction. The same
// JSON representation is used by the HTTP endpoint and the callback snapshot.
func (change ProfileUpdate) Snapshot() (ProfileUpdate, error) {
	if err := validateProfileChange(change); err != nil {
		return ProfileUpdate{}, err
	}
	raw, err := json.Marshal(change)
	if err != nil {
		return ProfileUpdate{}, validation("data")
	}
	var fields map[string]any
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err = decoder.Decode(&fields); err != nil {
		return ProfileUpdate{}, err
	}
	return profileUpdate(fields)
}

func mergeProfileChange(input, result ProfileUpdate) ProfileUpdate {
	if result.Name != nil {
		input.Name = result.Name
	}
	if result.Slug != nil {
		input.Slug = result.Slug
	}
	if result.ClearLogo || result.Logo != nil {
		input.Logo, input.ClearLogo = result.Logo, result.ClearLogo
	}
	if result.Metadata != nil {
		input.Metadata = result.Metadata
	}
	return input
}

func detachedUser(user auth.User) (auth.User, error) {
	// ProfileScope contains the core account and has no opaque credential or session state.
	raw, err := json.Marshal(user)
	if err != nil {
		return auth.User{}, err
	}
	var detached auth.User
	err = json.Unmarshal(raw, &detached)
	return detached, err
}

func (s *Service) observedProfileUpdate(ctx context.Context, session auth.Session, actor *auth.User, requestedID string, change ProfileUpdate) (*Organization, error) {
	store := s.options.Store.(ObservedProfileStore)
	original, err := change.Snapshot()
	if err != nil {
		return nil, err
	}
	scope, err := store.PrepareOrganizationProfile(ctx, session, requestedID, original.Slug)
	if err != nil {
		return nil, err
	}
	publicUser := scope.User
	if actor != nil {
		if actor.ID != scope.User.ID || !actor.CreatedAt.Equal(scope.User.CreatedAt) {
			return nil, ErrUnauthenticated
		}
		publicUser = *actor
	}
	if before := s.options.BeforeUpdateOrganization; before != nil {
		input, err := original.Snapshot()
		if err != nil {
			return nil, err
		}
		user, err := detachedUser(publicUser)
		if err != nil {
			return nil, err
		}
		result, err := before(ctx, BeforeProfileUpdate{Organization: input, User: user, Member: scope.Member})
		if err != nil {
			return nil, err
		}
		if result != nil {
			override, err := result.Snapshot()
			if err != nil {
				return nil, err
			}
			original = mergeProfileChange(original, override)
		}
	}
	updated, err := store.CommitOrganizationProfile(ctx, session, scope, original)
	if err != nil {
		return nil, err
	}
	if after := s.options.AfterUpdateOrganization; after != nil {
		var committed *Organization
		if updated != nil {
			row := *updated
			row.Metadata = bytes.Clone(row.Metadata)
			if row.Logo != nil {
				logo := *row.Logo
				row.Logo = &logo
			}
			committed = &row
		}
		user, err := detachedUser(publicUser)
		if err != nil {
			return nil, err
		}
		if err = after(ctx, AfterProfileUpdate{Organization: committed, User: user, Member: scope.Member}); err != nil {
			return nil, err
		}
	}
	return updated, nil
}
