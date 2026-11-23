package organization

import (
	"bytes"
	"context"
	"errors"
	"net/http"

	authn "github.com/Plain-Auth/plain-auth"
)

// TeamChange describes a team being created, updated or removed, its
// organization and the signed-in user making the change. User is nil for a
// trusted Service.CreateTeam call, and a proposed team has no ID yet.
type TeamChange struct {
	Team         Team
	User         *authn.User
	Organization Organization
}

// TeamOverride replaces fields of a proposed team or a team update.
type TeamOverride struct {
	Name *string
}

// BeforeTeamUpdate describes a team update about to be saved.
type BeforeTeamUpdate struct {
	TeamChange
	Updates TeamOverride
}

// ObservedTeamStore checks a team change without writing so the host's hooks
// see only changes that can proceed. The write checks everything again.
type ObservedTeamStore interface {
	PrepareTeamCreation(ctx context.Context, actor *TeamActor, input CreateTeamRequest, request *http.Request) (TeamChange, error)
	PrepareTeamUpdate(ctx context.Context, actor TeamActor, organizationID, teamID string, name *string) (TeamChange, error)
	PrepareTeamRemoval(ctx context.Context, actor TeamActor, organizationID, teamID string) (TeamChange, error)
}

func (o Options) teamHooksConfigured() bool {
	return o.BeforeCreateTeam != nil || o.AfterCreateTeam != nil || o.BeforeUpdateTeam != nil ||
		o.AfterUpdateTeam != nil || o.BeforeDeleteTeam != nil || o.AfterDeleteTeam != nil
}

func (o Options) validateTeamHooks() error {
	if !o.teamHooksConfigured() {
		return nil
	}
	if o.teamStore == nil {
		return errors.New("organization: team hooks require Teams")
	}
	if _, ok := o.teamStore.(ObservedTeamStore); !ok {
		return errors.New("organization: team hooks require an ObservedTeamStore")
	}
	if _, ok := o.teamStore.(TeamCreationStore); !ok && (o.BeforeCreateTeam != nil || o.AfterCreateTeam != nil) {
		return errors.New("organization: team creation hooks require a TeamCreationStore")
	}
	return nil
}

// detachedTeamChange copies the values handed to host code.
func detachedTeamChange(in TeamChange) (TeamChange, error) {
	if in.User != nil {
		user, err := detachedUser(*in.User)
		if err != nil {
			return TeamChange{}, err
		}
		in.User = &user
	}
	in.Organization.Metadata = bytes.Clone(in.Organization.Metadata)
	return in, nil
}

func (o Options) createTeam(ctx context.Context, actor *TeamActor, input CreateTeamRequest, request *http.Request) (*Team, error) {
	creator := o.teamStore.(TeamCreationStore)
	if o.BeforeCreateTeam == nil && o.AfterCreateTeam == nil {
		return creator.CreateOrganizationTeam(ctx, actor, input, request)
	}
	scope, err := o.teamStore.(ObservedTeamStore).PrepareTeamCreation(ctx, actor, input, request)
	if err != nil {
		return nil, err
	}
	if scope, err = detachedTeamChange(scope); err != nil {
		return nil, err
	}
	input.OrganizationID = scope.Organization.ID
	if before := o.BeforeCreateTeam; before != nil {
		override, err := before(ctx, scope)
		if err != nil {
			return nil, err
		}
		if override != nil && override.Name != nil {
			input.Name = *override.Name
		}
	}
	team, err := creator.CreateOrganizationTeam(ctx, actor, input, request)
	if err != nil {
		return nil, err
	}
	if after := o.AfterCreateTeam; after != nil {
		scope.Team = *team
		if err = after(ctx, scope); err != nil {
			return nil, err
		}
	}
	return team, nil
}

func (o Options) updateTeam(ctx context.Context, actor TeamActor, organizationID, teamID string, name *string) (*Team, error) {
	if o.BeforeUpdateTeam == nil && o.AfterUpdateTeam == nil {
		return o.teamStore.UpdateTeam(ctx, actor, organizationID, teamID, name)
	}
	scope, err := o.teamStore.(ObservedTeamStore).PrepareTeamUpdate(ctx, actor, organizationID, teamID, name)
	if err != nil {
		return nil, err
	}
	if scope, err = detachedTeamChange(scope); err != nil {
		return nil, err
	}
	if before := o.BeforeUpdateTeam; before != nil {
		override, err := before(ctx, BeforeTeamUpdate{TeamChange: scope, Updates: TeamOverride{Name: name}})
		if err != nil {
			return nil, err
		}
		if override != nil && override.Name != nil {
			name = override.Name
		}
	}
	team, err := o.teamStore.UpdateTeam(ctx, actor, scope.Organization.ID, scope.Team.ID, name)
	if err != nil {
		return nil, err
	}
	if after := o.AfterUpdateTeam; after != nil {
		scope.Team = *team
		if err = after(ctx, scope); err != nil {
			return nil, err
		}
	}
	return team, nil
}

func (o Options) removeTeam(ctx context.Context, actor TeamActor, organizationID, teamID string) error {
	if o.BeforeDeleteTeam == nil && o.AfterDeleteTeam == nil {
		return o.teamStore.RemoveTeam(ctx, actor, organizationID, teamID)
	}
	scope, err := o.teamStore.(ObservedTeamStore).PrepareTeamRemoval(ctx, actor, organizationID, teamID)
	if err != nil {
		return err
	}
	if scope, err = detachedTeamChange(scope); err != nil {
		return err
	}
	if before := o.BeforeDeleteTeam; before != nil {
		if err = before(ctx, scope); err != nil {
			return err
		}
	}
	if err = o.teamStore.RemoveTeam(ctx, actor, scope.Organization.ID, scope.Team.ID); err != nil {
		return err
	}
	if after := o.AfterDeleteTeam; after != nil {
		return after(ctx, scope)
	}
	return nil
}
