package organization

import (
	"bytes"
	"context"
	"errors"
	"net/http"

	authn "github.com/Plain-Org/plain-auth"
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

// TeamMembershipChange describes a user joining or leaving a team. Member is
// the proposed or existing team membership and User the account it belongs to.
type TeamMembershipChange struct {
	Member       TeamMember
	Team         Team
	User         authn.User
	Organization Organization
}

// ObservedTeamStore checks a team change without writing so the host's hooks
// see only changes that can proceed. The write checks everything again.
type ObservedTeamStore interface {
	PrepareTeamCreation(ctx context.Context, actor *TeamActor, input CreateTeamRequest, request *http.Request) (TeamChange, error)
	PrepareTeamUpdate(ctx context.Context, actor TeamActor, organizationID, teamID string, name *string) (TeamChange, error)
	PrepareTeamRemoval(ctx context.Context, actor TeamActor, organizationID, teamID string) (TeamChange, error)
	// PrepareTeamMemberAddition returns the existing membership in Member
	// when the user already belongs to the team.
	PrepareTeamMemberAddition(ctx context.Context, actor TeamActor, organizationID, teamID, userID string) (TeamMembershipChange, error)
	PrepareTeamMemberRemoval(ctx context.Context, actor TeamActor, organizationID, teamID, userID string) (TeamMembershipChange, error)
}

func (o Options) teamHooksConfigured() bool {
	return o.BeforeCreateTeam != nil || o.AfterCreateTeam != nil || o.BeforeUpdateTeam != nil ||
		o.AfterUpdateTeam != nil || o.BeforeDeleteTeam != nil || o.AfterDeleteTeam != nil ||
		o.teamMemberHooksConfigured()
}

func (o Options) teamMemberHooksConfigured() bool {
	return o.BeforeAddTeamMember != nil || o.AfterAddTeamMember != nil || o.BeforeRemoveTeamMember != nil || o.AfterRemoveTeamMember != nil
}

// DefaultTeamStore creates an organization and its default team in one
// transaction, naming the team after team.Name and filling in the saved team.
type DefaultTeamStore interface {
	CreateOrganizationWithTeam(ctx context.Context, group Organization, owner Member, sessionID string, keep bool, team *Team) error
}

// defaultTeamHooks reports whether organization creation runs the team
// creation hooks for the default team.
func (o Options) defaultTeamHooks() bool {
	return o.Teams != nil && !o.Teams.DisableDefaultTeam && (o.BeforeCreateTeam != nil || o.AfterCreateTeam != nil)
}

func (o Options) validateTeamHooks() error {
	if !o.teamHooksConfigured() {
		return nil
	}
	if _, ok := o.Store.(DefaultTeamStore); !ok && o.defaultTeamHooks() {
		return errors.New("organization: team creation hooks with a default team require a DefaultTeamStore")
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

func detachedMembershipChange(in TeamMembershipChange) (TeamMembershipChange, error) {
	user, err := detachedUser(in.User)
	if err != nil {
		return TeamMembershipChange{}, err
	}
	in.User = user
	in.Organization.Metadata = bytes.Clone(in.Organization.Metadata)
	return in, nil
}

func (o Options) addTeamMember(ctx context.Context, actor TeamActor, organizationID, teamID, userID string) (*TeamMember, error) {
	if o.BeforeAddTeamMember == nil && o.AfterAddTeamMember == nil {
		return o.teamStore.AddTeamMember(ctx, actor, organizationID, teamID, userID)
	}
	change, err := o.teamStore.(ObservedTeamStore).PrepareTeamMemberAddition(ctx, actor, organizationID, teamID, userID)
	if err != nil {
		return nil, err
	}
	// Repeating an add returns the existing membership without the hooks.
	if change.Member.ID != "" {
		return o.teamStore.AddTeamMember(ctx, actor, change.Organization.ID, teamID, userID)
	}
	if change, err = detachedMembershipChange(change); err != nil {
		return nil, err
	}
	if before := o.BeforeAddTeamMember; before != nil {
		if err = before(ctx, change); err != nil {
			return nil, err
		}
	}
	member, err := o.teamStore.AddTeamMember(ctx, actor, change.Organization.ID, teamID, userID)
	if err != nil {
		return nil, err
	}
	if after := o.AfterAddTeamMember; after != nil {
		change.Member = *member
		if err = after(ctx, change); err != nil {
			return nil, err
		}
	}
	return member, nil
}

func (o Options) removeTeamMember(ctx context.Context, actor TeamActor, organizationID, teamID, userID string) error {
	if o.BeforeRemoveTeamMember == nil && o.AfterRemoveTeamMember == nil {
		return o.teamStore.RemoveTeamMember(ctx, actor, organizationID, teamID, userID)
	}
	change, err := o.teamStore.(ObservedTeamStore).PrepareTeamMemberRemoval(ctx, actor, organizationID, teamID, userID)
	if err != nil {
		return err
	}
	if change, err = detachedMembershipChange(change); err != nil {
		return err
	}
	if before := o.BeforeRemoveTeamMember; before != nil {
		if err = before(ctx, change); err != nil {
			return err
		}
	}
	if err = o.teamStore.RemoveTeamMember(ctx, actor, change.Organization.ID, teamID, userID); err != nil {
		return err
	}
	if after := o.AfterRemoveTeamMember; after != nil {
		return after(ctx, change)
	}
	return nil
}

// RemoveTeamRequest names a team to remove from trusted server code.
type RemoveTeamRequest struct {
	OrganizationID string
	TeamID         string
}

// TrustedTeamRemovalStore removes a team without a session. The application
// authorizes the call.
type TrustedTeamRemovalStore interface {
	RemoveOrganizationTeam(ctx context.Context, organizationID, teamID string) error
	PrepareOrganizationTeamRemoval(ctx context.Context, organizationID, teamID string) (TeamChange, error)
}

// RemoveTeam removes a team from trusted server code. It skips the membership,
// permission and active-team checks of the HTTP route but keeps the final-team
// rule, and runs the team removal hooks with a nil User.
func (s *Service) RemoveTeam(ctx context.Context, request RemoveTeamRequest) error {
	o := s.options
	store, ok := o.teamStore.(TrustedTeamRemovalStore)
	if !ok {
		return errors.New("organization: trusted team removal requires a TrustedTeamRemovalStore")
	}
	if request.TeamID == "" {
		return validation("teamId")
	}
	if o.BeforeDeleteTeam == nil && o.AfterDeleteTeam == nil {
		return store.RemoveOrganizationTeam(ctx, request.OrganizationID, request.TeamID)
	}
	scope, err := store.PrepareOrganizationTeamRemoval(ctx, request.OrganizationID, request.TeamID)
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
	if err = store.RemoveOrganizationTeam(ctx, scope.Organization.ID, scope.Team.ID); err != nil {
		return err
	}
	if after := o.AfterDeleteTeam; after != nil {
		return after(ctx, scope)
	}
	return nil
}
