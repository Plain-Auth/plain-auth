package organization

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	authn "github.com/FineStack/frost-auth"
)

// TeamOptions enables team management for an organization store with the teams schema.
type TeamOptions struct {
	MaximumTeams          int
	MaximumMembersPerTeam *int
	DisableDefaultTeam    bool
	AllowRemovingAllTeams bool
}

type Team struct {
	ID             string     `json:"id"`
	Name           string     `json:"name"`
	OrganizationID string     `json:"organizationId"`
	CreatedAt      time.Time  `json:"createdAt"`
	UpdatedAt      *time.Time `json:"updatedAt"`
}

type TeamMember struct {
	ID        string     `json:"id"`
	TeamID    string     `json:"teamId"`
	UserID    string     `json:"userId"`
	CreatedAt *time.Time `json:"createdAt"`
}

type TeamActor struct{ UserID, SessionID string }

// TeamStore applies the team's permissions and organization scope within each storage operation.
type TeamStore interface {
	Store
	ActiveTeam(ctx context.Context, actor TeamActor) (*string, error)
	CreateTeam(ctx context.Context, actor TeamActor, orgID, name string) (*Team, error)
	UpdateTeam(ctx context.Context, actor TeamActor, orgID, teamID string, name *string) (*Team, error)
	RemoveTeam(ctx context.Context, actor TeamActor, orgID, teamID string) error
	ListTeams(ctx context.Context, actor TeamActor, orgID string) ([]Team, error)
	SetActiveTeam(ctx context.Context, actor TeamActor, teamID *string) (*Team, error)
	ListUserTeams(ctx context.Context, actor TeamActor, organizationID, userID string) ([]Team, error)
	ListTeamMembers(ctx context.Context, actor TeamActor, teamID string) ([]TeamMember, error)
	AddTeamMember(ctx context.Context, actor TeamActor, orgID, teamID, userID string) (*TeamMember, error)
	RemoveTeamMember(ctx context.Context, actor TeamActor, orgID, teamID, userID string) error
}

type TeamStoreProvider interface {
	WithOrganizationTeams(TeamOptions) (TeamStore, error)
}

var (
	ErrNoActiveOrg      = problem(400, "NO_ACTIVE_ORGANIZATION", "No active organization")
	ErrNoActiveTeam     = problem(400, "YOU_DO_NOT_HAVE_AN_ACTIVE_TEAM", "You do not have an active team")
	ErrTeamNotFound     = problem(400, "TEAM_NOT_FOUND", "Team not found")
	ErrTeamMember       = problem(400, "USER_IS_NOT_A_MEMBER_OF_THE_TEAM", "User is not a member of the team")
	ErrTeamSelect       = problem(403, "USER_IS_NOT_A_MEMBER_OF_THE_TEAM", "User is not a member of the team")
	ErrTeamOrgMember    = problem(400, "USER_IS_NOT_A_MEMBER_OF_THE_ORGANIZATION", "User is not a member of the organization")
	ErrTeamCreate       = problem(403, "YOU_ARE_NOT_ALLOWED_TO_CREATE_TEAMS_IN_THIS_ORGANIZATION", "You are not allowed to create teams in this organization")
	ErrTeamUpdate       = problem(403, "YOU_ARE_NOT_ALLOWED_TO_UPDATE_THIS_TEAM", "You are not allowed to update this team")
	ErrTeamDelete       = problem(403, "YOU_ARE_NOT_ALLOWED_TO_DELETE_TEAMS_IN_THIS_ORGANIZATION", "You are not allowed to delete teams in this organization")
	ErrTeamDeleteActive = problem(403, "YOU_ARE_NOT_ALLOWED_TO_DELETE_THIS_TEAM", "You are not allowed to delete this team")
	ErrTeamLast         = problem(400, "UNABLE_TO_REMOVE_LAST_TEAM", "Unable to remove last team")
	ErrTeamLimit        = problem(400, "YOU_HAVE_REACHED_THE_MAXIMUM_NUMBER_OF_TEAMS", "You have reached the maximum number of teams")
	ErrTeamMemberLimit  = problem(403, "TEAM_MEMBER_LIMIT_REACHED", "Team member limit reached")
	ErrTeamAdd          = problem(403, "YOU_ARE_NOT_ALLOWED_TO_CREATE_A_NEW_TEAM_MEMBER", "You are not allowed to create a new member")
	ErrTeamRemove       = problem(403, "YOU_ARE_NOT_ALLOWED_TO_REMOVE_A_TEAM_MEMBER", "You are not allowed to remove a team member")
	ErrTeamList         = problem(403, "YOU_ARE_NOT_ALLOWED_TO_ACCESS_THIS_ORGANIZATION", "You are not allowed to access this organization as an owner")
	ErrTeamListUser     = problem(403, "YOU_ARE_NOT_ALLOWED_TO_UPDATE_THIS_MEMBER", "You are not allowed to update this member")
	ErrTeamListOrg      = problem(403, "YOU_ARE_NOT_A_MEMBER_OF_THIS_ORGANIZATION", "You are not a member of this organization")
)

func (o *Options) configureTeams() error {
	if o.Teams == nil {
		return nil
	}
	opts := *o.Teams
	if opts.MaximumTeams < 0 || (opts.MaximumMembersPerTeam != nil && *opts.MaximumMembersPerTeam < 0) {
		return errors.New("organization: team limits cannot be negative")
	}
	if opts.MaximumMembersPerTeam != nil {
		limit := *opts.MaximumMembersPerTeam
		opts.MaximumMembersPerTeam = &limit
	}
	provider, ok := o.Store.(TeamStoreProvider)
	if !ok {
		return errors.New("organization: teams require a TeamStoreProvider")
	}
	store, err := provider.WithOrganizationTeams(opts)
	if err != nil {
		return err
	}
	o.teamStore = store
	o.Store = store
	return nil
}

func teamOrg(body map[string]any) (string, error) {
	if _, exists := body["organizationId"]; exists {
		return textField(body, "organizationId")
	}
	return "", nil
}

func teamInvitationIDs(value any) (*string, error) {
	if value == nil {
		return nil, nil
	}
	var values []any
	switch v := value.(type) {
	case string:
		values = []any{v}
	case []any:
		values = v
	default:
		return nil, validation("teamId")
	}
	ids := []string{}
	seen := map[string]bool{}
	for _, value := range values {
		id, ok := value.(string)
		if !ok || id == "" {
			return nil, validation("teamId")
		}
		if strings.Contains(id, ",") {
			return nil, problem(400, "INVALID_TEAM_ID", "Team id contains a reserved character")
		}
		if !seen[id] {
			ids = append(ids, id)
			seen[id] = true
		}
	}
	if len(ids) == 0 {
		return nil, nil
	}
	joined := strings.Join(ids, ",")
	return &joined, nil
}

func (o Options) teamEndpoints() []authn.Endpoint {
	type route struct{ method, path string }
	routes := []route{{"POST", "create-team"}, {"POST", "update-team"}, {"POST", "remove-team"}, {"GET", "list-teams"}, {"POST", "set-active-team"}, {"GET", "list-user-teams"}, {"GET", "list-team-members"}, {"POST", "add-team-member"}, {"POST", "remove-team-member"}}
	endpoints := make([]authn.Endpoint, 0, len(routes))
	for _, route := range routes {
		endpoints = append(endpoints, o.endpoint(route.method, route.path, func(c authn.EndpointContext, s *authn.SessionResult) (any, error) {
			return o.teamRequest(c, TeamActor{UserID: s.User.ID, SessionID: s.Session.ID}, s.Session, route.path)
		}))
	}
	return endpoints
}

func (o Options) teamRequest(c authn.EndpointContext, actor TeamActor, session authn.Session, action string) (any, error) {
	ctx := c.Request.Context()
	store := o.teamStore
	if c.Request.Method == http.MethodGet {
		q := c.Request.URL.Query()
		switch action {
		case "list-teams":
			return store.ListTeams(ctx, actor, q.Get("organizationId"))
		case "list-user-teams":
			return store.ListUserTeams(ctx, actor, q.Get("organizationId"), q.Get("userId"))
		default:
			return store.ListTeamMembers(ctx, actor, q.Get("teamId"))
		}
	}
	body := c.Body
	if action == "set-active-team" {
		value, exists := body["teamId"]
		id := session.ActiveTeamID
		if exists {
			id = nil
			if value != nil {
				requested, err := textField(body, "teamId")
				if err != nil {
					return nil, err
				}
				id = &requested
			}
		}
		if id == nil && session.ActiveTeamID == nil {
			return nil, nil
		}
		selected, err := store.SetActiveTeam(ctx, actor, id)
		if err == nil {
			c.ReissueSessionCookie(session)
		}
		return selected, err
	}
	data := body
	if action == "update-team" {
		var ok bool
		data, ok = body["data"].(map[string]any)
		if !ok {
			return nil, validation("data")
		}
	}
	orgID, err := teamOrg(data)
	if err != nil {
		return nil, err
	}
	if action == "create-team" {
		name, err := textField(data, "name")
		if err != nil {
			return nil, err
		}
		return store.CreateTeam(ctx, actor, orgID, name)
	}
	id, err := textField(body, "teamId")
	if err != nil {
		return nil, err
	}
	switch action {
	case "update-team":
		var name *string
		if _, ok := data["name"]; ok {
			value, err := textField(data, "name")
			if err != nil {
				return nil, err
			}
			name = &value
		}
		return store.UpdateTeam(ctx, actor, orgID, id, name)
	case "remove-team":
		return map[string]string{"message": "Team removed successfully."}, store.RemoveTeam(ctx, actor, orgID, id)
	default:
		user, err := textField(body, "userId")
		if err != nil {
			return nil, err
		}
		if action == "add-team-member" {
			return store.AddTeamMember(ctx, actor, orgID, id, user)
		}
		return map[string]string{"message": "Team member removed successfully."}, store.RemoveTeamMember(ctx, actor, orgID, id, user)
	}
}
