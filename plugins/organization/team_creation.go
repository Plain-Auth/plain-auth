package organization

import (
	"context"
	"errors"
	"net/http"
	"strings"

	auth "github.com/Plain-Auth/plain-auth"
)

// TeamLimitInput describes the destination and the signed-in user. A trusted
// Service.CreateTeam call has no session or HTTP request.
type TeamLimitInput struct {
	OrganizationID string
	Session        *auth.SessionResult
	Request        *http.Request `json:"-"`
}

// CreateTeamRequest identifies the organization that will own a new team.
type CreateTeamRequest struct {
	OrganizationID string
	Name           string
}

// TeamCreationStore supports both authenticated HTTP and trusted server creation.
// A nil actor is reserved for direct server calls with an explicit organization.
type TeamCreationStore interface {
	CreateOrganizationTeam(context.Context, *TeamActor, CreateTeamRequest, *http.Request) (*Team, error)
}

var ErrTeamLimitChanged = problem(409, "TEAM_POLICY_INPUT_CHANGED", "Team policy inputs changed. Retry the request.")

// CreateTeam creates a team from trusted server code. The caller supplies the destination.
func (s *Service) CreateTeam(ctx context.Context, input CreateTeamRequest) (*Team, error) {
	if _, ok := s.options.teamStore.(TeamCreationStore); !ok {
		return nil, errors.New("organization: trusted team creation requires a TeamCreationStore")
	}
	return s.options.createTeam(ctx, nil, input, nil)
}

func (o Options) teamCreationEndpoint() auth.Endpoint {
	return auth.Endpoint{Method: http.MethodPost, Path: "/organization/create-team", Handler: func(c auth.EndpointContext) (any, error) {
		var issues []string
		var input CreateTeamRequest
		value, present := c.Body["name"]
		var ok bool
		if input.Name, ok = value.(string); !ok {
			issues = append(issues, bodyTypeIssue("name", "string", value, present))
		}
		if value, present = c.Body["organizationId"]; present {
			if input.OrganizationID, ok = value.(string); !ok {
				issues = append(issues, bodyTypeIssue("organizationId", "string", value, true))
			}
		}
		if len(issues) > 0 {
			return nil, problem(400, "VALIDATION_ERROR", strings.Join(issues, "; "))
		}
		session, err := endpointSession(c, http.MethodPost, "create-team")
		if err != nil {
			return nil, err
		}
		actor := TeamActor{UserID: session.User.ID, SessionID: session.Session.ID}
		if _, ok := o.teamStore.(TeamCreationStore); ok {
			return o.createTeam(c.Request.Context(), &actor, input, c.Request)
		}
		return o.teamStore.CreateTeam(c.Request.Context(), actor, input.OrganizationID, input.Name)
	}}
}
