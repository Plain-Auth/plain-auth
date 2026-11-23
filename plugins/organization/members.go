package organization

import (
	"context"
	"crypto/rand"
	"errors"
	"slices"
	"strings"
	"time"
)

// ActiveMember is the current membership and public profile of a signed-in user.
type ActiveMember struct {
	Member
	User MemberUser `json:"user"`
}

// MemberWithUser pairs an organization membership with its public account profile.
type MemberWithUser = ActiveMember

// ActiveMemberStore resolves the live session selection, its membership and user
// together. A session without a selection returns ErrNoActiveOrg. A selection
// without a corresponding membership returns ErrMemberMissing.
type ActiveMemberStore interface {
	ActiveOrganizationMember(ctx context.Context, sessionID, userID string) (*ActiveMember, error)
}

// AddMemberRequest names an existing account and its destination. TeamID is optional.
type AddMemberRequest struct {
	OrganizationID string
	UserID         string
	Roles          []string
	TeamID         string
}

// MemberWriter commits the organization membership and optional team membership together.
type MemberWriter interface {
	AddOrganizationMember(ctx context.Context, member Member, teamID string) error
}

// AddMember grants membership from trusted application code. The application
// authorizes the grant before calling this function. No HTTP route exposes it.
func (service *Service) AddMember(ctx context.Context, request AddMemberRequest) (*Member, error) {
	store, ok := service.options.Store.(MemberWriter)
	if !ok {
		return nil, errors.New("organization: store does not support server-side member grants")
	}
	if request.TeamID != "" && service.options.teamStore == nil {
		return nil, validation("teamId")
	}
	if request.OrganizationID == "" {
		return nil, validation("organizationId")
	}
	if request.UserID == "" {
		return nil, validation("userId")
	}
	role, err := directMemberRoles(request.Roles)
	if err != nil {
		return nil, err
	}
	member := &Member{
		ID: rand.Text(), OrganizationID: request.OrganizationID, UserID: request.UserID,
		Role: role, CreatedAt: time.Now().UTC().Truncate(time.Millisecond),
	}
	if err := store.AddOrganizationMember(ctx, *member, request.TeamID); err != nil {
		return nil, err
	}
	return member, nil
}

func directMemberRoles(entries []string) (string, error) {
	if len(entries) == 0 {
		return "", validation("role")
	}
	var roles []string
	for _, entry := range entries {
		role := strings.TrimSpace(entry)
		if !builtinRole(role) {
			return "", problem(400, "ROLE_NOT_FOUND", "Role not found")
		}
		if !slices.Contains(roles, role) {
			roles = append(roles, role)
		}
	}
	return strings.Join(roles, ","), nil
}

// Store returns the adapter used for membership, including its configured team policy.
func (service *Service) Store() Store { return service.options.Store }
