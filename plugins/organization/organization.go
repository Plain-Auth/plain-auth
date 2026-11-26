// Package organization provides member-scoped groups, active selections and invitations.
package organization

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"maps"
	"net/http"
	"strings"
	"time"

	authn "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/internal/sessionfields"
	"github.com/Plain-Org/plain-auth/plugins/access"
)

type Organization struct {
	ID        string          `json:"id"`
	Name      string          `json:"name"`
	Slug      string          `json:"slug"`
	Logo      *string         `json:"logo"`
	Metadata  json.RawMessage `json:"metadata,omitempty"`
	CreatedAt time.Time       `json:"createdAt"`
}

type Member struct {
	ID             string    `json:"id"`
	OrganizationID string    `json:"organizationId"`
	UserID         string    `json:"userId"`
	Role           string    `json:"role"`
	CreatedAt      time.Time `json:"createdAt"`
}

type Invitation struct {
	TeamID         *string   `json:"teamId,omitempty"`
	ID             string    `json:"id"`
	OrganizationID string    `json:"organizationId"`
	InviterID      string    `json:"inviterId"`
	Email          string    `json:"email"`
	Role           string    `json:"role"`
	Status         string    `json:"status"`
	ExpiresAt      time.Time `json:"expiresAt"`
	CreatedAt      time.Time `json:"createdAt"`
}

// Store implements membership-scoped reads and transactional organization mutations.
// Invitation creation checks the inviter's role and acceptance verifies the recipient.
type Store interface {
	CreateOrganization(context.Context, Organization, Member, string, bool) error
	OrganizationsForUser(context.Context, string) ([]Organization, error)
	OrganizationForMember(ctx context.Context, userID, id, slug string) (*Organization, error)
	ActiveOrganization(ctx context.Context, sessionID, userID string) (*string, error)
	SetActiveOrganization(ctx context.Context, sessionID, userID string, id *string) error
	InviteOrganizationMember(ctx context.Context, invitation Invitation, sessionID string, resend bool) (Invitation, error)
	AcceptOrganizationInvitation(ctx context.Context, id, sessionID string, recipient authn.User, now time.Time, requireVerified bool) (Invitation, Member, error)
}

type Options struct {
	// CreatorRole is the membership assigned to an organization's creator.
	CreatorRole string
	// AllowUserToCreateOrganization decides whether a signed-in user may
	// create organizations. Nil allows every user.
	AllowUserToCreateOrganization func(context.Context, authn.User) (bool, error)
	// OrganizationLimit caps how many organizations a user may belong to when
	// creating another. Zero means unlimited.
	OrganizationLimit int
	// OrganizationLimitReached reports whether a user has reached a limit the
	// host defines, such as one based on their plan. It cannot be combined
	// with OrganizationLimit.
	OrganizationLimitReached func(context.Context, authn.User) (bool, error)
	// Roles replaces the built-in grants when non-nil. Use DefaultRoles to extend them.
	Roles map[string]access.Statements
	// DynamicAccessControl adds grants from the destination organization's role table.
	DynamicAccessControl bool
	// RoleControl declares the resources available to role management.
	RoleControl *access.Control
	// RoleAdditionalFields declares the stored role's application-defined columns.
	RoleAdditionalFields map[string]RoleField
	// RoleLimit optionally bounds the number of stored roles in each organization.
	RoleLimit       *RoleLimit
	rolePolicy      RolePolicy
	InvitationLimit *InvitationLimit
	// CancelPendingInvitationsOnReInvite replaces an existing live grant when
	// the application invites the same address again without requesting resend.
	CancelPendingInvitationsOnReInvite bool
	// InvitationExpiresIn applies to new and resent invitations. Zero uses 48 hours.
	InvitationExpiresIn    time.Duration
	BeforeCreateInvitation InvitationCreationHook
	AfterCreateInvitation  InvitationDecisionHook
	BeforeAcceptInvitation InvitationDecisionHook
	AfterAcceptInvitation  InvitationDecisionHook
	BeforeRejectInvitation InvitationDecisionHook
	AfterRejectInvitation  InvitationDecisionHook
	BeforeCancelInvitation InvitationDecisionHook
	AfterCancelInvitation  InvitationDecisionHook
	MembershipLimit        MembershipLimit
	// BeforeCreateOrganization sees the proposed organization and its creator
	// and may return fields that replace the proposal. An error cancels it.
	BeforeCreateOrganization func(context.Context, BeforeOrganizationCreation) (*ProfileUpdate, error)
	// AfterCreateOrganization runs after the organization and the creator's
	// membership commit. Its error is returned and the organization remains.
	AfterCreateOrganization func(context.Context, AfterOrganizationCreation) error
	// BeforeAddMember sees a membership about to be granted to an
	// organization's creator or through Service.AddMember, and may replace its
	// roles. An error cancels the grant.
	BeforeAddMember func(context.Context, BeforeMemberAddition) (*MemberOverride, error)
	// AfterAddMember runs after such a membership commits. Its error is
	// returned and the membership remains.
	AfterAddMember func(context.Context, AfterMemberAddition) error
	// BeforeRemoveMember runs after POST /organization/remove-member passes
	// its checks and before the membership is removed. An error cancels it.
	BeforeRemoveMember func(context.Context, MemberRemoval) error
	// AfterRemoveMember runs after the removal commits. Its error is
	// returned and the membership stays removed.
	AfterRemoveMember func(context.Context, MemberRemoval) error
	// BeforeUpdateMemberRole runs after a role change passes its checks and
	// may replace the roles to set. The replacement is checked like the
	// caller's own request. An error cancels the change.
	BeforeUpdateMemberRole func(context.Context, BeforeMemberRoleUpdate) (*MemberOverride, error)
	// AfterUpdateMemberRole runs after the change commits. Its error is
	// returned and the new roles remain.
	AfterUpdateMemberRole func(context.Context, AfterMemberRoleUpdate) error
	// BeforeCreateTeam, BeforeUpdateTeam and BeforeDeleteTeam run after a team
	// change passes its checks. Create and update may return a new name. An
	// error cancels the change. The After hooks run once it commits; their
	// error is returned and the change remains. Team hooks require Teams.
	BeforeCreateTeam func(context.Context, TeamChange) (*TeamOverride, error)
	AfterCreateTeam  func(context.Context, TeamChange) error
	BeforeUpdateTeam func(context.Context, BeforeTeamUpdate) (*TeamOverride, error)
	AfterUpdateTeam  func(context.Context, TeamChange) error
	BeforeDeleteTeam func(context.Context, TeamChange) error
	AfterDeleteTeam  func(context.Context, TeamChange) error
	// BeforeAddTeamMember and BeforeRemoveTeamMember run after a team
	// membership change passes its permission checks; an error cancels it. A
	// team member limit is checked afterwards, when the membership is written.
	// The After hooks run once the change commits; their error is returned
	// and the change remains. Adding an existing team member runs no hooks.
	BeforeAddTeamMember      func(context.Context, TeamMembershipChange) error
	AfterAddTeamMember       func(context.Context, TeamMembershipChange) error
	BeforeRemoveTeamMember   func(context.Context, TeamMembershipChange) error
	AfterRemoveTeamMember    func(context.Context, TeamMembershipChange) error
	BeforeUpdateOrganization func(context.Context, BeforeProfileUpdate) (*ProfileUpdate, error)
	AfterUpdateOrganization  func(context.Context, AfterProfileUpdate) error
	// DisableOrganizationDeletion makes POST /organization/delete answer 404
	// with ORGANIZATION_DELETION_DISABLED.
	DisableOrganizationDeletion bool
	// BeforeDeleteOrganization runs after the caller's permission check and
	// before anything is deleted. Returning an error cancels the deletion.
	BeforeDeleteOrganization func(context.Context, OrganizationDeletion) error
	// AfterDeleteOrganization runs after the deletion commits. Its error is
	// returned to the caller, and the organization stays deleted.
	AfterDeleteOrganization func(context.Context, OrganizationDeletion) error
	Teams                   *TeamOptions
	teamStore               TeamStore
	Store                   Store
	SendInvitation          func(context.Context, Invitation) error
	SendInvitationEmail     func(context.Context, InvitationDelivery) error
	RequireVerifiedEmail    bool
}

func problem(status int, code, message string) *authn.APIError {
	return &authn.APIError{Status: status, Code: code, Message: message}
}

// Errors are shared with storage implementations so transactions can return consistent domain errors.
var (
	ErrUnauthenticated = problem(401, "UNAUTHORIZED", "Unauthorized")
	ErrNotFound        = problem(400, "ORGANIZATION_NOT_FOUND", "Organization not found")
	ErrDuplicate       = problem(400, "ORGANIZATION_ALREADY_EXISTS", "Organization already exists")
	ErrNotMember       = problem(403, "USER_IS_NOT_A_MEMBER_OF_THE_ORGANIZATION", "User is not a member of the organization")
	ErrInviteDenied    = problem(403, "YOU_ARE_NOT_ALLOWED_TO_INVITE_USERS_TO_THIS_ORGANIZATION", "You are not allowed to invite users to this organization")
	ErrRoleDenied      = problem(403, "YOU_ARE_NOT_ALLOWED_TO_INVITE_USER_WITH_THIS_ROLE", "You are not allowed to invite a user with this role")
	ErrAlreadyMember   = problem(400, "USER_IS_ALREADY_A_MEMBER_OF_THIS_ORGANIZATION", "User is already a member of this organization")
	ErrAlreadyInvited  = problem(400, "USER_IS_ALREADY_INVITED_TO_THIS_ORGANIZATION", "User is already invited to this organization")
	ErrInvitation      = problem(400, "INVITATION_NOT_FOUND", "Invitation not found")
	ErrRecipient       = problem(403, "YOU_ARE_NOT_THE_RECIPIENT_OF_THE_INVITATION", "You are not the recipient of the invitation")
	ErrUnverified      = problem(403, "EMAIL_VERIFICATION_REQUIRED_BEFORE_ACCEPTING_OR_REJECTING_INVITATION", "Email verification required before accepting or rejecting invitation")
	ErrMemberLimit     = problem(403, "ORGANIZATION_MEMBERSHIP_LIMIT_REACHED", "Organization membership limit reached")
)

type handler func(authn.EndpointContext, *authn.SessionResult) (any, error)

func (o Options) endpoint(method, action string, fn handler) authn.Endpoint {
	return authn.Endpoint{Method: method, Path: "/organization/" + action, Handler: func(c authn.EndpointContext) (any, error) {
		s, err := endpointSession(c, method, action)
		if err != nil {
			return nil, err
		}
		return fn(c, s)
	}}
}

func endpointSession(c authn.EndpointContext, method, action string) (*authn.SessionResult, error) {
	s, err := c.Auth.GetSession(c.Request.Context(), c.Request.Header)
	if err != nil {
		return nil, err
	}
	if s == nil {
		return nil, ErrUnauthenticated
	}
	if s.Session.IsApplicationCredential() {
		allowed := false
		switch action {
		case "invite-member":
			allowed = s.Session.AllowsCredentialAction("invitation", "create")
		case "list", "get-organization":
			allowed = s.Session.AllowsCredentialAction("organization", "read")
		}
		if !allowed {
			return nil, &authn.APIError{Status: 403, Code: "INSUFFICIENT_API_KEY_PERMISSIONS", Message: "Credential cannot perform this organization action"}
		}
		return s, nil
	}
	if method != http.MethodGet && action != "set-active" && action != "set-active-team" && action != "has-permission" {
		if err := s.Session.RequireOwner(); err != nil {
			return nil, err
		}
	}
	return s, nil
}

// New registers the organization's membership, team and invitation endpoints.
func New(o Options) (authn.Plugin, error) {
	service, err := NewService(o)
	if err != nil {
		return authn.Plugin{}, err
	}
	return service.Plugin(), nil
}

// Service uses one configuration for the HTTP plugin and trusted server operations.
type Service struct{ options Options }

// RoleSettings returns the role policy this service applies and whether it
// also reads the roles organizations store with DynamicAccessControl, so
// other plugins can authorize organization actions with the same roles.
func (service *Service) RoleSettings() (RolePolicy, bool) {
	return service.options.rolePolicy, service.options.DynamicAccessControl
}

func NewService(o Options) (*Service, error) {
	if o.Store == nil {
		return nil, errors.New("organization: Store is required")
	}
	roleStore, supportsRoles := o.Store.(RolePolicyStoreProvider)
	if o.CreatorRole != "" || o.Roles != nil {
		policy, err := NewRolePolicy(o.CreatorRole, o.Roles)
		if err != nil {
			return nil, err
		}
		if !supportsRoles {
			return nil, errors.New("organization: custom roles require a RolePolicyStoreProvider")
		}
		o.Store, err = roleStore.WithOrganizationRolePolicy(policy)
		if err != nil {
			return nil, err
		}
		o.rolePolicy = policy
	} else if supportsRoles {
		o.rolePolicy = roleStore.OrganizationRolePolicy()
	}
	if o.RoleControl != nil {
		control := *o.RoleControl
		o.RoleControl = &control
	}
	if o.RoleLimit != nil {
		limit := *o.RoleLimit
		if limit.Maximum < 0 || (limit.Resolve != nil && limit.Maximum != 0) {
			return nil, errors.New("organization: choose a nonnegative fixed role limit or a resolver")
		}
		o.RoleLimit = &limit
	}
	if o.DynamicAccessControl {
		provider, ok := o.Store.(DynamicRoleStoreProvider)
		if !ok {
			return nil, errors.New("organization: dynamic access control requires a DynamicRoleStoreProvider")
		}
		store, err := provider.WithOrganizationDynamicRoles()
		if err != nil {
			return nil, err
		}
		o.Store = store
	}
	if len(o.RoleAdditionalFields) > 0 {
		if !o.DynamicAccessControl {
			return nil, errors.New("organization: role fields require dynamic access control")
		}
		defs, err := sessionfields.NormalizeRole(o.RoleAdditionalFields)
		if err != nil {
			return nil, err
		}
		provider, ok := o.Store.(RoleFieldStoreProvider)
		if !ok {
			return nil, errors.New("organization: additional role fields require a RoleFieldStoreProvider")
		}
		o.Store, err = provider.WithOrganizationRoleFields(defs)
		if err != nil {
			return nil, err
		}
		o.RoleAdditionalFields = defs
	}
	if err := o.configureCreationPolicy(); err != nil {
		return nil, err
	}
	if err := o.MembershipLimit.Validate(); err != nil {
		return nil, err
	}
	if o.MembershipLimit.Maximum != 0 || o.MembershipLimit.Resolve != nil {
		provider, ok := o.Store.(MembershipLimitStoreProvider)
		if !ok {
			return nil, errors.New("organization: configured membership limits require a MembershipLimitStoreProvider")
		}
		store, err := provider.WithOrganizationMembershipLimit(o.MembershipLimit)
		if err != nil {
			return nil, err
		}
		o.Store = store
	}
	if o.InvitationLimit != nil {
		if err := o.InvitationLimit.Validate(); err != nil {
			return nil, err
		}
		provider, ok := o.Store.(InvitationLimitStoreProvider)
		if !ok {
			return nil, errors.New("organization: configured invitation limits require an InvitationLimitStoreProvider")
		}
		store, err := provider.WithOrganizationInvitationLimit(*o.InvitationLimit)
		if err != nil {
			return nil, err
		}
		o.Store = store
	}
	if err := o.configureTeams(); err != nil {
		return nil, err
	}
	if err := o.validateTeamHooks(); err != nil {
		return nil, err
	}
	if o.DynamicAccessControl {
		if _, ok := o.Store.(DynamicRoleStore); !ok {
			return nil, errors.New("organization: the configured store must retain dynamic role support")
		}
	}
	if o.BeforeUpdateOrganization != nil || o.AfterUpdateOrganization != nil {
		if _, ok := o.Store.(ObservedProfileStore); !ok {
			return nil, errors.New("organization: profile hooks require an ObservedProfileStore")
		}
	}
	if o.BeforeUpdateMemberRole != nil || o.AfterUpdateMemberRole != nil {
		if _, ok := o.Store.(ObservedMemberRoleStore); !ok {
			return nil, errors.New("organization: member role hooks require an ObservedMemberRoleStore")
		}
	}
	if o.BeforeRemoveMember != nil || o.AfterRemoveMember != nil {
		if _, ok := o.Store.(ObservedMemberRemovalStore); !ok {
			return nil, errors.New("organization: member removal hooks require an ObservedMemberRemovalStore")
		}
	}
	if o.BeforeDeleteOrganization != nil || o.AfterDeleteOrganization != nil {
		if _, ok := o.Store.(OrganizationDeletionStore); !ok {
			return nil, errors.New("organization: deletion hooks require an OrganizationDeletionStore")
		}
	}
	if o.SendInvitationEmail != nil && o.SendInvitation != nil {
		return nil, errors.New("organization: configure one invitation sender")
	}
	if o.BeforeCreateInvitation != nil {
		if _, ok := o.Store.(PreparedInvitationStore); !ok {
			return nil, errors.New("organization: before invitation creation requires a PreparedInvitationStore")
		}
	} else if o.SendInvitationEmail != nil || o.AfterCreateInvitation != nil {
		if _, ok := o.Store.(InvitationDeliveryStore); !ok {
			return nil, errors.New("organization: invitation delivery and creation callbacks require an InvitationDeliveryStore")
		}
	} else if o.CancelPendingInvitationsOnReInvite {
		if _, ok := o.Store.(InvitationReplacementStore); !ok {
			return nil, errors.New("organization: replacing invitations requires an InvitationReplacementStore")
		}
	}
	if o.BeforeRejectInvitation != nil || o.AfterRejectInvitation != nil || o.BeforeCancelInvitation != nil || o.AfterCancelInvitation != nil {
		if _, ok := o.Store.(ObservedInvitationDecisionStore); !ok {
			return nil, errors.New("organization: invitation decision hooks require an ObservedInvitationDecisionStore")
		}
	}
	if o.BeforeAcceptInvitation != nil || o.AfterAcceptInvitation != nil {
		if _, ok := o.Store.(ObservedInvitationAcceptanceStore); !ok {
			return nil, errors.New("organization: acceptance hooks require an ObservedInvitationAcceptanceStore")
		}
	}
	return &Service{options: o}, nil
}

// Plugin exposes organization routes for the host auth instance.
func (service *Service) Plugin() authn.Plugin {
	o := service.options
	plugin := authn.Plugin{
		ID:                     "organization",
		OrganizationRoleFields: maps.Clone(o.RoleAdditionalFields),
		OnReadSession: func(ctx context.Context, s *authn.SessionResult) error {
			if s.Session.IsApplicationCredential() {
				return nil
			}
			active, err := o.Store.ActiveOrganization(ctx, s.Session.ID, s.User.ID)
			s.Session.ActiveOrganizationID = active
			if err == nil && o.teamStore != nil {
				s.Session.ActiveTeamID, err = o.teamStore.ActiveTeam(ctx, TeamActor{UserID: s.User.ID, SessionID: s.Session.ID})
			}
			return err
		},
		Endpoints: []authn.Endpoint{
			o.endpoint(http.MethodPost, "create", o.create),
			o.endpoint(http.MethodGet, "list", func(c authn.EndpointContext, s *authn.SessionResult) (any, error) {
				return o.Store.OrganizationsForUser(c.Request.Context(), s.User.ID)
			}),
			o.endpoint(http.MethodGet, "get-organization", o.get),
			{Method: http.MethodPost, Path: "/organization/set-active", Handler: o.selectActive},
			{Method: http.MethodPost, Path: "/organization/invite-member", Handler: o.invite},
			{Method: http.MethodPost, Path: "/organization/accept-invitation", Handler: o.accept},
		},
	}
	if store, ok := o.Store.(RoleUpdateStore); ok && o.DynamicAccessControl {
		plugin.Endpoints = append(plugin.Endpoints, o.updateRoleEndpoint(store))
	}
	if store, ok := o.Store.(RoleCreationStore); ok && o.DynamicAccessControl {
		plugin.Endpoints = append(plugin.Endpoints, o.createRoleEndpoint(store))
	}
	if store, ok := o.Store.(RoleDeletionStore); ok && o.DynamicAccessControl {
		plugin.Endpoints = append(plugin.Endpoints, deleteRoleEndpoint(store))
	}
	if store, ok := o.Store.(RoleDirectoryStore); ok && o.DynamicAccessControl {
		plugin.Endpoints = append(plugin.Endpoints, roleDirectoryEndpoint("get-role", store), roleDirectoryEndpoint("list-roles", store))
	}
	if store, ok := o.Store.(ProfileStore); ok {
		plugin.Endpoints = append(plugin.Endpoints, service.profileEndpoints(store)...)
	}
	if store, ok := o.Store.(OrganizationDeletionStore); ok {
		plugin.Endpoints = append(plugin.Endpoints, o.deleteOrganizationEndpoint(store))
	}
	if _, ok := o.Store.(MemberRoleStore); ok {
		plugin.Endpoints = append(plugin.Endpoints, service.memberRoleEndpoint())
	}
	if store, ok := o.Store.(InvitationCancellationStore); ok {
		plugin.Endpoints = append(plugin.Endpoints, o.cancelInvitationEndpoint(store))
	}
	if store, ok := o.Store.(InvitationRejectionStore); ok {
		plugin.Endpoints = append(plugin.Endpoints, o.rejectInvitationEndpoint(store))
	}
	if store, ok := o.Store.(InvitationDetailsStore); ok {
		plugin.Endpoints = append(plugin.Endpoints, o.invitationDetailsEndpoint(store))
	}
	if store, ok := o.Store.(ReceivedInvitationStore); ok {
		plugin.Endpoints = append(plugin.Endpoints, o.receivedInvitationsEndpoint(store))
	}
	if store, ok := o.Store.(InvitationListStore); ok {
		plugin.Endpoints = append(plugin.Endpoints, o.invitationListEndpoint(store))
	}
	if store, ok := o.Store.(FullOrganizationStore); ok {
		plugin.Endpoints = append(plugin.Endpoints, o.fullOrganizationEndpoint(store))
	}
	if store, ok := o.Store.(MemberDirectoryStore); ok {
		plugin.Endpoints = append(plugin.Endpoints, o.memberDirectoryEndpoint(store))
	}
	if store, ok := o.Store.(MemberRoleReader); ok {
		plugin.Endpoints = append(plugin.Endpoints, o.readMemberRoleEndpoint(store), o.rolePolicy.permissionEndpoint(store))
	}
	if store, ok := o.Store.(ActiveMemberStore); ok {
		plugin.Endpoints = append(plugin.Endpoints, o.endpoint(http.MethodGet, "get-active-member", func(c authn.EndpointContext, s *authn.SessionResult) (any, error) {
			return store.ActiveOrganizationMember(c.Request.Context(), s.Session.ID, s.User.ID)
		}))
	}
	if store, ok := o.Store.(MemberRemovalStore); ok {
		plugin.Endpoints = append(plugin.Endpoints, o.memberRemovalEndpoints(store)...)
	}
	if o.teamStore != nil {
		plugin.Endpoints = append(plugin.Endpoints, o.teamEndpoints()...)
	}
	return plugin
}

func validation(field string) error { return problem(400, "VALIDATION_ERROR", "Invalid "+field) }

func textField(body map[string]any, key string) (string, error) {
	v, ok := body[key].(string)
	if !ok || v == "" {
		return "", validation(key)
	}
	return v, nil
}

func activeID(s *authn.SessionResult) string {
	if s.Session.ActiveOrganizationID == nil {
		return ""
	}
	return *s.Session.ActiveOrganizationID
}

func (o Options) create(c authn.EndpointContext, s *authn.SessionResult) (any, error) {
	name, err := textField(c.Body, "name")
	if err != nil {
		return nil, err
	}
	slug, err := textField(c.Body, "slug")
	if err != nil {
		return nil, err
	}
	var logo *string
	if value := c.Body["logo"]; value != nil {
		text, ok := value.(string)
		if !ok {
			return nil, validation("logo")
		}
		logo = &text
	}
	var metadata map[string]any
	if value, exists := c.Body["metadata"]; exists {
		m, ok := value.(map[string]any)
		if !ok {
			return nil, validation("metadata")
		}
		metadata = m
	}
	keep, ok := c.Body["keepCurrentActiveOrganization"].(bool)
	if c.Body["keepCurrentActiveOrganization"] != nil && !ok {
		return nil, validation("keepCurrentActiveOrganization")
	}
	group, err := newOrganization(name, slug, logo, metadata)
	if err != nil {
		return nil, err
	}
	ctx := c.Request.Context()
	if err := o.checkCreationPolicy(ctx, s.User); err != nil {
		return nil, err
	}
	return o.createOrganization(ctx, s.User, group, s.Session.ID, keep)
}

func (o Options) get(c authn.EndpointContext, s *authn.SessionResult) (any, error) {
	q := c.Request.URL.Query()
	id, slug := q.Get("organizationId"), q.Get("organizationSlug")
	if id == "" && slug == "" {
		id = activeID(s)
	}
	if id == "" && slug == "" {
		return nil, nil
	}
	ctx := c.Request.Context()
	group, err := o.Store.OrganizationForMember(ctx, s.User.ID, id, slug)
	if errors.Is(err, ErrNotMember) {
		if store, ok := o.Store.(DeniedSelectionStore); ok {
			if clearErr := store.ClearDeniedOrganizationSelection(ctx, s.Session.ID, s.User.ID, id, slug); clearErr != nil {
				return nil, clearErr
			}
		}
	}
	return group, err
}

// DeniedSelectionStore clears a session's organization selection after the
// caller is refused an organization they do not belong to.
type DeniedSelectionStore interface {
	ClearDeniedOrganizationSelection(ctx context.Context, sessionID, userID, organizationID, organizationSlug string) error
}

func (o Options) invite(c authn.EndpointContext) (any, error) {
	input, err := readInvitationInput(c.Body)
	if err != nil {
		return nil, err
	}
	s, err := endpointSession(c, http.MethodPost, "invite-member")
	if err != nil {
		return nil, err
	}
	id := input.organizationID
	if id == "" {
		id = activeID(s)
	}
	if id == "" {
		return nil, ErrNotFound
	}
	email := strings.ToLower(input.email)
	if !invitationEmailPattern.MatchString(email) {
		return nil, problem(400, "INVALID_EMAIL", "Invalid email")
	}
	_, supportsPreparation := o.Store.(PreparedInvitationStore)
	role := strings.Join(input.roles, ",")
	if !supportsPreparation {
		role, err = o.rolePolicy.ParseInvitationRoles(input.roles...)
		if err != nil {
			return nil, err
		}
	}
	resend := input.resend
	now := time.Now().UTC().Truncate(time.Millisecond)
	validFor := o.InvitationExpiresIn
	if validFor == 0 {
		validFor = 48 * time.Hour
	}
	inv := Invitation{ID: rand.Text(), OrganizationID: id, InviterID: s.User.ID, Email: email, Role: role, Status: "pending", CreatedAt: now, ExpiresAt: now.Add(validFor).Truncate(time.Millisecond)}
	how := InvitationIssueOptions{Resend: resend, Replace: o.CancelPendingInvitationsOnReInvite && !resend, UseActiveOrganization: input.organizationID == ""}
	if input.teamIDs != nil {
		_, single := c.Body["teamId"].(string)
		how.TeamTargets = &InvitationTeamTargets{IDs: input.teamIDs, Single: single}
		if !supportsPreparation && o.teamStore != nil {
			inv.TeamID, err = how.TeamTargets.StoredValue()
			if err != nil {
				return nil, err
			}
		}
	}
	if supportsPreparation || o.SendInvitationEmail != nil || o.AfterCreateInvitation != nil {
		inv, err = o.issueObservedInvitation(c, s, inv, how)
		if err != nil {
			return nil, err
		}
		return o.invitationRow(inv), nil
	}
	if o.CancelPendingInvitationsOnReInvite && !resend {
		inv, err = o.Store.(InvitationReplacementStore).ReplaceOrganizationInvitation(c.Request.Context(), inv, s.Session.ID)
	} else {
		inv, err = o.Store.InviteOrganizationMember(c.Request.Context(), inv, s.Session.ID, resend)
	}
	if err != nil {
		return nil, err
	}
	if err := o.sendSimpleInvitation(c.Request.Context(), inv); err != nil {
		return nil, err
	}
	return o.invitationRow(inv), nil
}

func (o Options) accept(c authn.EndpointContext) (any, error) {
	id, s, err := invitationAction(c, "accept-invitation")
	if err != nil {
		return nil, err
	}
	var inv Invitation
	var member Member
	if store, ok := o.Store.(ObservedInvitationAcceptanceStore); ok {
		inv, member, err = o.acceptWithHooks(c.Request.Context(), store, s, id)
	} else {
		inv, member, err = o.Store.AcceptOrganizationInvitation(c.Request.Context(), id, s.Session.ID, s.User, time.Now().UTC().Truncate(time.Millisecond), o.RequireVerifiedEmail)
	}
	if err != nil {
		return nil, err
	}
	return map[string]any{"invitation": o.invitationRow(inv), "member": member}, nil
}
