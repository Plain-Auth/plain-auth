// Package organization provides member-scoped groups, active selections and invitations.
package organization

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	authn "github.com/Plain-Auth/plain-auth"
	"github.com/Plain-Auth/plain-auth/plugins/access"
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
	// Roles replaces the built-in grants when non-nil. Use DefaultRoles to extend them.
	Roles map[string]access.Statements
	// DynamicAccessControl adds grants from the destination organization's role table.
	DynamicAccessControl bool
	// RoleControl declares the resources available to role management.
	RoleControl *access.Control
	// RoleLimit optionally bounds the number of stored roles in each organization.
	RoleLimit       *RoleLimit
	rolePolicy      RolePolicy
	InvitationLimit *InvitationLimit
	// CancelPendingInvitationsOnReInvite replaces an existing live grant when
	// the application invites the same address again without requesting resend.
	CancelPendingInvitationsOnReInvite bool
	// InvitationExpiresIn applies to new and resent invitations. Zero uses 48 hours.
	InvitationExpiresIn      time.Duration
	BeforeCreateInvitation   InvitationCreationHook
	AfterCreateInvitation    InvitationDecisionHook
	BeforeAcceptInvitation   InvitationDecisionHook
	AfterAcceptInvitation    InvitationDecisionHook
	BeforeRejectInvitation   InvitationDecisionHook
	AfterRejectInvitation    InvitationDecisionHook
	BeforeCancelInvitation   InvitationDecisionHook
	AfterCancelInvitation    InvitationDecisionHook
	MembershipLimit          MembershipLimit
	BeforeUpdateOrganization func(context.Context, BeforeProfileUpdate) (*ProfileUpdate, error)
	AfterUpdateOrganization  func(context.Context, AfterProfileUpdate) error
	Teams                    *TeamOptions
	teamStore                TeamStore
	Store                    Store
	SendInvitation           func(context.Context, Invitation) error
	SendInvitationEmail      func(context.Context, InvitationDelivery) error
	RequireVerifiedEmail     bool
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
		ID: "organization",
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
			o.endpoint(http.MethodPost, "set-active", o.selectActive),
			{Method: http.MethodPost, Path: "/organization/invite-member", Handler: o.invite},
			{Method: http.MethodPost, Path: "/organization/accept-invitation", Handler: o.accept},
		},
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
	now := time.Now().UTC().Truncate(time.Millisecond)
	org := Organization{ID: rand.Text(), Name: name, Slug: slug, CreatedAt: now}
	if value := c.Body["logo"]; value != nil {
		logo, ok := value.(string)
		if !ok {
			return nil, validation("logo")
		}
		org.Logo = &logo
	}
	if value, exists := c.Body["metadata"]; exists {
		m, ok := value.(map[string]any)
		if !ok {
			return nil, validation("metadata")
		}
		org.Metadata, err = json.Marshal(m)
		if err != nil {
			return nil, err
		}
	}
	keep, ok := c.Body["keepCurrentActiveOrganization"].(bool)
	if c.Body["keepCurrentActiveOrganization"] != nil && !ok {
		return nil, validation("keepCurrentActiveOrganization")
	}
	member := Member{ID: rand.Text(), OrganizationID: org.ID, UserID: s.User.ID, Role: o.rolePolicy.CreatorRole(), CreatedAt: now}
	err = o.Store.CreateOrganization(c.Request.Context(), org, member, s.Session.ID, keep)
	return struct {
		Organization
		Members []Member `json:"members"`
	}{org, []Member{member}}, err
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
	return o.Store.OrganizationForMember(c.Request.Context(), s.User.ID, id, slug)
}

func (o Options) selectActive(c authn.EndpointContext, s *authn.SessionResult) (any, error) {
	ctx := c.Request.Context()
	slug, isString := c.Body["organizationSlug"].(string)
	if _, supplied := c.Body["organizationSlug"]; supplied && !isString {
		return nil, validation("organizationSlug")
	}
	value, exists := c.Body["organizationId"]
	if exists && value == nil {
		if err := o.Store.SetActiveOrganization(ctx, s.Session.ID, s.User.ID, nil); err != nil {
			return nil, err
		}
		if s.Session.ActiveOrganizationID != nil && c.DirectBrowserSession(s.Session.Token) {
			return nil, c.TryReissueSessionCookie(s.Session)
		}
		return nil, nil
	}
	id, ok := value.(string)
	if exists && !ok {
		return nil, validation("organizationId")
	}
	if id != "" {
		slug = ""
	}
	if id == "" && slug == "" {
		id = activeID(s)
	}
	if id == "" && slug == "" {
		return nil, nil
	}
	org, err := o.Store.OrganizationForMember(ctx, s.User.ID, id, slug)
	if err != nil {
		return nil, err
	}
	if err := o.Store.SetActiveOrganization(ctx, s.Session.ID, s.User.ID, &org.ID); err != nil {
		return nil, err
	}
	if c.DirectBrowserSession(s.Session.Token) {
		return org, c.TryReissueSessionCookie(s.Session)
	}
	return org, nil
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
