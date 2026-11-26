package apikey

import (
	"context"
	"errors"
	"slices"
	"strings"

	"github.com/Plain-Org/plain-auth/plugins/organization"
)

// OrganizationOptions maps membership roles to API-key management actions.
// Members whose roles include CreatorRole (default "owner") have all actions.
type OrganizationOptions struct {
	CreatorRole string
	Roles       map[string][]string
	// RolesFrom takes API-key grants from an organization service's roles:
	// a member may perform each action one of its roles grants on the
	// "apiKey" resource, roles an organization stored with
	// DynamicAccessControl included, and the organization's creator role
	// may perform all of them. Leave CreatorRole and Roles empty with it.
	RolesFrom *organization.Service

	policy         organization.RolePolicy
	stored, linked bool
}

// RolesAllow reports whether membership may perform an API-key action under
// an organization role policy: the creator role may do everything, and any
// other role needs the action on the apiKey resource.
func RolesAllow(policy organization.RolePolicy, membership, action string) bool {
	return slices.Contains(organization.NormalizeRoles(membership), policy.CreatorRole()) || policy.HasAction(membership, "apiKey", action)
}

// OrganizationRoles returns the linked organization role policy and whether
// the organization's stored roles join it. A store that reads them in its
// own transaction merges them with policy.WithStoredRoles and calls
// RolesAllow. ok is false without RolesFrom.
func (o *OrganizationOptions) OrganizationRoles() (policy organization.RolePolicy, stored, ok bool) {
	return o.policy, o.stored, o.linked
}

const (
	CreateAction = "create"
	ReadAction   = "read"
	UpdateAction = "update"
	DeleteAction = "delete"
)

func (o *OrganizationOptions) Allows(roles, action string) bool {
	if o.linked {
		return RolesAllow(o.policy, roles, action)
	}
	for _, role := range strings.Split(roles, ",") {
		role = strings.TrimSpace(role)
		if role == o.CreatorRole || slices.Contains(o.Roles[role], action) {
			return true
		}
	}
	return false
}

type ReferenceStore interface {
	ConfigureKeyReference(context.Context, string, bool) error
}

func (s *Service) configureReference(ctx context.Context) error {
	if ref, ok := s.opts.Store.(ReferenceStore); ok {
		return ref.ConfigureKeyReference(ctx, s.opts.ConfigID, s.opts.Organization != nil)
	}
	if s.opts.Organization != nil {
		return errors.New("apikey: store does not support organization ownership")
	}
	return nil
}
func (o Owner) ReferenceID() string {
	if o.Organization != nil {
		return o.OrganizationID
	}
	return o.UserID
}
func (s *Service) forAction(o Owner, action string) Owner {
	o.Organization = s.opts.Organization
	o.Action = action
	return o
}
