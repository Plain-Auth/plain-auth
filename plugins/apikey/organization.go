package apikey

import (
	"context"
	"errors"
	"slices"
	"strings"
)

// OrganizationOptions maps membership roles to API-key management actions.
// Members whose roles include CreatorRole (default "owner") have all actions.
type OrganizationOptions struct {
	CreatorRole string
	Roles       map[string][]string
}

const (
	CreateAction = "create"
	ReadAction   = "read"
	UpdateAction = "update"
	DeleteAction = "delete"
)

var ErrOrganizationRequired = problem(400, "ORGANIZATION_ID_REQUIRED", "Organization ID is required for organization-owned API keys")
var ErrMembership = problem(403, "USER_NOT_MEMBER_OF_ORGANIZATION", "You are not a member of the organization that owns this API key")
var ErrPermission = problem(403, "INSUFFICIENT_API_KEY_PERMISSIONS", "You do not have permission to perform this action on organization API keys")
var ErrOrgPlugin = problem(500, "ORGANIZATION_PLUGIN_REQUIRED", "Organization plugin is required for organization-owned API keys")

func (o *OrganizationOptions) Allows(roles, action string) bool {
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
