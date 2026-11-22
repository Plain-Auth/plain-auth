package authtest

import (
	"context"
	"errors"
	"slices"

	auth "github.com/Plain-Auth/plain-auth"
	"github.com/Plain-Auth/plain-auth/plugins/organization"
)

// OrganizationStore saves ownerless fixture records and removes their local
// tenant data. A custom adapter can implement it alongside organization.Store.
type OrganizationStore interface {
	SaveFixtureOrganization(context.Context, organization.Organization) (organization.Organization, error)
	DeleteFixtureOrganization(context.Context, string) error
}

var errOrganizationSetup = errors.New("authtest: organization fixtures require NewWithOrganizations")

// NewWithOrganizations installs a single organization plugin and retains its
// service for trusted fixture grants. A nil org.Store uses opts.Store.
func NewWithOrganizations(opts auth.Options, org organization.Options) (*Server, error) {
	for _, p := range opts.Plugins {
		if p.ID == "organization" {
			return nil, errors.New("authtest: configure the organization plugin only through NewWithOrganizations")
		}
	}
	if org.Store == nil {
		var ok bool
		org.Store, ok = opts.Store.(organization.Store)
		if !ok {
			return nil, errors.New("authtest: adapter does not implement organization.Store")
		}
	}
	service, err := organization.NewService(org)
	if err != nil {
		return nil, err
	}
	fixtures, ok := service.Store().(OrganizationStore)
	if !ok {
		return nil, errors.New("authtest: configured organization adapter does not implement authtest.OrganizationStore")
	}
	if _, ok := service.Store().(organization.MemberWriter); !ok {
		return nil, errors.New("authtest: configured organization adapter does not support trusted member grants")
	}
	opts.Plugins = append(slices.Clone(opts.Plugins), service.Plugin())
	server, err := New(opts)
	if err != nil {
		return nil, err
	}
	server.organizations, server.organizationFixtures = service, fixtures
	return server, nil
}

// SaveOrganization inserts the supplied organization without creating a member, team or login.
func (s *Server) SaveOrganization(ctx context.Context, o organization.Organization) (organization.Organization, error) {
	if s.organizationFixtures == nil {
		return organization.Organization{}, errOrganizationSetup
	}
	return s.organizationFixtures.SaveFixtureOrganization(ctx, o)
}

// AddMember grants a role to an existing account. An omitted role defaults to member.
func (s *Server) AddMember(ctx context.Context, request organization.AddMemberRequest) (*organization.Member, error) {
	if s.organizations == nil {
		return nil, errOrganizationSetup
	}
	if len(request.Roles) == 0 {
		request.Roles = []string{"member"}
	}
	return s.organizations.AddMember(ctx, request)
}

// DeleteOrganization removes a fixture and its owned local state from the test database.
func (s *Server) DeleteOrganization(ctx context.Context, id string) error {
	if s.organizationFixtures == nil {
		return errOrganizationSetup
	}
	return s.organizationFixtures.DeleteFixtureOrganization(ctx, id)
}
