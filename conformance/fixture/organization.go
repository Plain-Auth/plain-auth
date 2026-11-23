package main

import (
	"context"
	"encoding/json"
	"os"

	auth "github.com/Plain-Auth/plain-auth"
	"github.com/Plain-Auth/plain-auth/adapters/sqlstore"
	"github.com/Plain-Auth/plain-auth/plugins/organization"
)

// The differential test invokes the server-only operation in a separate process.
func grantMember(database string) error {
	ctx := context.Background()
	store, err := sqlstore.Open(ctx, "sqlite", database)
	if err != nil {
		return err
	}
	defer store.Close()
	var request organization.AddMemberRequest
	if err := json.NewDecoder(os.Stdin).Decode(&request); err != nil {
		return err
	}
	options := organization.Options{Store: store, MembershipLimit: fixtureMembershipLimit()}
	if request.TeamID != "" {
		options.Teams = &organization.TeamOptions{}
	}
	service, err := organization.NewService(options)
	if err != nil {
		return err
	}
	member, err := service.AddMember(ctx, request)
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(member)
}

func fixtureMembershipLimit() organization.MembershipLimit {
	switch os.Getenv("CONFORMANCE_ORG_CAPACITY") {
	case "fixed":
		return organization.MembershipLimit{Maximum: 2}
	case "dynamic":
		return organization.MembershipLimit{Resolve: func(_ context.Context, u auth.User, g organization.Organization) (int, error) {
			if g.Slug == "studio" && u.Name == "Guest" {
				return 0, nil
			}
			return 2, nil
		}}
	default:
		return organization.MembershipLimit{}
	}
}

func fixtureInvitationLimit() *organization.InvitationLimit {
	switch os.Getenv("CONFORMANCE_INVITATION_LIMIT") {
	case "zero":
		return &organization.InvitationLimit{}
	case "fixed":
		return &organization.InvitationLimit{Maximum: 1}
	case "dynamic":
		return &organization.InvitationLimit{Resolve: func(_ context.Context, in organization.InvitationLimitInput) (int, error) {
			if in.User.Name == "Owner" && in.Member.Role == "owner" && in.Member.UserID == in.User.ID && in.Member.OrganizationID == in.Organization.ID && in.Organization.Slug == "studio" {
				return 1, nil
			}
			return 0, nil
		}}
	}
	return nil
}
