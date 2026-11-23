package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"

	"github.com/Plain-Auth/plain-auth/adapters/sqlstore"
	"github.com/Plain-Auth/plain-auth/plugins/organization"
)

func fixtureTeamOptions() *organization.TeamOptions {
	opts := &organization.TeamOptions{}
	if os.Getenv("CONFORMANCE_TEAM_LIMIT") == "resolve" {
		opts.ResolveMaximumTeams = func(_ context.Context, in organization.TeamLimitInput) (int, error) {
			if in.Session == nil {
				if in.Request != nil {
					return 0, errors.New("trusted creation received an HTTP request")
				}
				return 4, nil
			}
			if in.Session.Session.UserID != in.Session.User.ID || in.Session.Session.Token == "" || in.Request == nil {
				return 0, errors.New("incomplete team limit context")
			}
			if in.Session.User.Email == "unlimited@example.test" {
				return 0, nil
			}
			if id := in.Session.Session.ActiveOrganizationID; id != nil && *id == in.OrganizationID {
				return 2, nil
			}
			return 3, nil
		}
	}
	return opts
}

func createFixtureTeam(path string) error {
	ctx := context.Background()
	store, err := sqlstore.Open(ctx, "sqlite", path)
	if err != nil {
		return err
	}
	defer store.Close()
	service, err := organization.NewService(organization.Options{Store: store, Teams: fixtureTeamOptions()})
	if err != nil {
		return err
	}
	var request organization.CreateTeamRequest
	if err := json.NewDecoder(os.Stdin).Decode(&request); err != nil {
		return err
	}
	team, err := service.CreateTeam(ctx, request)
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(team)
}
