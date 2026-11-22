package main

import (
	"context"
	"encoding/json"
	"os"

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
	service, err := organization.NewService(organization.Options{Store: store, Teams: &organization.TeamOptions{}})
	if err != nil {
		return err
	}
	var request organization.AddMemberRequest
	if err := json.NewDecoder(os.Stdin).Decode(&request); err != nil {
		return err
	}
	member, err := service.AddMember(ctx, request)
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(member)
}
