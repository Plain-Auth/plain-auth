package main

import (
	"context"
	"encoding/json"
	"os"

	auth "github.com/Stonewrit/stonewrit-auth"
	"github.com/Stonewrit/stonewrit-auth/adapters/sqlstore"
	"github.com/Stonewrit/stonewrit-auth/plugins/twofactor"
)

// A separate fixture process exercises the trusted import without a browser route.
func importAuthenticator(database string) error {
	ctx := context.Background()
	store, err := sqlstore.Open(ctx, "sqlite", database)
	if err != nil {
		return err
	}
	defer store.Close()
	host, err := auth.New(auth.Options{Store: store, BaseURL: "http://localhost", Secret: "local-conformance-0123456789-abcdefghijk", Plugins: []auth.Plugin{twofactor.New(twofactor.Options{})}})
	if err != nil {
		return err
	}
	var in struct{ UserID, Secret string }
	if err := json.NewDecoder(os.Stdin).Decode(&in); err != nil {
		return err
	}
	return host.ImportTOTP(ctx, in.UserID, in.Secret)
}
