// Command scimfixture exercises server-only catalog methods from a test process.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"time"

	auth "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/adapters/sqlstore"
	"github.com/Plain-Org/plain-auth/plugins/scim"
)

type input struct {
	Op, ProvisioningDomainID, CreationRequestID, ActorID, ConnectionID, CredentialID string
	Scopes                                                                           []string
	ExpiresAt                                                                        time.Time
	Limit, Offset                                                                    int
	SortDirection                                                                    string
}

func main() {
	if len(os.Args) != 2 {
		log.Fatal("expected a disposable database path")
	}
	ctx := context.Background()
	db, e := sqlstore.Open(ctx, "sqlite", os.Args[1])
	if e != nil {
		log.Fatal(e)
	}
	defer db.Close()
	h, e := auth.New(auth.Options{BaseURL: "http://fixture.localhost", Store: db, Secret: "fixture-only-directory-testing-secret"})
	if e != nil {
		log.Fatal(e)
	}
	directory, e := scim.New(h, scim.Options{Store: db, Managed: &scim.ManagedOptions{MaxActiveCredentials: 3, CredentialHashSecret: "managed-local-fixture-credential-digest-secret"}})
	if e != nil {
		log.Fatal(e)
	}
	var in input
	if e = json.NewDecoder(os.Stdin).Decode(&in); e != nil {
		log.Fatal(e)
	}
	catalog := directory.Catalog()
	d := scim.Directory{ID: in.ConnectionID, ProvisioningDomainID: in.ProvisioningDomainID}
	p := scim.CredentialPolicy{Scopes: in.Scopes, ExpiresAt: in.ExpiresAt}
	var result any
	switch in.Op {
	case "create":
		result, e = catalog.Create(ctx, in.ProvisioningDomainID, in.CreationRequestID, in.ActorID, p)
	case "rotate":
		result, e = catalog.Rotate(ctx, d, in.ActorID, p)
	case "get":
		result, e = catalog.Get(ctx, d)
	case "list":
		var list []scim.ManagedConnection
		list, e = catalog.List(ctx, in.ProvisioningDomainID)
		result = map[string]any{"connections": list}
	case "events":
		result, e = catalog.Events(ctx, d, scim.EventQuery{Limit: in.Limit, Offset: in.Offset, SortDirection: in.SortDirection})
	case "retire":
		result, e = catalog.Decommission(ctx, d, in.ActorID)
	case "retireDirectory":
		result, e = directory.Decommission(ctx, d)
	case "revoke":
		result, e = catalog.Revoke(ctx, d, in.CredentialID, in.ActorID)
	default:
		log.Fatal("unknown catalog operation")
	}
	if e != nil {
		var typed *scim.Error
		if !errors.As(e, &typed) {
			log.Fatal(e)
		}
		result = map[string]any{"status": typed.Status}
	}
	if e = json.NewEncoder(os.Stdout).Encode(result); e != nil {
		log.Fatal(fmt.Errorf("write fixture: %w", e))
	}
}
