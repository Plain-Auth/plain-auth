package oauthprovider

import (
	"context"
	"time"
)

// DiscoveredClient is a stored client row as a client discovery reads it.
// DiscoveryID names the discovery that owns the row, or is empty for a
// client registered locally.
type DiscoveredClient struct {
	ClientDetails
	RowID, DiscoveryID   string
	CreatedAt, UpdatedAt time.Time
}

// DiscoveredClientRecord is a validated metadata document to store for a
// client discovery. Metadata has the provider's defaults applied, and its
// Resources are the default resources to link. Existing is the row a refresh
// started from, or nil to create the client.
type DiscoveredClientRecord struct {
	ID, ClientID, DiscoveryID string
	Metadata                  RegistrationMetadata
	Scopes                    []string
	Existing                  *DiscoveredClient
	Now                       time.Time
}

// DiscoveredClientStore stores the clients a client discovery owns.
type DiscoveredClientStore interface {
	// LookupDiscoveredClient reads any client row by its exact client ID,
	// local or owned by a discovery, or returns ErrClientNotFound.
	LookupDiscoveredClient(ctx context.Context, clientID string) (DiscoveredClient, error)
	// SaveDiscoveredClient creates the client, or replaces only the fields
	// its document owns when the same discovery owns it already, and links
	// each default resource the client lacks, in one transaction. A new row
	// has no owner and no secret. A replacement keeps the server-owned flags,
	// the machine-scope ceiling and createdAt, clears an omitted document
	// field, and keeps a stored subject type the document omits. A client of
	// another source, a local one included, is refused with invalid_client;
	// so is a refresh whose row is gone. A missing or disabled default
	// resource is refused with invalid_target and writes nothing.
	SaveDiscoveredClient(ctx context.Context, record DiscoveredClientRecord) (client DiscoveredClient, created bool, err error)
}
