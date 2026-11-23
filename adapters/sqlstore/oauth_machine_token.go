package sqlstore

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"errors"

	op "github.com/Plain-Org/plain-auth/plugins/oauthprovider"
)

var _ op.MachineTokenStore = (*Store)(nil)
var _ op.DPoPMachineTokenStore = (*Store)(nil)

const machineClientColumns = `"id","clientId","clientSecret","tokenEndpointAuthMethod","grantTypes","clientCredentialsScopes","disabled","dpopBoundAccessTokens","metadata","jwks","jwksUri"`
const machineClientSelect = "SELECT " + machineClientColumns + ` FROM "oauthClient"` + localClientFilter

func scanMachineClient(row rowScanner, id string, extra ...any) (op.MachineClient, error) {
	var client op.MachineClient
	var secret, method, jwks, uri sql.NullString
	var disabled, dpop sql.NullBool
	var grants, scopes, metadata []byte
	fields := []any{&client.RowID, &client.ClientID, &secret, &method, &grants, &scopes, &disabled, &dpop, &metadata, &jwks, &uri}
	err := row.Scan(append(fields, extra...)...)
	if errors.Is(err, sql.ErrNoRows) || err == nil && client.ClientID != id {
		return op.MachineClient{}, op.ErrClientNotFound
	}
	if err != nil {
		return op.MachineClient{}, err
	}
	client.StoredSecret, client.AuthMethod = secret.String, method.String
	client.JWKS, client.JWKSURI = jwks.String, uri.String
	client.Disabled, client.RequireDPoP = disabled.Bool, dpop.Bool
	if grants != nil {
		if err := json.Unmarshal(grants, &client.GrantTypes); err != nil {
			return op.MachineClient{}, err
		}
	}
	if scopes != nil {
		if err := json.Unmarshal(scopes, &client.MachineScopes); err != nil {
			return op.MachineClient{}, err
		}
	}
	if len(metadata) > 0 {
		client.Metadata, err = op.DecodeClientMetadata(metadata)
		if err != nil {
			return op.MachineClient{}, err
		}
		client.RequireDPoP = client.RequireDPoP || string(client.Metadata["dpop_bound_access_tokens"]) == "true"
	}
	return client, nil
}

func (s *Store) LookupMachineClient(ctx context.Context, id string) (op.MachineClient, error) {
	return scanMachineClient(s.db.QueryRowContext(ctx, s.bind(machineClientSelect), id), id)
}

func (s *Store) StoreMachineToken(ctx context.Context, id string, prepare func(op.MachineClient) (op.MachineTokenRecord, error)) error {
	return s.storeMachineToken(ctx, id, "", prepare)
}

// StoreDPoPMachineToken stores cnf.jkt together with the new token so readers
// can never observe the credential without its sender constraint.
func (s *Store) StoreDPoPMachineToken(ctx context.Context, id, thumbprint string, prepare func(op.MachineClient) (op.MachineTokenRecord, error)) error {
	if thumbprint == "" {
		return errors.New("sqlstore: missing DPoP thumbprint")
	}
	return s.storeMachineToken(ctx, id, thumbprint, prepare)
}

func (s *Store) storeMachineToken(ctx context.Context, id, thumbprint string, prepare func(op.MachineClient) (op.MachineTokenRecord, error)) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	client, err := scanMachineClient(tx.QueryRowContext(ctx, s.readForUpdate(machineClientSelect), id), id)
	if err != nil {
		return err
	}
	record, err := prepare(client)
	if err != nil {
		return err
	}
	if err := s.insertMachineToken(ctx, tx, id, op.ResourceMachineTokenRecord{MachineTokenRecord: record, Thumbprint: thumbprint}); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) insertMachineToken(ctx context.Context, tx *sql.Tx, id string, record op.ResourceMachineTokenRecord) error {
	scopes, err := json.Marshal(record.Scopes)
	if err != nil {
		return err
	}
	var resources, confirmation sql.NullString
	if len(record.Resources) > 0 {
		raw, err := json.Marshal(record.Resources)
		if err != nil {
			return err
		}
		resources = sql.NullString{String: string(raw), Valid: true}
	}
	if record.Thumbprint != "" {
		raw, err := json.Marshal(map[string]string{"jkt": record.Thumbprint})
		if err != nil {
			return err
		}
		confirmation = sql.NullString{String: string(raw), Valid: true}
	}
	const insert = `INSERT INTO "oauthAccessToken" ("id","token","clientId","scopes","createdAt","expiresAt","confirmation","resources") VALUES (?,?,?,?,?,?,?,?)`
	_, err = tx.ExecContext(ctx, s.bind(insert), rand.Text(), record.StoredToken, id, string(scopes), s.date(record.IssuedAt), s.date(record.ExpiresAt), confirmation, resources)
	return err
}
