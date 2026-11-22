package sqlstore

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"errors"

	op "github.com/Plain-Auth/plain-auth/plugins/oauthprovider"
)

var _ op.MachineTokenStore = (*Store)(nil)

const machineClientSelect = `SELECT "id","clientId","clientSecret","tokenEndpointAuthMethod","grantTypes","clientCredentialsScopes","disabled","dpopBoundAccessTokens","metadata","jwks","jwksUri" FROM "oauthClient"` + localClientFilter

func scanMachineClient(row rowScanner, id string) (op.MachineClient, error) {
	var client op.MachineClient
	var secret, method, jwks, uri sql.NullString
	var disabled, dpop sql.NullBool
	var grants, scopes, metadata []byte
	err := row.Scan(&client.RowID, &client.ClientID, &secret, &method, &grants, &scopes, &disabled, &dpop, &metadata, &jwks, &uri)
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
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(metadata, &fields); err != nil {
			return op.MachineClient{}, err
		}
		client.RequireDPoP = client.RequireDPoP || string(fields["dpop_bound_access_tokens"]) == "true"
	}
	return client, nil
}

func (s *Store) LookupMachineClient(ctx context.Context, id string) (op.MachineClient, error) {
	return scanMachineClient(s.db.QueryRowContext(ctx, s.bind(machineClientSelect), id), id)
}

func (s *Store) StoreMachineToken(ctx context.Context, id string, prepare func(op.MachineClient) (op.MachineTokenRecord, error)) error {
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
	scopes, err := json.Marshal(record.Scopes)
	if err != nil {
		return err
	}
	const insert = `INSERT INTO "oauthAccessToken" ("id","token","clientId","scopes","createdAt","expiresAt") VALUES (?,?,?,?,?,?)`
	if _, err := tx.ExecContext(ctx, s.bind(insert), rand.Text(), record.StoredToken, id, string(scopes), s.date(record.IssuedAt), s.date(record.ExpiresAt)); err != nil {
		return err
	}
	return tx.Commit()
}
