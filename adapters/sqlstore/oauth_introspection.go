package sqlstore

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"

	op "github.com/Plain-Auth/plain-auth/plugins/oauthprovider"
)

var _ op.MachineIntrospectionStore = (*Store)(nil)

func (s *Store) InspectMachineToken(ctx context.Context, clientID, digest string) (op.MachineClient, *op.MachineTokenRecord, error) {
	client, record, _, err := s.InspectOpaqueMachineToken(ctx, clientID, digest)
	return client, record, err
}

func (s *Store) InspectOpaqueMachineToken(ctx context.Context, clientID, digest string) (op.MachineClient, *op.MachineTokenRecord, bool, error) {
	// Keep credential rotation, deletion, revocation and token ownership in one
	// snapshot. Delegated and sender-constrained tokens need additional checks.
	const query = `SELECT c."id",c."clientId",c."clientSecret",c."tokenEndpointAuthMethod",c."disabled",c."jwks",c."jwksUri",
		t."token",t."clientId",t."createdAt",t."expiresAt",t."scopes",t."resources",
		(t."revoked" IS NULL AND t."sessionId" IS NULL AND t."userId" IS NULL AND t."refreshId" IS NULL
		AND t."authorizationCodeId" IS NULL AND t."referenceId" IS NULL AND t."confirmation" IS NULL AND t."requestedUserInfoClaims" IS NULL)
		FROM "oauthClient" c LEFT JOIN "oauthAccessToken" t ON t."token"=?
		WHERE c."clientId"=? AND (c."clientDiscoveryId" IS NULL OR c."clientDiscoveryId"='')`
	var client op.MachineClient
	var secret, method, stored, owner, jwks, uri sql.NullString
	var eligible bool
	var disabled sql.NullBool
	var issued, expires sql.NullTime
	var scopes, resources []byte
	err := s.db.QueryRowContext(ctx, s.bind(query), digest, clientID).Scan(
		&client.RowID, &client.ClientID, &secret, &method, &disabled, &jwks, &uri, &stored, &owner, &issued, &expires, &scopes, &resources, &eligible)
	if errors.Is(err, sql.ErrNoRows) || err == nil && client.ClientID != clientID {
		return op.MachineClient{}, nil, false, op.ErrClientNotFound
	}
	if err != nil {
		return op.MachineClient{}, nil, false, err
	}
	client.StoredSecret, client.AuthMethod, client.Disabled = secret.String, method.String, disabled.Bool
	client.JWKS, client.JWKSURI = jwks.String, uri.String
	if digest == "" || stored.String != digest {
		return client, nil, false, nil
	}
	if !eligible || owner.String != clientID || !issued.Valid || !expires.Valid {
		return client, nil, true, nil
	}
	if resources != nil {
		var targets []string
		if err := json.Unmarshal(resources, &targets); err != nil {
			return client, nil, true, err
		}
		if len(targets) > 0 {
			return client, nil, true, nil
		}
	}
	token := op.MachineTokenRecord{StoredToken: stored.String, IssuedAt: issued.Time, ExpiresAt: expires.Time}
	if err := json.Unmarshal(scopes, &token.Scopes); err != nil {
		return client, nil, true, err
	}
	return client, &token, true, nil
}
