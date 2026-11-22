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
	// Keep credential rotation, deletion, revocation and token ownership in one
	// snapshot. Delegated and sender-constrained tokens need additional checks.
	const query = `SELECT c."id",c."clientId",c."clientSecret",c."tokenEndpointAuthMethod",c."disabled",
		t."token",t."clientId",t."createdAt",t."expiresAt",t."scopes",t."resources"
		FROM "oauthClient" c LEFT JOIN "oauthAccessToken" t
		ON t."clientId"=c."clientId" AND t."token"=? AND t."revoked" IS NULL
		AND t."sessionId" IS NULL AND t."userId" IS NULL AND t."refreshId" IS NULL
		AND t."authorizationCodeId" IS NULL AND t."referenceId" IS NULL
		AND t."confirmation" IS NULL AND t."requestedUserInfoClaims" IS NULL
		WHERE c."clientId"=? AND (c."clientDiscoveryId" IS NULL OR c."clientDiscoveryId"='')`
	var client op.MachineClient
	var secret, method, stored, owner sql.NullString
	var disabled sql.NullBool
	var issued, expires sql.NullTime
	var scopes, resources []byte
	err := s.db.QueryRowContext(ctx, s.bind(query), digest, clientID).Scan(
		&client.RowID, &client.ClientID, &secret, &method, &disabled, &stored, &owner, &issued, &expires, &scopes, &resources)
	if errors.Is(err, sql.ErrNoRows) || err == nil && client.ClientID != clientID {
		return op.MachineClient{}, nil, op.ErrClientNotFound
	}
	if err != nil {
		return op.MachineClient{}, nil, err
	}
	client.StoredSecret, client.AuthMethod, client.Disabled = secret.String, method.String, disabled.Bool
	if digest == "" || stored.String != digest || owner.String != clientID || !issued.Valid || !expires.Valid {
		return client, nil, nil
	}
	if resources != nil {
		var targets []string
		if err := json.Unmarshal(resources, &targets); err != nil {
			return client, nil, err
		}
		if len(targets) > 0 {
			return client, nil, nil
		}
	}
	token := op.MachineTokenRecord{StoredToken: stored.String, IssuedAt: issued.Time, ExpiresAt: expires.Time}
	if err := json.Unmarshal(scopes, &token.Scopes); err != nil {
		return client, nil, err
	}
	return client, &token, nil
}
