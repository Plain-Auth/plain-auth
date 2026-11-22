package sqlstore

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"

	op "github.com/Plain-Auth/plain-auth/plugins/oauthprovider"
)

var _ op.RefreshIntrospectionStore = (*Store)(nil)

func (s *Store) InspectRefreshToken(ctx context.Context, clientID, digest string) (op.MachineClient, *op.RefreshTokenRecord, error) {
	q := `SELECT c."id",c."clientId",c."clientSecret",c."tokenEndpointAuthMethod",c."disabled",c."jwks",c."jwksUri",
		c."subjectType",c."redirectUris",r."token",r."clientId",r."createdAt",r."expiresAt",r."scopes",r."confirmation",
		u."id",r."sessionId",r."authorizationCodeId",s."expiresAt"
		FROM "oauthClient" c LEFT JOIN "oauthRefreshToken" r ON r."clientId"=c."clientId" AND r."token"=? AND r."revoked" IS NULL
		LEFT JOIN "user" u ON u."id"=` + s.exactSQLValue(`r."userId"`) + `
		LEFT JOIN "session" s ON s."id"=` + s.exactSQLValue(`r."sessionId"`) + ` AND s."userId"=` + s.exactSQLValue(`r."userId"`) + `
		WHERE c."clientId"=? AND (c."clientDiscoveryId" IS NULL OR c."clientDiscoveryId"='')`
	var c op.MachineClient
	var secret, method, jwks, uri, subject, stored, owner, user, session, code sql.NullString
	var disabled sql.NullBool
	var issued, expires, sessionEnd sql.NullTime
	var redirects, scopes, confirmation []byte
	err := s.db.QueryRowContext(ctx, s.bind(q), digest, clientID).Scan(&c.RowID, &c.ClientID, &secret, &method, &disabled, &jwks, &uri,
		&subject, &redirects, &stored, &owner, &issued, &expires, &scopes, &confirmation, &user, &session, &code, &sessionEnd)
	if errors.Is(err, sql.ErrNoRows) || err == nil && c.ClientID != clientID {
		return c, nil, op.ErrClientNotFound
	}
	if err != nil {
		return c, nil, err
	}
	c.StoredSecret, c.AuthMethod, c.JWKS, c.JWKSURI, c.Disabled = secret.String, method.String, jwks.String, uri.String, disabled.Bool
	if digest == "" || stored.String != digest || owner.String != clientID || !issued.Valid || !expires.Valid {
		return c, nil, nil
	}
	r := op.RefreshTokenRecord{StoredToken: digest, ClientID: clientID, IssuedAt: issued.Time, ExpiresAt: expires.Time, SubjectType: subject.String,
		SessionID: session.String, AuthorizationCodeID: code.String}
	r.UserID, r.SessionExpiresAt = user.String, sessionEnd.Time
	if subject.String == "pairwise" && len(redirects) > 0 {
		if err := json.Unmarshal(redirects, &r.RedirectURIs); err != nil {
			return c, nil, err
		}
	}
	if len(scopes) > 0 {
		if err := json.Unmarshal(scopes, &r.Scopes); err != nil {
			return c, nil, err
		}
	}
	if len(confirmation) > 0 {
		if err := json.Unmarshal(confirmation, &r.Confirmation); err != nil {
			return c, nil, err
		}
	}
	return c, &r, nil
}
