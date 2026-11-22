package sqlstore

import (
	"context"
	"database/sql"
	"errors"

	auth "github.com/Plain-Auth/plain-auth"
	op "github.com/Plain-Auth/plain-auth/plugins/oauthprovider"
)

var _ op.UserInfoStore = (*Store)(nil)

// LookupOAuthUserInfo reads authorization, subject and profile in one snapshot.
func (s *Store) LookupOAuthUserInfo(ctx context.Context, query op.UserInfoLookup) (*op.UserInfoRecord, error) {
	tx, err := s.beginIntrospectionSnapshot(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	var result op.UserInfoRecord
	var subject, clientID string
	if query.SignedGrant != nil {
		grant := *query.SignedGrant
		client, err := s.readSignedGrant(ctx, tx, grant.ClientID, query.Endpoint, grant)
		if err != nil || client == nil {
			return nil, err
		}
		result.Issuer = *client
		subject, clientID = query.Subject, grant.ClientID
	} else {
		if query.Digest == "" {
			return nil, nil
		}
		grant, _, err := s.readOpaqueGrant(ctx, tx, nil, query.Digest, query.Endpoint)
		if err != nil || grant == nil {
			return nil, err
		}
		result.Opaque = grant
		result.Issuer = op.SignedGrantClient{SubjectType: grant.SubjectType, RedirectURIs: grant.RedirectURIs}
		subject, clientID = grant.UserID, grant.ClientID
	}
	if subject != "" {
		var user auth.User
		q := `SELECT ` + userColumns + ` FROM "user" u WHERE u."id"=` + s.exactSQLValue("?")
		err := tx.QueryRowContext(ctx, s.bind(q), subject).Scan(userFields(&user)...)
		if err == nil {
			result.User = &user
		} else if !errors.Is(err, sql.ErrNoRows) {
			return nil, err
		}
	}
	if query.IncludeClient {
		client, err := scanClientDetails(tx.QueryRowContext(ctx, s.bind(clientDetailsSelect+localClientFilter), clientID))
		if err != nil {
			return nil, err
		}
		if client.ClientID != clientID {
			return nil, nil
		}
		result.Client = &client
	}
	return &result, tx.Commit()
}
