package sqlstore

import (
	"context"
	"database/sql"
	"errors"

	authn "github.com/Plain-Org/plain-auth"
	op "github.com/Plain-Org/plain-auth/plugins/oauthprovider"
)

var _ op.EndSessionStore = (*Store)(nil)

// OAuthLogoutSessionToken returns the token of the session with this ID. A
// row kept after its session ended is not found.
func (s *Store) OAuthLogoutSessionToken(ctx context.Context, sessionID string) (string, error) {
	var token string
	err := s.db.QueryRowContext(ctx, s.bind(`SELECT "token" FROM "session" WHERE "id"=? AND "expiresAt">?`), sessionID, s.date(endedSessionExpiry)).Scan(&token)
	if errors.Is(err, sql.ErrNoRows) {
		return "", authn.ErrNotFound
	}
	return token, err
}
