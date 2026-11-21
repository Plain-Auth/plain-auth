package sqlstore

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/go-sql-driver/mysql"
	"github.com/jackc/pgx/v5/pgconn"
	authn "github.com/FineStack/finestack-auth"
)

var _ authn.OAuthStore = (*Store)(nil)

func (s *Store) SaveOAuthFlow(ctx context.Context, flow authn.OAuthFlow, now time.Time) error {
	payload, err := json.Marshal(flow)
	if err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, s.bind(`DELETE FROM "verification" WHERE "identifier" LIKE 'oauth-state:%' AND "expiresAt"<=?`), s.date(now)); err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, s.bind(`INSERT INTO "verification" ("id","identifier","value","expiresAt","createdAt","updatedAt") VALUES (?,?,?,?,?,?)`),
		flow.State, "oauth-state:"+flow.Binding, string(payload), s.date(flow.ExpiresAt), s.date(now), s.date(now))
	if err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) ConsumeOAuthFlow(ctx context.Context, state, binding string, now time.Time) (authn.OAuthFlow, error) {
	var flow authn.OAuthFlow
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return flow, err
	}
	defer tx.Rollback()
	q := `SELECT "value" FROM "verification" WHERE "id"=? AND "identifier"=? AND "expiresAt">?`
	if s.dialect != "sqlite" {
		q += " FOR UPDATE"
	}
	var payload string
	err = tx.QueryRowContext(ctx, s.bind(q), state, "oauth-state:"+binding, s.date(now)).Scan(&payload)
	if errors.Is(err, sql.ErrNoRows) {
		return flow, authn.ErrNotFound
	}
	if err != nil {
		return flow, err
	}
	if err = json.Unmarshal([]byte(payload), &flow); err != nil {
		return flow, err
	}
	if _, err = tx.ExecContext(ctx, s.bind(`DELETE FROM "verification" WHERE "id"=? AND "identifier"=?`), state, "oauth-state:"+binding); err != nil {
		return flow, err
	}
	return flow, tx.Commit()
}

// CompleteOAuth serializes account creation, verified-email linking and session
// issuance. A stable primary key serializes concurrent first logins even on a
// canonical schema with no (providerId, accountId) unique constraint.
func (s *Store) CompleteOAuth(ctx context.Context, provider, subject string, tokens authn.OAuthTokens, candidate authn.User, session authn.StoredSession, options authn.OAuthLoginOptions) (authn.User, bool, error) {
	candidate.Email = strings.ToLower(candidate.Email)
	var u authn.User
	var created bool
	var err error
	for attempt := 0; attempt < 3; attempt++ {
		u, created, err = s.completeOAuth(ctx, provider, subject, tokens, candidate, session, options)
		if !retryIdentity(err) {
			break
		}
	}
	return u, created, err
}

func retryIdentity(err error) bool {
	var my *mysql.MySQLError
	if errors.As(err, &my) {
		return my.Number == 1062 || my.Number == 1213
	}
	var pg *pgconn.PgError
	if errors.As(err, &pg) {
		return pg.Code == "23505" || pg.Code == "40001" || pg.Code == "40P01"
	}
	return false
}

func (s *Store) completeOAuth(ctx context.Context, provider, subject string, tokens authn.OAuthTokens, candidate authn.User, session authn.StoredSession, options authn.OAuthLoginOptions) (authn.User, bool, error) {
	var u authn.User
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return u, false, err
	}
	defer tx.Rollback()
	if options.LinkUserID != "" {
		if !candidate.EmailVerified {
			return u, false, authn.ErrOAuthLinkRequired
		}
		if err := s.lockActiveAccount(ctx, tx, options.LinkUserID, options.LinkSessionToken, session.CreatedAt); err != nil {
			return u, false, err
		}
	}
	if !options.IDTokenValidUntil.IsZero() {
		if !options.IDTokenValidUntil.After(session.CreatedAt) {
			return u, false, authn.ErrIDTokenUsed
		}
		hash := options.IDTokenHash
		if hash == ([32]byte{}) {
			hash = sha256.Sum256([]byte(provider + "\x00" + tokens.IDToken))
		}
		if err := s.claimIDToken(ctx, tx, provider, hash, session.CreatedAt, options.IDTokenValidUntil); err != nil {
			return u, false, err
		}
	}
	if options.OneTapNonce != "" {
		if !options.OneTapExpires.After(session.CreatedAt) {
			return u, false, authn.ErrIDTokenUsed
		}
		if err := s.claimIDToken(ctx, tx, "one-tap-nonce", sha256.Sum256([]byte("one-tap-nonce\x00"+options.OneTapNonce)), session.CreatedAt, options.OneTapExpires); err != nil {
			return u, false, err
		}
	}
	suffix := ""
	if s.dialect != "sqlite" {
		suffix = " FOR UPDATE"
	}
	var account string
	q := `SELECT ` + userColumns + `,a."id" FROM "account" a JOIN "user" u ON u."id"=a."userId" WHERE a."providerId"=? AND a."accountId"=?`
	// MySQL deployments may use case-insensitive collations by default.
	if s.dialect == "mysql" {
		q = `SELECT ` + userColumns + `,a."id" FROM "account" a JOIN "user" u ON u."id"=a."userId" WHERE BINARY a."providerId"=? AND BINARY a."accountId"=?`
	}
	err = tx.QueryRowContext(ctx, s.bind(q+suffix), provider, subject).Scan(append(userFields(&u), &account)...)
	existing := err == nil
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return u, false, err
	}
	if existing && options.LinkUserID != "" && (u.ID != options.LinkUserID || !strings.EqualFold(u.Email, candidate.Email)) {
		return u, false, authn.ErrOAuthLinkRequired
	}
	created := false
	if !existing {
		err = tx.QueryRowContext(ctx, s.bind(`SELECT `+userColumns+` FROM "user" u WHERE u."email"=?`+suffix), candidate.Email).Scan(userFields(&u)...)
		switch {
		case errors.Is(err, sql.ErrNoRows):
			if options.LinkUserID != "" {
				return u, false, authn.ErrOAuthLinkRequired
			}
			if options.DisableSignUp {
				return u, false, authn.ErrOAuthSignupDisabled
			}
			u = candidate
			created = true
			_, err = tx.ExecContext(ctx, s.bind(`INSERT INTO "user" ("id","email","name","image","emailVerified","createdAt","updatedAt") VALUES (?,?,?,?,?,?,?)`), u.ID, u.Email, u.Name, u.Image, u.EmailVerified, s.date(u.CreatedAt), s.date(u.UpdatedAt))
			if err != nil {
				return u, false, err
			}
		case err != nil:
			return u, false, err
		case options.LinkUserID != "" && u.ID != options.LinkUserID:
			return u, false, authn.ErrOAuthLinkRequired
		case options.LinkUserID == "" && (!options.AllowVerifiedEmailLink || !u.EmailVerified || !candidate.EmailVerified):
			return u, false, authn.ErrOAuthLinkRequired
		}
		key := sha256.Sum256([]byte(provider + "\x00" + subject))
		account = hex.EncodeToString(key[:16])
	}
	var expires, refreshExpires any
	if !tokens.RefreshExpiresAt.IsZero() {
		refreshExpires = s.date(tokens.RefreshExpiresAt)
	}
	if !tokens.ExpiresAt.IsZero() {
		expires = s.date(tokens.ExpiresAt)
	}
	if existing {
		_, err = tx.ExecContext(ctx, s.bind(`UPDATE "account" SET "accessToken"=COALESCE(NULLIF(?,''),"accessToken"),"refreshToken"=COALESCE(NULLIF(?,''),"refreshToken"),"idToken"=COALESCE(NULLIF(?,''),"idToken"),"scope"=COALESCE(NULLIF(?,''),"scope"),"accessTokenExpiresAt"=CASE WHEN ?='' THEN "accessTokenExpiresAt" ELSE ? END,"refreshTokenExpiresAt"=COALESCE(?,"refreshTokenExpiresAt"),"updatedAt"=? WHERE "id"=?`),
			tokens.AccessToken, tokens.RefreshToken, tokens.IDToken, tokens.Scope, tokens.AccessToken, expires, refreshExpires, s.date(session.CreatedAt), account)
	} else {
		_, err = tx.ExecContext(ctx, s.bind(`INSERT INTO "account" ("id","accountId","providerId","userId","accessToken","refreshToken","idToken","scope","accessTokenExpiresAt","refreshTokenExpiresAt","createdAt","updatedAt") VALUES (?,?,?,?,NULLIF(?,''),NULLIF(?,''),NULLIF(?,''),NULLIF(?,''),?,?,?,?)`),
			account, subject, provider, u.ID, tokens.AccessToken, tokens.RefreshToken, tokens.IDToken, tokens.Scope, expires, refreshExpires, s.date(session.CreatedAt), s.date(session.CreatedAt))
	}
	if err != nil {
		return u, false, err
	}
	session.UserID = u.ID
	if options.LinkUserID == "" {
		if err := s.insertSession(ctx, tx, session); err != nil {
			return u, false, err
		}
	}
	return u, created, tx.Commit()
}

func (s *Store) claimIDToken(ctx context.Context, tx *sql.Tx, provider string, hash [32]byte, now, expires time.Time) error {
	if _, err := tx.ExecContext(ctx, s.bind(`DELETE FROM "verification" WHERE "identifier"='consumed-id-token' AND "expiresAt"<=?`), s.date(now)); err != nil {
		return err
	}
	id := "oid-" + hex.EncodeToString(hash[:16])
	q := `INSERT INTO "verification" ("id","identifier","value","expiresAt","createdAt","updatedAt") VALUES (?,'consumed-id-token',?,?,?,?)`
	if s.dialect != "mysql" {
		q += ` ON CONFLICT("id") DO NOTHING`
	}
	result, err := tx.ExecContext(ctx, s.bind(q), id, provider, s.date(expires), s.date(now), s.date(now))
	if err != nil {
		var my *mysql.MySQLError
		if errors.As(err, &my) && my.Number == 1062 {
			return authn.ErrIDTokenUsed
		}
		return err
	}
	n, err := result.RowsAffected()
	if err == nil && n == 0 {
		return authn.ErrIDTokenUsed
	}
	return err
}
