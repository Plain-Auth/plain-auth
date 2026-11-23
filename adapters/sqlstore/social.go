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

	authn "github.com/Plain-Org/plain-auth"
	"github.com/go-sql-driver/mysql"
	"github.com/jackc/pgx/v5/pgconn"
)

var _ authn.OAuthStore = (*Store)(nil)
var _ authn.OAuthLinkRefreshStore = (*Store)(nil)
var _ authn.OAuthProfileSyncStore = (*Store)(nil)
var _ authn.OAuthVerifiedEmailStore = (*Store)(nil)

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
	return s.completeOAuthWith(ctx, provider, subject, tokens, candidate, session, options, nil, false, nil)
}

func (s *Store) CompleteOAuthRegistration(ctx context.Context, provider, subject string, tokens authn.OAuthTokens, candidate authn.User, session authn.StoredSession, options authn.OAuthLoginOptions, fields authn.OAuthRegistrationFields) (authn.User, bool, error) {
	if fields == nil || options.LinkUserID != "" {
		return authn.User{}, false, errors.New("sqlstore: invalid OAuth registration")
	}
	return s.completeOAuthWith(ctx, provider, subject, tokens, candidate, session, options, nil, false, &authn.OAuthProfileFields{Create: fields})
}

func (s *Store) CompleteOAuthProfile(ctx context.Context, provider, subject string, tokens authn.OAuthTokens, candidate authn.User, session authn.StoredSession, options authn.OAuthLoginOptions, fields authn.OAuthProfileFields) (authn.User, bool, error) {
	if options.LinkUserID != "" || fields.Create == nil || fields.Update == nil {
		return authn.User{}, false, errors.New("sqlstore: invalid OAuth profile sync")
	}
	return s.completeOAuthWith(ctx, provider, subject, tokens, candidate, session, options, nil, false, &fields)
}

func (s *Store) CompleteOAuthVerifiedEmail(ctx context.Context, provider, subject string, tokens authn.OAuthTokens, candidate authn.User, session authn.StoredSession, options authn.OAuthLoginOptions, fields authn.OAuthProfileFields) (authn.User, bool, error) {
	if options.LinkUserID != "" || fields.Create == nil {
		return authn.User{}, false, errors.New("sqlstore: invalid verified-email sign-in")
	}
	options.RequireEmailVerification = true
	return s.completeOAuthWith(ctx, provider, subject, tokens, candidate, session, options, nil, false, &fields)
}

// RefreshOwnedOAuthLink can only update an existing provider identity, even if
// another request unlinks or reassigns the identity during the exchange.
func (s *Store) RefreshOwnedOAuthLink(ctx context.Context, provider, subject string, tokens authn.OAuthTokens, candidate authn.User, session authn.StoredSession, options authn.OAuthLoginOptions) (authn.User, bool, error) {
	if options.LinkUserID == "" || options.LinkSessionToken == "" {
		return authn.User{}, false, authn.ErrOAuthLinkingDisabled
	}
	return s.completeOAuthWith(ctx, provider, subject, tokens, candidate, session, options, nil, true, nil)
}

type oauthTransactionHooks struct {
	authority        oauthAuthority
	trustEmailDomain bool
	guard            func(*sql.Tx) error
	afterIdentity    func(*sql.Tx, authn.User) error
}

func (s *Store) completeOAuthWith(ctx context.Context, provider, subject string, tokens authn.OAuthTokens, candidate authn.User, session authn.StoredSession, options authn.OAuthLoginOptions, hooks *oauthTransactionHooks, existingOnly bool, fields *authn.OAuthProfileFields) (authn.User, bool, error) {
	candidate.Email = strings.ToLower(candidate.Email)
	var u authn.User
	var created bool
	var err error
	for attempt := 0; attempt < 3; attempt++ {
		u, created, err = s.completeOAuth(ctx, provider, subject, tokens, candidate, session, options, hooks, existingOnly, fields)
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

func (s *Store) completeOAuth(ctx context.Context, provider, subject string, tokens authn.OAuthTokens, candidate authn.User, session authn.StoredSession, options authn.OAuthLoginOptions, hooks *oauthTransactionHooks, existingOnly bool, fields *authn.OAuthProfileFields) (authn.User, bool, error) {
	var u authn.User
	var txOptions *sql.TxOptions
	if hooks != nil && s.dialect != "sqlite" {
		txOptions = &sql.TxOptions{Isolation: sql.LevelReadCommitted}
	}
	tx, err := s.db.BeginTx(ctx, txOptions)
	if err != nil {
		return u, false, err
	}
	defer tx.Rollback()
	authn.LoginPlanFrom(ctx).Attempt()
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
	var accountCreated time.Time
	var storedScope sql.NullString
	q := `SELECT ` + userColumns + `,a."id",a."createdAt",a."scope" FROM "account" a JOIN "user" u ON u."id"=a."userId" WHERE `
	q += s.exactSQLValue(`a."providerId"`) + "=? AND " + s.exactSQLValue(`a."accountId"`) + "=?"
	err = tx.QueryRowContext(ctx, s.bind(q+suffix), provider, subject).Scan(append(userFields(&u), &account, &accountCreated, &storedScope)...)
	existing := err == nil
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return u, false, err
	}
	if existingOnly {
		if !existing {
			return u, false, authn.ErrOAuthLinkingDisabled
		}
		if u.ID != options.LinkUserID {
			return u, false, authn.ErrOAuthAccountAlreadyLinked
		}
	}
	if existing && options.LinkUserID != "" && (u.ID != options.LinkUserID || !strings.EqualFold(u.Email, candidate.Email)) {
		return u, false, authn.ErrOAuthLinkRequired
	}
	created := false
	emailLink := false
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
			var values authn.UserFieldValues
			if fields != nil {
				values, err = fields.Create()
				if err != nil {
					return u, false, err
				}
			}
			if err := authn.LoginPlanFrom(ctx).PlanUser(&u); err != nil {
				return u, false, err
			}
			query, args := s.userInsert(u, values.Columns())
			_, err = tx.ExecContext(ctx, s.bind(query), args...)
			if err != nil {
				return u, false, err
			}
		case err != nil:
			return u, false, err
		case options.LinkUserID != "" && u.ID != options.LinkUserID:
			return u, false, authn.ErrOAuthLinkRequired
		case options.LinkUserID == "":
			emailLink = true
		}
		key := sha256.Sum256([]byte(provider + "\x00" + subject))
		account = hex.EncodeToString(key[:16])
	}
	// Membership and account deletion take user locks before locking the tenant.
	// Recheck the directory under lock before writing its account or session.
	if hooks != nil {
		if err := hooks.guard(tx); err != nil {
			return u, false, err
		}
	}
	if emailLink && (options.DisableImplicitLinking || strings.ToLower(u.Email) != candidate.Email || !u.EmailVerified || (!(options.AllowVerifiedEmailLink && candidate.EmailVerified) && !(hooks != nil && hooks.trustEmailDomain))) {
		return u, false, authn.ErrOAuthLinkRequired
	}
	authority := socialAuthority
	if hooks != nil {
		authority = hooks.authority
	}
	if !existing {
		accountCreated = session.CreatedAt
	}
	identity := oauthIdentity{ID: account, UserID: u.ID, ProviderID: provider, Subject: subject, CreatedMS: accountCreated.UnixMilli()}
	if existing {
		if err = s.requireAccountSource(ctx, tx, identity, authority); err != nil {
			return u, false, err
		}
	}
	var expires, refreshExpires any
	if !tokens.RefreshExpiresAt.IsZero() {
		refreshExpires = s.date(tokens.RefreshExpiresAt)
	}
	if !tokens.ExpiresAt.IsZero() {
		expires = s.date(tokens.ExpiresAt)
	}
	switch {
	case !existing:
		err = s.insertAccount(ctx, tx, `"id","accountId","providerId","userId","accessToken","refreshToken","idToken","scope","accessTokenExpiresAt","refreshTokenExpiresAt","createdAt","updatedAt"`, `?,?,?,?,NULLIF(?,''),NULLIF(?,''),NULLIF(?,''),NULLIF(?,''),?,?,?,?`,
			[]any{account, subject, provider, u.ID, tokens.AccessToken, tokens.RefreshToken, tokens.IDToken, tokens.Scope, expires, refreshExpires, s.date(session.CreatedAt), s.date(session.CreatedAt)}, options.AccountFields)
	case options.LinkUserID != "" || !options.DisableAccountUpdateOnSignIn:
		var scope any
		if options.LinkUserID != "" && tokens.Scope != "" {
			scope = mergeGrantedScopes(storedScope.String, tokens.Scope)
		}
		extra, values, fieldErr := s.accountFieldUpdates(options.AccountFields)
		if fieldErr != nil {
			return u, false, fieldErr
		}
		q := `UPDATE "account" SET "accessToken"=COALESCE(NULLIF(?,''),"accessToken"),"refreshToken"=COALESCE(NULLIF(?,''),"refreshToken"),"idToken"=COALESCE(NULLIF(?,''),"idToken"),"scope"=COALESCE(?,"scope"),"accessTokenExpiresAt"=COALESCE(?,"accessTokenExpiresAt"),"refreshTokenExpiresAt"=COALESCE(?,"refreshTokenExpiresAt"),"updatedAt"=?`
		args := []any{tokens.AccessToken, tokens.RefreshToken, tokens.IDToken, scope, expires, refreshExpires, s.date(session.CreatedAt)}
		args = append(args, values...)
		_, err = tx.ExecContext(ctx, s.bind(q+extra+` WHERE "id"=?`), append(args, account)...)
	}
	if err != nil {
		return u, false, err
	}
	if !existing {
		if err = s.writeAccountSource(ctx, tx, identity, authority); err != nil {
			return u, false, err
		}
	}
	if !created && fields != nil && fields.Update != nil {
		values, err := fields.Update()
		if err != nil {
			return u, false, err
		}
		u, err = s.syncOAuthProfile(ctx, tx, u, candidate, values, session.CreatedAt)
		if err != nil {
			return u, false, err
		}
	}
	if options.RequireEmailVerification && options.LinkUserID == "" && !u.EmailVerified {
		if !candidate.EmailVerified || strings.ToLower(u.Email) != candidate.Email {
			if err := authn.LoginPlanFrom(ctx).Commit(); err != nil {
				return authn.User{}, false, err
			}
			if err := tx.Commit(); err != nil {
				return authn.User{}, false, err
			}
			return u, created, authn.ErrOAuthEmailUnverified
		}
		// A verified claim for this owner's current mailbox also satisfies the
		// gate when the host keeps name and other profile fields locally.
		_, err := tx.ExecContext(ctx, s.bind(`UPDATE "user" SET "emailVerified"=?,"updatedAt"=? WHERE "id"=?`), true, s.date(session.CreatedAt), u.ID)
		if err != nil {
			return authn.User{}, false, err
		}
		u.EmailVerified, u.UpdatedAt = true, session.CreatedAt
	}
	if hooks != nil {
		if err := hooks.afterIdentity(tx, u); err != nil {
			return u, false, err
		}
	}
	session.UserID = u.ID
	if options.LinkUserID == "" {
		if err := s.insertSession(ctx, tx, session); err != nil {
			return u, false, err
		}
	}
	if err := authn.LoginPlanFrom(ctx).Commit(); err != nil {
		return u, false, err
	}
	return u, created, tx.Commit()
}

// Explicit reauthorization can extend a grant. Preserve the original ordering.
func mergeGrantedScopes(stored, incoming string) string {
	var scopes []string
	seen := make(map[string]bool)
	for item := range strings.SplitSeq(stored+","+incoming, ",") {
		scope := strings.TrimSpace(item)
		if scope != "" && !seen[scope] {
			scopes = append(scopes, scope)
			seen[scope] = true
		}
	}
	return strings.Join(scopes, ",")
}

// The caller locks and authorizes the exact owner before applying provider data.
func (s *Store) syncOAuthProfile(ctx context.Context, tx *sql.Tx, owner, candidate authn.User, values authn.UserFieldValues, now time.Time) (authn.User, error) {
	owner.EmailVerified = candidate.EmailVerified || (strings.ToLower(owner.Email) == candidate.Email && owner.EmailVerified)
	owner.Email = candidate.Email
	owner.UpdatedAt = now
	if candidate.Name != "" {
		owner.Name = candidate.Name
	}
	if candidate.Image != nil {
		owner.Image = candidate.Image
	}
	fields := []string{`"name"=?`, `"image"=?`, `"email"=?`, `"emailVerified"=?`, `"updatedAt"=?`}
	args := []any{owner.Name, owner.Image, owner.Email, owner.EmailVerified, s.date(now)}
	fields, args = s.appendUserFieldUpdates(fields, args, values.Columns())
	args = append(args, owner.ID)
	_, err := tx.ExecContext(ctx, s.bind(`UPDATE "user" SET `+strings.Join(fields, ",")+` WHERE "id"=?`), args...)
	if duplicateConstraint(err) {
		return authn.User{}, authn.ErrOAuthProfileConflict
	}
	return owner, err
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
