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
	if s.sweeping() {
		if _, err = tx.ExecContext(ctx, s.bind(`DELETE FROM "verification" WHERE "identifier" LIKE 'oauth-state:%' AND "expiresAt"<=?`), s.date(now)); err != nil {
			return err
		}
	}
	_, err = tx.ExecContext(ctx, s.bind(`INSERT INTO "verification" ("id","identifier","value","expiresAt","createdAt","updatedAt") VALUES (?,?,?,?,?,?)`),
		flow.State, "oauth-state:"+flow.Binding, string(payload), s.date(flow.ExpiresAt), s.date(now), s.date(now))
	if err != nil {
		return err
	}
	return tx.Commit()
}

var _ authn.OAuthFlowFinder = (*Store)(nil)

// FindOAuthFlow reads a live browser OAuth flow without spending it.
func (s *Store) FindOAuthFlow(ctx context.Context, state, binding string, now time.Time) (authn.OAuthFlow, error) {
	var flow authn.OAuthFlow
	var payload string
	err := s.db.QueryRowContext(ctx, s.bind(`SELECT "value" FROM "verification" WHERE "id"=? AND "identifier"=? AND "expiresAt">?`), state, "oauth-state:"+binding, s.date(now)).Scan(&payload)
	if errors.Is(err, sql.ErrNoRows) {
		return flow, authn.ErrNotFound
	}
	if err != nil {
		return flow, err
	}
	return flow, json.Unmarshal([]byte(payload), &flow)
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
	// withSession writes records bound to the session, such as a SAML logout
	// binding, once the session row is stored as planned and before its copy
	// leaves the transaction.
	withSession func(*sql.Tx, authn.User, authn.StoredSession) error
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
	// An ID-token link refreshes an identity the user already owns and refuses
	// one that belongs to someone else first. Every other explicit link, as on
	// the reference's browser path, first needs a verified email or a trusted
	// provider, then a matching email, and only then an identity it may take.
	if options.LinkUserID != "" {
		if !existing || options.IDTokenValidUntil.IsZero() {
			if !candidate.EmailVerified && !options.TrustedProvider {
				return u, false, authn.ErrOAuthLinkNotAllowed
			}
			// The owner row is already locked by lockActiveAccount.
			var owner authn.User
			err = tx.QueryRowContext(ctx, s.bind(`SELECT `+userColumns+` FROM "user" u WHERE u."id"=?`+suffix), options.LinkUserID).Scan(userFields(&owner)...)
			if errors.Is(err, sql.ErrNoRows) {
				return u, false, authn.ErrNotFound
			}
			if err != nil {
				return u, false, err
			}
			if !options.AllowDifferentEmails && !strings.EqualFold(owner.Email, candidate.Email) {
				return u, false, authn.ErrOAuthLinkEmailMismatch
			}
			if !existing {
				u = owner
			}
		}
		if existing && u.ID != options.LinkUserID {
			return u, false, authn.ErrOAuthAccountAlreadyLinked
		}
	}
	created := false
	emailLink := false
	if !existing && options.LinkUserID == "" {
		err = tx.QueryRowContext(ctx, s.bind(`SELECT `+userColumns+` FROM "user" u WHERE u."email"=?`+suffix), candidate.Email).Scan(userFields(&u)...)
		switch {
		case errors.Is(err, sql.ErrNoRows):
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
		default:
			emailLink = true
		}
	}
	if !existing {
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
	// A trusted provider stands in for the provider's verified email. The
	// local email must still be verified.
	if emailLink && (options.DisableImplicitLinking || strings.ToLower(u.Email) != candidate.Email || !u.EmailVerified ||
		(!options.TrustedProvider && !(options.AllowVerifiedEmailLink && candidate.EmailVerified) && !(hooks != nil && hooks.trustEmailDomain))) {
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
	if !created {
		if err := authn.LoginPlanFrom(ctx).PlanIdentity(u.ID, existing); err != nil {
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
	// A profile sync on sign-in already writes everything the link copy would.
	if options.UpdateUserInfoOnLink && (options.LinkUserID != "" || emailLink) && (fields == nil || fields.Update == nil) {
		values, valid := authn.UserFieldValues{}, true
		if options.LinkUserFields != nil {
			values, valid = options.LinkUserFields()
		}
		if valid {
			if u, err = s.applyLinkProfile(ctx, tx, u, candidate, values, session.CreatedAt); err != nil {
				return u, false, err
			}
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
		_, err := s.execUserUpdate(ctx, tx, u.ID, s.bind(`UPDATE "user" SET "emailVerified"=?,"updatedAt"=? WHERE "id"=?`), true, s.date(session.CreatedAt), u.ID)
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
		admin, err := s.insertPlannedSession(ctx, tx, &session)
		if err != nil {
			return u, false, err
		}
		// Records bound to the session take it as stored, with a create
		// hook's edits, and are written before its copy leaves the transaction.
		if hooks != nil && hooks.withSession != nil {
			if err := hooks.withSession(tx, u, session); err != nil {
				return u, false, err
			}
		}
		if err := s.mirrorNewSession(ctx, tx, session, admin); err != nil {
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
	_, err := s.execUserUpdate(ctx, tx, owner.ID, s.bind(`UPDATE "user" SET `+strings.Join(fields, ",")+` WHERE "id"=?`), args...)
	if duplicateConstraint(err) {
		return authn.User{}, authn.ErrOAuthProfileConflict
	}
	return owner, err
}

// applyLinkProfile copies a linked provider's name, image and mapped fields
// onto the locked owner. The email and its verification never change.
func (s *Store) applyLinkProfile(ctx context.Context, tx *sql.Tx, owner, candidate authn.User, values authn.UserFieldValues, now time.Time) (authn.User, error) {
	var fields []string
	var args []any
	if candidate.Name != "" {
		fields, args, owner.Name = append(fields, `"name"=?`), append(args, candidate.Name), candidate.Name
	}
	if candidate.Image != nil {
		fields, args, owner.Image = append(fields, `"image"=?`), append(args, candidate.Image), candidate.Image
	}
	fields, args = s.appendUserFieldUpdates(fields, args, values.Columns())
	if len(fields) == 0 {
		return owner, nil
	}
	fields, args, owner.UpdatedAt = append(fields, `"updatedAt"=?`), append(args, s.date(now)), now
	_, err := s.execUserUpdate(ctx, tx, owner.ID, s.bind(`UPDATE "user" SET `+strings.Join(fields, ",")+` WHERE "id"=?`), append(args, owner.ID)...)
	if duplicateConstraint(err) {
		return authn.User{}, authn.ErrOAuthProfileConflict
	}
	return owner, err
}

func (s *Store) claimIDToken(ctx context.Context, tx *sql.Tx, provider string, hash [32]byte, now, expires time.Time) error {
	id := "oid-" + hex.EncodeToString(hash[:16])
	// An expired claim with this id is replaced; others are swept unless
	// expired verification rows are kept.
	sweep, args := `DELETE FROM "verification" WHERE "identifier"='consumed-id-token' AND "expiresAt"<=?`, []any{s.date(now)}
	if !s.sweeping() {
		sweep, args = `DELETE FROM "verification" WHERE "id"=? AND "expiresAt"<=?`, []any{id, s.date(now)}
	}
	if _, err := tx.ExecContext(ctx, s.bind(sweep), args...); err != nil {
		return err
	}
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
