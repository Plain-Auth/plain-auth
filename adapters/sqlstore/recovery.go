package sqlstore

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"

	authn "github.com/Plain-Auth/plain-auth"
)

var _ authn.AccountStore = (*Store)(nil)

func (s *Store) FindAccountUser(ctx context.Context, email string) (authn.User, error) {
	var u authn.User
	err := s.db.QueryRowContext(ctx, s.bind(`SELECT `+userColumns+` FROM "user" u WHERE u."email"=?`), strings.ToLower(email)).Scan(userFields(&u)...)
	if errors.Is(err, sql.ErrNoRows) {
		err = authn.ErrNotFound
	}
	return u, err
}

func (s *Store) UpdateProfile(ctx context.Context, userID string, patch authn.ProfileUpdate, now time.Time) error {
	return s.updateProfile(ctx, s.db, userID, patch, now)
}

func (s *Store) updateProfile(ctx context.Context, db executor, userID string, patch authn.ProfileUpdate, now time.Time) error {
	fields := []string{`"updatedAt" = ?`}
	args := []any{s.date(now)}
	if patch.Name != nil {
		fields = append(fields, `"name" = ?`)
		args = append(args, *patch.Name)
	}
	if patch.ClearImage {
		fields = append(fields, `"image" = NULL`)
	} else if patch.Image != nil {
		fields = append(fields, `"image" = ?`)
		args = append(args, *patch.Image)
	}
	if patch.ClearUsername {
		fields = append(fields, `"username" = NULL`)
	} else if patch.Username != nil {
		fields = append(fields, `"username"=?`)
		args = append(args, *patch.Username)
	}
	if patch.ClearDisplayUsername {
		fields = append(fields, `"displayUsername" = NULL`)
	} else if patch.DisplayUsername != nil {
		fields = append(fields, `"displayUsername"=?`)
		args = append(args, *patch.DisplayUsername)
	}
	if patch.ClearPhoneNumber {
		fields = append(fields, `"phoneNumber"=NULL`, `"phoneNumberVerified"=?`)
		args = append(args, false)
	}
	fields, args = s.appendUserFieldUpdates(fields, args, patch.PhysicalUserFields())
	args = append(args, userID)
	_, err := db.ExecContext(ctx, s.bind(`UPDATE "user" SET `+strings.Join(fields, ", ")+` WHERE "id" = ?`), args...)
	if patch.Username != nil && duplicateConstraint(err) {
		return authn.ErrUsernameTaken
	}
	return err
}

// Lock the owning user before checking or changing a credential. This also
// serializes the creation of a credential for an account that used social login.
func (s *Store) lockAccount(ctx context.Context, tx *sql.Tx, userID string) error {
	query := `SELECT "id" FROM "user" WHERE "id" = ?`
	if s.dialect != "sqlite" {
		query += " FOR UPDATE"
	}
	var id string
	err := tx.QueryRowContext(ctx, s.bind(query), userID).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return authn.ErrNotFound
	}
	return err
}

func (s *Store) credentialHash(ctx context.Context, tx *sql.Tx, userID string) (string, error) {
	query := `SELECT "password" FROM "account" WHERE "userId"=? AND "providerId"='credential' AND "accountId"="userId"`
	if s.dialect != "sqlite" {
		query += " FOR UPDATE"
	}
	var hash sql.NullString
	err := tx.QueryRowContext(ctx, s.bind(query), userID).Scan(&hash)
	if errors.Is(err, sql.ErrNoRows) {
		return "", authn.ErrNotFound
	}
	return hash.String, err
}

func (s *Store) CreateCredentialSession(ctx context.Context, expectedHash string, ss authn.StoredSession) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err = s.lockAccount(ctx, tx, ss.UserID); err != nil {
		return err
	}
	if err = s.checkPhoneLogin(ctx, tx, ss.UserID); err != nil {
		return err
	}
	hash, err := s.credentialHash(ctx, tx, ss.UserID)
	if err != nil {
		return err
	}
	hasFactor, err := s.detectFactorSchema(ctx, tx)
	if err != nil {
		return err
	}
	if hasFactor {
		var enabled sql.NullBool
		if err := tx.QueryRowContext(ctx, s.readForUpdate(`SELECT "twoFactorEnabled" FROM "user" WHERE "id"=?`), ss.UserID).Scan(&enabled); err != nil {
			return err
		}
		if enabled.Bool {
			return &authn.APIError{Status: 403, Code: "TWO_FACTOR_REQUIRED", Message: "Two-factor authentication required"}
		}
	}
	if hash != expectedHash {
		return authn.ErrNotFound
	}
	if err = s.insertSession(ctx, tx, ss); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) writeCredential(ctx context.Context, tx *sql.Tx, userID, newHash string, now time.Time) error {
	_, err := tx.ExecContext(ctx, s.bind(`UPDATE "account" SET "password"=?,"updatedAt"=? WHERE "userId"=? AND "providerId"='credential' AND "accountId"="userId"`), newHash, s.date(now), userID)
	return err
}

func (s *Store) ChangeCredential(ctx context.Context, userID, oldHash, newHash string, replacement *authn.StoredSession) error {
	return s.ChangeCredentialForSession(ctx, userID, oldHash, newHash, replacement, "", time.Time{})
}

// ChangeCredentialForSession validates the source session under the account
// lock so a concurrent enrollment or sign-out cannot revive a revoked session.
func (s *Store) ChangeCredentialForSession(ctx context.Context, userID, oldHash, newHash string, replacement *authn.StoredSession, source string, now time.Time) error {
	if replacement != nil && replacement.UserID != userID {
		return errors.New("sqlstore: replacement session has wrong account")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err = s.lockAccount(ctx, tx, userID); err != nil {
		return err
	}
	hash, err := s.credentialHash(ctx, tx, userID)
	if err != nil {
		return err
	}
	if source != "" {
		var owner string
		err := tx.QueryRowContext(ctx, s.readForUpdate(`SELECT "userId" FROM "session" WHERE "token"=? AND "userId"=? AND "expiresAt">?`), source, userID, s.date(now)).Scan(&owner)
		if err != nil {
			return factorRowError(err)
		}
	}
	if hash != oldHash {
		return authn.ErrNotFound
	}
	hasFactor, err := s.detectFactorSchema(ctx, tx)
	if err != nil {
		return err
	}
	if hasFactor {
		if err := s.invalidateFactorChallenges(ctx, tx, userID); err != nil {
			return err
		}
	}
	if err = s.writeCredential(ctx, tx, userID, newHash, time.Now()); err != nil {
		return err
	}
	if replacement != nil {
		if _, err = tx.ExecContext(ctx, s.bind(`DELETE FROM "session" WHERE "userId"=?`), userID); err != nil {
			return err
		}
		if err = s.insertSession(ctx, tx, *replacement); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) SavePasswordResetToken(ctx context.Context, t authn.PasswordResetToken) error {
	_, err := s.db.ExecContext(ctx, s.bind(`INSERT INTO "verification" ("id","identifier","value","expiresAt","createdAt","updatedAt") VALUES (?,?,?,?,?,?)`), t.ID, "reset-password:"+t.Token, t.UserID, s.date(t.ExpiresAt), s.date(t.CreatedAt), s.date(t.CreatedAt))
	return err
}

type rowQuerier interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func (s *Store) findPasswordResetToken(ctx context.Context, db rowQuerier, token string, now time.Time) (authn.PasswordResetToken, error) {
	t := authn.PasswordResetToken{Token: token}
	err := db.QueryRowContext(ctx, s.bind(`SELECT v."id",v."value",u."email",v."expiresAt" FROM "verification" v
	JOIN "user" u ON u."id"=v."value" WHERE v."identifier"=? AND v."expiresAt">?`), "reset-password:"+token, s.date(now)).Scan(&t.ID, &t.UserID, &t.Email, &t.ExpiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		err = authn.ErrNotFound
	}
	return t, err
}

func (s *Store) FindPasswordResetToken(ctx context.Context, token string, now time.Time) (authn.PasswordResetToken, error) {
	return s.findPasswordResetToken(ctx, s.db, token, now)
}

func (s *Store) FinishPasswordReset(ctx context.Context, token, newHash string, now time.Time, revoke bool) error {
	return s.finishPasswordReset(ctx, token, newHash, now, revoke, nil)
}

// FinishPasswordResetWithUser returns the owner selected by the winning reset.
func (s *Store) FinishPasswordResetWithUser(ctx context.Context, token, newHash string, now time.Time, revoke bool) (authn.User, error) {
	var owner authn.User
	err := s.finishPasswordReset(ctx, token, newHash, now, revoke, &owner)
	return owner, err
}

func (s *Store) finishPasswordReset(ctx context.Context, token, newHash string, now time.Time, revoke bool, owner *authn.User) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	t, err := s.findPasswordResetToken(ctx, tx, token, now)
	if err != nil {
		return err
	}
	if err = s.lockAccount(ctx, tx, t.UserID); err != nil {
		return err
	}
	if owner != nil {
		err = tx.QueryRowContext(ctx, s.bind(`SELECT `+userColumns+` FROM "user" u WHERE u."id"=?`), t.UserID).Scan(userFields(owner)...)
		if err != nil {
			return err
		}
	}
	res, err := tx.ExecContext(ctx, s.bind(`DELETE FROM "verification" WHERE "id"=? AND "identifier"=? AND "value"=? AND "expiresAt">?`), t.ID, "reset-password:"+token, t.UserID, s.date(now))
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return authn.ErrNotFound
	}
	if err = s.replaceResetCredential(ctx, tx, t.UserID, newHash, now, revoke); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) replaceResetCredential(ctx context.Context, tx *sql.Tx, id, newHash string, now time.Time, revoke bool) error {
	_, err := s.credentialHash(ctx, tx, id)
	if errors.Is(err, authn.ErrNotFound) {
		err = s.insertPasswordAccount(ctx, tx, id, newHash, now, now)
	} else if err == nil {
		err = s.writeCredential(ctx, tx, id, newHash, now)
	}
	if err != nil {
		return err
	}
	hasFactor, err := s.detectFactorSchema(ctx, tx)
	if err != nil {
		return err
	}
	if hasFactor {
		if err := s.invalidateFactorChallenges(ctx, tx, id); err != nil {
			return err
		}
	}
	if revoke {
		if _, err = tx.ExecContext(ctx, s.bind(`DELETE FROM "session" WHERE "userId"=?`), id); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) VerifyAccountEmail(ctx context.Context, userID, email string, now time.Time) error {
	res, err := s.db.ExecContext(ctx, s.bind(`UPDATE "user" SET "emailVerified"=?,"updatedAt"=? WHERE `+s.exactSQLValue(`"id"`)+`=? AND `+s.exactSQLValue(`LOWER("email")`)+`=? AND "emailVerified"=?`), true, s.date(now), userID, strings.ToLower(email), false)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil || n > 0 {
		return err
	}
	// Replay of a previously successful verification is idempotent. Only the
	// same address on the same account can satisfy the binding.
	u, err := s.FindAccountUser(ctx, email)
	if err != nil {
		return err
	}
	if u.ID != userID || strings.ToLower(u.Email) != strings.ToLower(email) || !u.EmailVerified {
		return authn.ErrNotFound
	}
	return nil
}
