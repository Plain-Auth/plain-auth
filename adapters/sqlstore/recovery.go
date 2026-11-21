package sqlstore

import (
	"context"
	"crypto/rand"
	"database/sql"
	"errors"
	"strings"
	"time"

	betterauth "github.com/nabuhadba/go-better-auth"
)

var _ betterauth.AccountStore = (*Store)(nil)

func (s *Store) FindAccountUser(ctx context.Context, email string) (betterauth.User, error) {
	var u betterauth.User
	err := s.db.QueryRowContext(ctx, s.bind(`SELECT `+userColumns+` FROM "user" u WHERE u."email"=?`), strings.ToLower(email)).Scan(userFields(&u)...)
	if errors.Is(err, sql.ErrNoRows) {
		err = betterauth.ErrNotFound
	}
	return u, err
}

func (s *Store) UpdateProfile(ctx context.Context, userID string, patch betterauth.ProfileUpdate, now time.Time) error {
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
	args = append(args, userID)
	_, err := s.db.ExecContext(ctx, s.bind(`UPDATE "user" SET `+strings.Join(fields, ", ")+` WHERE "id" = ?`), args...)
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
		return betterauth.ErrNotFound
	}
	return err
}

func (s *Store) credentialHash(ctx context.Context, tx *sql.Tx, userID string) (string, error) {
	query := `SELECT "password" FROM "account" WHERE "userId"=? AND "providerId"='credential'`
	if s.dialect != "sqlite" {
		query += " FOR UPDATE"
	}
	var hash sql.NullString
	err := tx.QueryRowContext(ctx, s.bind(query), userID).Scan(&hash)
	if errors.Is(err, sql.ErrNoRows) {
		return "", betterauth.ErrNotFound
	}
	return hash.String, err
}

func (s *Store) CreateCredentialSession(ctx context.Context, expectedHash string, ss betterauth.StoredSession) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err = s.lockAccount(ctx, tx, ss.UserID); err != nil {
		return err
	}
	hash, err := s.credentialHash(ctx, tx, ss.UserID)
	if err != nil {
		return err
	}
	if hash != expectedHash {
		return betterauth.ErrNotFound
	}
	if err = s.insertSession(ctx, tx, ss); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) writeCredential(ctx context.Context, tx *sql.Tx, userID, newHash string, now time.Time) error {
	_, err := tx.ExecContext(ctx, s.bind(`UPDATE "account" SET "password"=?,"updatedAt"=? WHERE "userId"=? AND "providerId"='credential'`), newHash, s.date(now), userID)
	return err
}

func (s *Store) ChangeCredential(ctx context.Context, userID, oldHash, newHash string, replacement *betterauth.StoredSession) error {
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
	if hash != oldHash {
		return betterauth.ErrNotFound
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

func (s *Store) SavePasswordResetToken(ctx context.Context, t betterauth.PasswordResetToken) error {
	_, err := s.db.ExecContext(ctx, s.bind(`INSERT INTO "verification" ("id","identifier","value","expiresAt","createdAt","updatedAt") VALUES (?,?,?,?,?,?)`), t.ID, "reset-password:"+t.Token, t.UserID, s.date(t.ExpiresAt), s.date(t.CreatedAt), s.date(t.CreatedAt))
	return err
}

type rowQuerier interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func (s *Store) findPasswordResetToken(ctx context.Context, db rowQuerier, token string, now time.Time) (betterauth.PasswordResetToken, error) {
	t := betterauth.PasswordResetToken{Token: token}
	err := db.QueryRowContext(ctx, s.bind(`SELECT v."id",v."value",u."email",v."expiresAt" FROM "verification" v
	JOIN "user" u ON u."id"=v."value" WHERE v."identifier"=? AND v."expiresAt">?`), "reset-password:"+token, s.date(now)).Scan(&t.ID, &t.UserID, &t.Email, &t.ExpiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		err = betterauth.ErrNotFound
	}
	return t, err
}

func (s *Store) FindPasswordResetToken(ctx context.Context, token string, now time.Time) (betterauth.PasswordResetToken, error) {
	return s.findPasswordResetToken(ctx, s.db, token, now)
}

func (s *Store) FinishPasswordReset(ctx context.Context, token, newHash string, now time.Time, revoke bool) error {
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
	res, err := tx.ExecContext(ctx, s.bind(`DELETE FROM "verification" WHERE "id"=? AND "identifier"=? AND "value"=? AND "expiresAt">?`), t.ID, "reset-password:"+token, t.UserID, s.date(now))
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return betterauth.ErrNotFound
	}
	_, err = s.credentialHash(ctx, tx, t.UserID)
	if errors.Is(err, betterauth.ErrNotFound) {
		_, err = tx.ExecContext(ctx, s.bind(`INSERT INTO "account" ("id","userId","providerId","accountId","password","createdAt","updatedAt") VALUES (?,?,'credential',?,?,?,?)`), rand.Text(), t.UserID, t.UserID, newHash, s.date(now), s.date(now))
	} else if err == nil {
		err = s.writeCredential(ctx, tx, t.UserID, newHash, now)
	}
	if err != nil {
		return err
	}
	if revoke {
		if _, err = tx.ExecContext(ctx, s.bind(`DELETE FROM "session" WHERE "userId"=?`), t.UserID); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) VerifyAccountEmail(ctx context.Context, userID, email string, now time.Time) error {
	res, err := s.db.ExecContext(ctx, s.bind(`UPDATE "user" SET "emailVerified"=?,"updatedAt"=? WHERE "id"=? AND "email"=? AND "emailVerified"=?`), true, s.date(now), userID, strings.ToLower(email), false)
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
	if u.ID != userID || !u.EmailVerified {
		return betterauth.ErrNotFound
	}
	return nil
}
