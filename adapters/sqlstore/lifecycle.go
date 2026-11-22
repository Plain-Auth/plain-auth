package sqlstore

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"

	authn "github.com/Plain-Auth/plain-auth"
)

var _ authn.AccountLifecycleStore = (*Store)(nil)

func (s *Store) lockActiveAccount(ctx context.Context, tx *sql.Tx, userID, token string, now time.Time) error {
	admin, err := s.lockAllowedAccount(ctx, tx, userID, now)
	if err != nil {
		return err
	}
	parameter, _ := s.deviceTokenParameters([]string{token})
	q := `SELECT "id" FROM "session" WHERE "userId"=` + s.exactSQLValue("?") + ` AND "token"=` + parameter + ` AND "expiresAt">?`
	if admin {
		q += ` AND "impersonatedBy" IS NULL`
	}
	if s.dialect != "sqlite" {
		q += " FOR UPDATE"
	}
	var id string
	err = tx.QueryRowContext(ctx, s.bind(q), userID, token, s.date(now)).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return authn.ErrNotFound
	}
	return err
}

func (s *Store) SetInitialPassword(ctx context.Context, userID, sessionToken, newHash string, now time.Time) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := s.lockActiveAccount(ctx, tx, userID, sessionToken, now); err != nil {
		return err
	}
	hash, err := s.credentialHash(ctx, tx, userID)
	switch {
	case errors.Is(err, authn.ErrNotFound):
		err = s.insertPasswordAccount(ctx, tx, userID, newHash, now, now)
	case err != nil:
		return err
	case hash != "":
		return authn.ErrPasswordAlreadySet
	default:
		err = s.writeCredential(ctx, tx, userID, newHash, now)
	}
	if err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) SaveDeletionToken(ctx context.Context, t authn.PasswordResetToken) error {
	_, err := s.db.ExecContext(ctx, s.bind(`INSERT INTO "verification" ("id","identifier","value","expiresAt","createdAt","updatedAt") VALUES (?,?,?,?,?,?)`), t.ID, "delete-account-"+t.Token, t.UserID, s.date(t.ExpiresAt), s.date(t.CreatedAt), s.date(t.CreatedAt))
	return err
}

func (s *Store) DeleteAccount(ctx context.Context, userID, sessionToken, expectedHash, deleteToken string, now time.Time) error {
	tx, err := s.beginMembershipChange(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := s.lockActiveAccount(ctx, tx, userID, sessionToken, now); err != nil {
		return err
	}
	if expectedHash != "" {
		hash, err := s.credentialHash(ctx, tx, userID)
		if err != nil {
			return err
		}
		if hash != expectedHash {
			return authn.ErrNotFound
		}
	}
	if deleteToken != "" {
		result, err := tx.ExecContext(ctx, s.bind(`DELETE FROM "verification" WHERE "identifier"=? AND "value"=? AND "expiresAt">?`), "delete-account-"+deleteToken, userID, s.date(now))
		if err != nil {
			return err
		}
		n, err := result.RowsAffected()
		if err != nil {
			return err
		}
		if n != 1 {
			return authn.ErrNotFound
		}
	}
	if err := s.deleteAccountRows(ctx, tx, userID); err != nil {
		return err
	}
	return tx.Commit()
}

// DeleteFixtureUser removes the supplied user and its dependent records in a test database.
func (s *Store) DeleteFixtureUser(ctx context.Context, id string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err = s.lockAccount(ctx, tx, id); errors.Is(err, authn.ErrNotFound) {
		return nil
	} else if err != nil {
		return err
	}
	if err = s.deleteAccountRows(ctx, tx, id); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) deleteAccountRows(ctx context.Context, tx *sql.Tx, userID string) error {
	if _, err := tx.ExecContext(ctx, s.bind(`DELETE FROM "verification" WHERE "identifier"=?`), sourceOwner(userID)); err != nil {
		return err
	}
	var err error
	// The verification schema also stores plugin state. Remove the two core
	// mail-link families whose value is the user ID, leaving other records alone.
	if _, err = tx.ExecContext(ctx, s.bind(`DELETE FROM "verification" WHERE "value"=? AND ("identifier" LIKE 'delete-account-%' OR "identifier" LIKE 'reset-password:%')`), userID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, s.bind(`DELETE FROM "verification" WHERE "identifier" IN (?,?)`), "anonymous-link:"+userID, "verified-email-proof:"+userID); err != nil {
		return err
	}
	hasFactor, err := s.detectFactorSchema(ctx, tx)
	if err != nil {
		return err
	}
	if hasFactor {
		if _, err = tx.ExecContext(ctx, s.bind(`DELETE FROM "verification" WHERE "identifier"=?`), "2fa-totp-step-"+userID); err != nil {
			return err
		}
		if err := s.invalidateFactorChallenges(ctx, tx, userID); err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, s.bind(`DELETE FROM "twoFactor" WHERE "userId"=?`), userID); err != nil {
			return err
		}
	}
	if _, err := tx.ExecContext(ctx, s.bind(`DELETE FROM "verification" WHERE "identifier" IN (?,?,?,?)`), "stripe-checkout:"+userID, "stripe-sync:"+userID, "stripe-event:"+userID, "stripe-return:"+userID); err != nil {
		return err
	}
	if err := s.cleanupSSOProviders(ctx, tx, userID); err != nil {
		return err
	}
	if err := s.cleanupAPIKeys(ctx, tx, userID); err != nil {
		return err
	}
	if err := s.deleteOwnerWalletAddresses(ctx, tx, userID); err != nil {
		return err
	}
	if err := s.cleanupPasskeys(ctx, tx, userID); err != nil {
		return err
	}
	if err := s.cleanupSCIMAccount(ctx, tx, userID); err != nil {
		return err
	}
	if err := s.cleanupOrganizationAccount(ctx, tx, userID); err != nil {
		return err
	}
	// MySQL accepts the canonical inline REFERENCES syntax without enforcing
	// its cascade. Perform child removal explicitly on every dialect.
	if _, err := s.deleteSessionsTx(ctx, tx, `"userId"=?`, userID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, s.bind(`DELETE FROM "account" WHERE "userId"=?`), userID); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, s.bind(`DELETE FROM "user" WHERE "id"=?`), userID); err != nil {
		return err
	}
	return nil
}

func (s *Store) ChangeAccountEmail(ctx context.Context, userID, oldEmail, newEmail string, verified bool, now time.Time) (authn.User, error) {
	var user authn.User
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return user, err
	}
	defer tx.Rollback()
	if err = s.lockAccount(ctx, tx, userID); err != nil {
		return user, err
	}
	oldEmail, newEmail = strings.ToLower(oldEmail), strings.ToLower(newEmail)
	update := s.bind(`UPDATE "user" SET "email"=?,"updatedAt"=? WHERE "id"=? AND ` + s.exactSQLValue(`LOWER("email")`) + `=? AND "emailVerified"=?`)
	res, err := tx.ExecContext(ctx, update, newEmail, s.date(now), userID, oldEmail, verified)
	if err != nil {
		// PostgreSQL rejects subsequent queries in a failed transaction. Roll
		// it back before determining whether another user claimed the address.
		if rollbackErr := tx.Rollback(); rollbackErr != nil {
			return user, err
		}
		if other, lookupErr := s.FindAccountUser(ctx, newEmail); lookupErr == nil && other.ID != userID {
			return user, authn.ErrEmailTaken
		}
		return user, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return user, err
	}
	if n != 1 {
		return user, authn.ErrNotFound
	}
	err = tx.QueryRowContext(ctx, s.bind(`SELECT `+userColumns+` FROM "user" u WHERE u."id"=?`), userID).Scan(userFields(&user)...)
	if err != nil {
		return user, err
	}
	return user, tx.Commit()
}
