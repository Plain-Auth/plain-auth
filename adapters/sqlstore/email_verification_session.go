package sqlstore

import (
	"context"
	"crypto/rand"
	"database/sql"
	"errors"
	"strings"
	"time"

	auth "github.com/Stonewrit/stonewrit-auth"
)

// CompleteEmailVerification spends the address proof and decides browser
// ownership while holding the verified account's write lock.
func (s *Store) CompleteEmailVerification(ctx context.Context, v auth.EmailVerificationAttempt) (string, error) {
	started := time.Now()
	if v.OwnerID == "" || v.Email == "" || v.ProofID == "" || !v.ExpiresAt.After(v.Now) ||
		v.NewSession != nil && (v.NewSession.UserID != v.OwnerID || v.NewSession.ID == "" || v.NewSession.Token == "" || v.NewSession.Session.RequireOwner() != nil || !v.NewSession.ExpiresAt.After(v.Now)) {
		return "", auth.ErrNotFound
	}
	tx, err := s.beginMembershipChange(ctx)
	if err != nil {
		return "", err
	}
	defer tx.Rollback()
	var id, email string
	var verified bool
	var profileCreated, profileUpdated time.Time
	err = tx.QueryRowContext(ctx, s.readForUpdate(`SELECT "id","email","emailVerified","createdAt","updatedAt" FROM "user" WHERE "id"=?`), v.OwnerID).Scan(&id, &email, &verified, &profileCreated, &profileUpdated)
	if errors.Is(err, sql.ErrNoRows) || err == nil && (id != v.OwnerID || strings.ToLower(email) != strings.ToLower(v.Email)) {
		return "", auth.ErrNotFound
	}
	if err != nil {
		return "", err
	}
	if !v.ExpiresAt.After(v.Now.Add(time.Since(started))) {
		return "", auth.ErrNotFound
	}
	if verified {
		return "", tx.Commit()
	}
	group := "verified-email-proof:" + v.OwnerID
	if _, err := tx.ExecContext(ctx, s.bind(`DELETE FROM "verification" WHERE "identifier"=? AND "expiresAt"<=?`), group, s.date(v.Now)); err != nil {
		return "", err
	}
	var used int
	cutoff := v.IssuedAt
	if cutoff.IsZero() {
		cutoff = time.Unix(1, 0).UTC()
	}
	err = tx.QueryRowContext(ctx, s.bind(`SELECT COUNT(*) FROM "verification" WHERE "identifier"=? AND (`+s.exactSQLValue(`"value"`)+`=? OR "createdAt">=?)`), group, v.ProofID, s.date(cutoff)).Scan(&used)
	if err != nil {
		return "", err
	}
	if used != 0 {
		return "", auth.ErrNotFound
	}
	_, err = tx.ExecContext(ctx, s.bind(`INSERT INTO "verification" ("id","identifier","value","createdAt","updatedAt","expiresAt") VALUES (?,?,?,?,?,?)`), rand.Text(), group, v.ProofID, s.date(v.Now), s.date(v.Now), s.date(v.ExpiresAt))
	if err != nil {
		return "", err
	}
	_, err = tx.ExecContext(ctx, s.bind(`UPDATE "user" SET "emailVerified"=?,"updatedAt"=? WHERE "id"=?`), true, s.date(v.Now), v.OwnerID)
	if err != nil {
		return "", err
	}
	token := ""
	if v.NewSession != nil && v.MatchesProfileRevision(profileCreated, profileUpdated) {
		token, err = s.emailVerificationToken(ctx, tx, v)
		if err != nil {
			return "", err
		}
	}
	if !v.ExpiresAt.After(v.Now.Add(time.Since(started))) {
		return "", auth.ErrNotFound
	}
	return token, tx.Commit()
}

func (s *Store) emailVerificationToken(ctx context.Context, tx *sql.Tx, v auth.EmailVerificationAttempt) (string, error) {
	admin, err := s.detectAdminSchema(ctx, tx)
	if err != nil {
		return "", err
	}
	if admin {
		err := s.adminSessionGate(ctx, tx, v.OwnerID, v.Now)
		var denial *auth.APIError
		if errors.As(err, &denial) && denial.Code == "BANNED_USER" {
			return "", nil
		}
		if err != nil {
			return "", err
		}
	}
	factors, err := s.detectFactorSchema(ctx, tx)
	if err != nil {
		return "", err
	}
	if factors {
		var enabled sql.NullBool
		err := tx.QueryRowContext(ctx, s.readForUpdate(`SELECT "twoFactorEnabled" FROM "user" WHERE "id"=?`), v.OwnerID).Scan(&enabled)
		if err != nil || enabled.Bool {
			return "", err
		}
	}
	if v.ExistingToken != "" {
		var userID, token string
		var delegated sql.NullString
		column := "NULL"
		if admin {
			column = `"impersonatedBy"`
		}
		err := tx.QueryRowContext(ctx, s.readForUpdate(`SELECT "userId","token",`+column+` FROM "session" WHERE "token"=? AND "expiresAt">?`), v.ExistingToken, s.date(v.Now)).Scan(&userID, &token, &delegated)
		if errors.Is(err, sql.ErrNoRows) {
			return "", nil
		}
		if err != nil {
			return "", err
		}
		if token != v.ExistingToken || delegated.Valid {
			return "", nil
		}
		if userID == v.OwnerID {
			return token, nil
		}
	}
	if err := s.insertSession(ctx, tx, *v.NewSession); err != nil {
		return "", err
	}
	return v.NewSession.Token, nil
}
