package sqlstore

import (
	"context"
	"crypto/rand"
	"database/sql"
	"errors"
	"strings"
	"time"

	auth "github.com/Plain-Org/plain-auth"
)

// CompleteEmailVerification spends the address proof and decides browser
// ownership while holding the verified account's write lock.
func (s *Store) CompleteEmailVerification(ctx context.Context, v auth.EmailVerificationAttempt) (string, error) {
	return s.completeEmailVerification(ctx, v, nil)
}

// InspectEmailVerification takes a consistent owner/receipt snapshot and releases
// the account before any host code runs. Completion repeats both checks.
func (s *Store) InspectEmailVerification(ctx context.Context, v auth.EmailVerificationAttempt) (auth.User, error) {
	started := time.Now()
	tx, err := s.beginMembershipChange(ctx)
	if err != nil {
		return auth.User{}, err
	}
	defer tx.Rollback()
	u, err := s.verificationOwner(ctx, tx, v)
	if err == nil && !u.EmailVerified {
		err = s.unspentEmailVerification(ctx, tx, v)
	}
	if err != nil {
		return auth.User{}, err
	}
	if !v.ExpiresAt.After(v.Now.Add(time.Since(started))) {
		return auth.User{}, auth.ErrNotFound
	}
	return u, tx.Commit()
}

func (s *Store) verificationOwner(ctx context.Context, tx *sql.Tx, v auth.EmailVerificationAttempt) (auth.User, error) {
	var u auth.User
	err := tx.QueryRowContext(ctx, s.readForUpdate(`SELECT `+userColumns+` FROM "user" u WHERE u."id"=?`), v.OwnerID).Scan(userFields(&u)...)
	if errors.Is(err, sql.ErrNoRows) || err == nil && (u.ID != v.OwnerID || strings.ToLower(u.Email) != strings.ToLower(v.Email)) {
		return auth.User{}, auth.ErrNotFound
	}
	return u, err
}

func (s *Store) unspentEmailVerification(ctx context.Context, tx *sql.Tx, v auth.EmailVerificationAttempt) error {
	cutoff := v.IssuedAt
	if cutoff.IsZero() {
		cutoff = time.Unix(1, 0).UTC()
	}
	var used int
	err := tx.QueryRowContext(ctx, s.bind(`SELECT COUNT(*) FROM "verification" WHERE "identifier"=? AND "expiresAt">? AND (`+s.exactSQLValue(`"value"`)+`=? OR "createdAt">=?)`), "verified-email-proof:"+v.OwnerID, s.date(v.Now), v.ProofID, s.date(cutoff)).Scan(&used)
	if err == nil && used != 0 {
		return auth.ErrNotFound
	}
	return err
}

func (s *Store) CompleteObservedEmailVerification(ctx context.Context, v auth.EmailVerificationAttempt) (auth.VerifiedEmailChange, error) {
	var change auth.VerifiedEmailChange
	_, err := s.completeEmailVerification(ctx, v, &change)
	return change, err
}

func (s *Store) completeEmailVerification(ctx context.Context, v auth.EmailVerificationAttempt, change *auth.VerifiedEmailChange) (string, error) {
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
	auth.LoginPlanFrom(ctx).Attempt()
	owner, err := s.verificationOwner(ctx, tx, v)
	if err != nil {
		return "", err
	}
	if !v.ExpiresAt.After(v.Now.Add(time.Since(started))) {
		return "", auth.ErrNotFound
	}
	if owner.EmailVerified {
		if err := auth.LoginPlanFrom(ctx).Commit(); err != nil {
			return "", err
		}
		return "", tx.Commit()
	}
	group := "verified-email-proof:" + v.OwnerID
	if _, err := tx.ExecContext(ctx, s.bind(`DELETE FROM "verification" WHERE "identifier"=? AND "expiresAt"<=?`), group, s.date(v.Now)); err != nil {
		return "", err
	}
	if err := s.unspentEmailVerification(ctx, tx, v); err != nil {
		return "", err
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
	if change != nil {
		out, err := s.emailOTPUser(ctx, tx, owner.Email)
		if err != nil {
			return "", err
		}
		if out.ID != v.OwnerID || strings.ToLower(out.Email) != strings.ToLower(v.Email) || !out.EmailVerified {
			return "", auth.ErrNotFound
		}
		change.User = out
		if v.NewSession != nil && v.MatchesProfileRevision(owner.CreatedAt, owner.UpdatedAt) {
			_, change.SessionEligible, err = s.emailVerificationSessionPolicy(ctx, tx, v)
			if err == nil && change.SessionEligible {
				err = s.saveVerificationReceipt(ctx, tx, v.SessionReceipt(out), v.Now)
			}
			if err != nil {
				return "", err
			}
		}
	} else if v.NewSession != nil && v.MatchesProfileRevision(owner.CreatedAt, owner.UpdatedAt) {
		token, err = s.emailVerificationToken(ctx, tx, v)
		if err != nil {
			return "", err
		}
	}
	if !v.ExpiresAt.After(v.Now.Add(time.Since(started))) {
		return "", auth.ErrNotFound
	}
	if err := auth.LoginPlanFrom(ctx).Commit(); err != nil {
		return token, err
	}
	return token, tx.Commit()
}

func (s *Store) emailVerificationToken(ctx context.Context, tx *sql.Tx, v auth.EmailVerificationAttempt) (string, error) {
	token, allowed, err := s.emailVerificationSessionPolicy(ctx, tx, v)
	if err != nil || !allowed || token != "" {
		return token, err
	}
	if err := s.insertSession(ctx, tx, *v.NewSession); err != nil {
		return "", err
	}
	return v.NewSession.Token, nil
}

func (s *Store) emailVerificationSessionPolicy(ctx context.Context, tx *sql.Tx, v auth.EmailVerificationAttempt) (string, bool, error) {
	admin, err := s.detectAdminSchema(ctx, tx)
	if err != nil {
		return "", false, err
	}
	if admin {
		err := s.adminSessionGate(ctx, tx, v.OwnerID, v.Now)
		var denial *auth.APIError
		if errors.As(err, &denial) && denial.Code == "BANNED_USER" {
			return "", false, nil
		}
		if err != nil {
			return "", false, err
		}
	}
	factors, err := s.detectFactorSchema(ctx, tx)
	if err != nil {
		return "", false, err
	}
	if factors {
		var enabled sql.NullBool
		err := tx.QueryRowContext(ctx, s.readForUpdate(`SELECT "twoFactorEnabled" FROM "user" WHERE "id"=?`), v.OwnerID).Scan(&enabled)
		if err != nil || enabled.Bool {
			return "", false, err
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
			return "", false, nil
		}
		if err != nil {
			return "", false, err
		}
		if token != v.ExistingToken || delegated.Valid {
			return "", false, nil
		}
		if userID == v.OwnerID && !v.AlwaysCreateSession {
			return token, true, nil
		}
	}
	return "", true, nil
}

func (s *Store) FinishObservedEmailSession(ctx context.Context, v auth.EmailVerificationAttempt, owner auth.User) (string, error) {
	started := time.Now()
	if v.NewSession == nil || v.OwnerID != owner.ID || v.NewSession.UserID != owner.ID || v.NewSession.ID == "" || v.NewSession.Token == "" || v.NewSession.Session.RequireOwner() != nil || !v.NewSession.ExpiresAt.After(v.Now) || !v.ExpiresAt.After(v.Now) || !owner.EmailVerified {
		return "", nil
	}
	tx, err := s.beginMembershipChange(ctx)
	if err != nil {
		return "", err
	}
	defer tx.Rollback()
	current, err := s.emailOTPUser(ctx, tx, owner.Email)
	if err != nil {
		return "", err
	}
	if current.ID != owner.ID || current.Email != owner.Email || !current.EmailVerified || !current.UpdatedAt.Equal(owner.UpdatedAt) {
		return "", nil
	}
	ok, err := s.takeVerificationReceipt(ctx, tx, v.SessionReceipt(owner), v.Now.Add(time.Since(started)))
	if err != nil || !ok {
		return "", err
	}
	token, err := s.emailVerificationToken(ctx, tx, v)
	if err != nil {
		return "", err
	}
	if !v.ExpiresAt.After(v.Now.Add(time.Since(started))) {
		return "", nil
	}
	return token, tx.Commit()
}

func (s *Store) saveVerificationReceipt(ctx context.Context, tx *sql.Tx, r auth.EmailVerificationReceipt, now time.Time) error {
	if _, err := tx.ExecContext(ctx, s.bind(`DELETE FROM "verification" WHERE "identifier"=? AND "expiresAt"<=?`), r.Identifier, s.date(now)); err != nil {
		return err
	}
	_, err := tx.ExecContext(ctx, s.bind(`INSERT INTO "verification" ("id","identifier","value","expiresAt","createdAt","updatedAt") VALUES (?,?,?,?,?,?)`), rand.Text(), r.Identifier, r.Value, s.date(r.ExpiresAt), s.date(now), s.date(now))
	return err
}

func (s *Store) takeVerificationReceipt(ctx context.Context, tx *sql.Tx, r auth.EmailVerificationReceipt, now time.Time) (bool, error) {
	res, err := tx.ExecContext(ctx, s.bind(`DELETE FROM "verification" WHERE "identifier"=? AND `+s.exactSQLValue(`"value"`)+`=? AND "expiresAt">?`), r.Identifier, r.Value, s.date(now))
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n == 1, err
}

func (s *Store) DiscardEmailVerificationReceipt(ctx context.Context, r auth.EmailVerificationReceipt) error {
	if !r.ValidScope() {
		return auth.ErrNotFound
	}
	_, err := s.db.ExecContext(ctx, s.bind(`DELETE FROM "verification" WHERE "identifier"=? AND `+s.exactSQLValue(`"value"`)+`=?`), r.Identifier, r.Value)
	return err
}
