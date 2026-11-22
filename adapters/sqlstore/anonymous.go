package sqlstore

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"time"

	authn "github.com/Plain-Auth/plain-auth"
)

var _ authn.AnonymousStore = (*Store)(nil)

func (s *Store) CheckAnonymousSchema(ctx context.Context) error {
	rows, err := s.db.QueryContext(ctx, s.bind(`SELECT u."isAnonymous" FROM "user" u WHERE 1=0`))
	if err != nil {
		return err
	}
	return rows.Close()
}
func (s *Store) IsAnonymous(ctx context.Context, id string) (bool, error) {
	var anon bool
	err := s.db.QueryRowContext(ctx, s.bind(`SELECT COALESCE("isAnonymous",false) FROM "user" WHERE "id"=?`), id).Scan(&anon)
	if errors.Is(err, sql.ErrNoRows) {
		return false, authn.ErrNotFound
	}
	return anon, err
}
func (s *Store) CreateAnonymous(ctx context.Context, u authn.User, ss authn.StoredSession) error {
	if ss.UserID != u.ID || u.IsAnonymous == nil || !*u.IsAnonymous {
		return errors.New("sqlstore: invalid guest session")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	q := `INSERT INTO "user" ("id","name","email","emailVerified","isAnonymous","createdAt","updatedAt") VALUES (?,?,?,false,true,?,?)`
	if _, err = tx.ExecContext(ctx, s.bind(q), u.ID, u.Name, u.Email, s.date(u.CreatedAt), s.date(u.UpdatedAt)); err != nil {
		if duplicateConstraint(err) {
			return authn.ErrEmailTaken
		}
		return err
	}
	if err := s.insertSession(ctx, tx, ss); err != nil {
		return err
	}
	return tx.Commit()
}

// Resolve the persisted token and owner under a row lock. An absent or
// revoked source cannot authorize a transfer, even inside a multi-step flow.
func (s *Store) anonymousActor(ctx context.Context, tx *sql.Tx, token string, now time.Time) (authn.SessionResult, error) {
	var u authn.User
	var row authn.StoredSession
	var guest bool
	cols := sessionColumns + "," + userColumns + `,COALESCE(u."isAnonymous",false)`
	dest := append(append(sessionFields(&row), userFields(&u)...), &guest)
	admin := s.adminSchema.Load()
	if admin {
		cols += `,s."impersonatedBy"`
		dest = append(dest, &row.ImpersonatedBy)
	}
	parameter, _ := s.deviceTokenParameters([]string{token})
	q := `SELECT ` + cols + ` FROM "session" s JOIN "user" u ON u."id"=s."userId" WHERE s."token"=` + parameter + ` AND s."expiresAt">?`
	err := tx.QueryRowContext(ctx, s.readForUpdate(q), token, s.date(now)).Scan(dest...)
	if errors.Is(err, sql.ErrNoRows) {
		return authn.SessionResult{}, authn.ErrNotFound
	}
	if err == nil && !admin {
		var enabled bool
		enabled, err = s.detectAdminSchema(ctx, tx)
		if err == nil && enabled {
			return s.anonymousActor(ctx, tx, token, now)
		}
	}
	if err == nil && admin {
		err = s.adminSessionGate(ctx, tx, u.ID, now)
	}
	u.IsAnonymous = &guest
	return authn.SessionResult{User: u, Session: row.Session}, err
}
func (s *Store) DeleteAnonymous(ctx context.Context, id, token string, now time.Time) error {
	tx, err := s.beginMembershipChange(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	src, err := s.anonymousActor(ctx, tx, token, now)
	if err != nil {
		return err
	}
	if src.User.ID != id {
		return authn.ErrNotFound
	}
	if src.Session.ImpersonatedBy != nil {
		return authn.ErrNotAnonymous
	}
	if !*src.User.IsAnonymous {
		return authn.ErrNotAnonymous
	}
	if err = s.deleteAccountRows(ctx, tx, id); err != nil {
		return err
	}
	return tx.Commit()
}
func (s *Store) LinkAnonymous(ctx context.Context, source, target string, now time.Time, retain bool, callback func(context.Context, authn.AnonymousLink) error) error {
	tx, err := s.beginMembershipChange(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	src, err := s.anonymousActor(ctx, tx, source, now)
	if errors.Is(err, authn.ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	if src.Session.ImpersonatedBy != nil || !*src.User.IsAnonymous {
		return nil
	}
	dst, err := s.anonymousActor(ctx, tx, target, now)
	if err != nil {
		return err
	}
	if dst.Session.ImpersonatedBy != nil || *dst.User.IsAnonymous || dst.User.ID == src.User.ID {
		return nil
	}
	if retain {
		// Keep one claim for a retained guest so concurrent sign-ins cannot
		// transfer the same application data to two different owners.
		hash := sha256.Sum256([]byte("anonymous-link\x00" + src.User.ID))
		id := "gl-" + hex.EncodeToString(hash[:16])
		var exists string
		err = tx.QueryRowContext(ctx, s.readForUpdate(`SELECT "id" FROM "verification" WHERE "id"=?`), id).Scan(&exists)
		if err == nil {
			return nil
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		_, err = tx.ExecContext(ctx, s.bind(`INSERT INTO "verification" ("id","identifier","value","expiresAt","createdAt","updatedAt") VALUES(?,?,?,?,?,?)`), id, "anonymous-link:"+src.User.ID, dst.User.ID, s.date(src.Session.ExpiresAt), s.date(now), s.date(now))
		if err != nil {
			return err
		}
	}
	if callback != nil {
		if err := callback(ctx, authn.AnonymousLink{AnonymousUser: src, NewUser: dst, Tx: tx}); err != nil {
			return err
		}
	}
	if !retain {
		if err = s.deleteAccountRows(ctx, tx, src.User.ID); err != nil {
			return err
		}
	}
	return tx.Commit()
}
