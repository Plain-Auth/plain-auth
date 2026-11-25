package sqlstore

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"time"

	auth "github.com/Plain-Org/plain-auth"
	pk "github.com/Plain-Org/plain-auth/plugins/passkey"
	"github.com/go-sql-driver/mysql"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/mattn/go-sqlite3"
)

var _ pk.Store = (*Store)(nil)

const passkeyFields = `"id","name","publicKey","userId","credentialID","counter","deviceType","backedUp","transports","createdAt","aaguid"`

// CheckPasskeySchema verifies the physical profile before the server accepts traffic.
func (s *Store) CheckPasskeySchema(ctx context.Context) error {
	rows, err := s.db.QueryContext(ctx, s.bind(`SELECT `+passkeyFields+` FROM "passkey" WHERE 1=0`))
	if err != nil {
		return err
	}
	return rows.Close()
}
func scanPasskey(row rowScanner) (pk.Record, error) {
	var r pk.Record
	err := row.Scan(&r.ID, &r.Name, &r.PublicKey, &r.UserID, &r.CredentialID, &r.Counter, &r.DeviceType, &r.BackedUp, &r.Transports, &r.CreatedAt, &r.AAGUID)
	if errors.Is(err, sql.ErrNoRows) {
		return r, pk.ErrMissing
	}
	return r, err
}
func (s *Store) SavePasskeyChallenge(ctx context.Context, key string, body []byte, now, expiry time.Time) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if s.sweeping() {
		if _, err := tx.ExecContext(ctx, s.bind(`DELETE FROM "verification" WHERE "identifier" LIKE 'passkey:%' AND "expiresAt"<=?`), s.date(now)); err != nil {
			return err
		}
	}
	_, err = tx.ExecContext(ctx, s.bind(`INSERT INTO "verification" ("id","identifier","value","expiresAt","createdAt","updatedAt") VALUES(?,?,?,?,?,?)`), rand.Text(), "passkey:"+key, string(body), s.date(expiry), s.date(now), s.date(now))
	if err != nil {
		return err
	}
	return tx.Commit()
}
func (s *Store) TakePasskeyChallenge(ctx context.Context, key string, now time.Time) ([]byte, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	var id string
	var body []byte
	err = tx.QueryRowContext(ctx, s.readForUpdate(`SELECT "id","value" FROM "verification" WHERE "identifier"=? AND "expiresAt">?`), "passkey:"+key, s.date(now)).Scan(&id, &body)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, pk.ErrChallenge
	}
	if err != nil {
		return nil, err
	}
	if _, err = tx.ExecContext(ctx, s.bind(`DELETE FROM "verification" WHERE "id"=?`), id); err != nil {
		return nil, err
	}
	return body, tx.Commit()
}
func (s *Store) ListPasskeys(ctx context.Context, userID string) ([]pk.Record, error) {
	rows, err := s.db.QueryContext(ctx, s.bind(`SELECT `+passkeyFields+` FROM "passkey" WHERE "userId"=? ORDER BY "createdAt","id"`), userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	keys := []pk.Record{}
	for rows.Next() {
		r, err := scanPasskey(rows)
		if err != nil {
			return nil, err
		}
		keys = append(keys, r)
	}
	return keys, rows.Err()
}
func (s *Store) passkeyMatch() string {
	// Credential IDs contain case-sensitive base64url. MySQL databases often
	// use a case-insensitive default character collation.
	if s.dialect == "mysql" {
		return `BINARY "credentialID"=?`
	}
	return `"credentialID"=?`
}
func (s *Store) LookupPasskey(ctx context.Context, id string) (pk.Record, error) {
	rows, err := s.db.QueryContext(ctx, s.bind(`SELECT `+passkeyFields+` FROM "passkey" WHERE `+s.passkeyMatch()+` LIMIT 2`), id)
	if err != nil {
		return pk.Record{}, err
	}
	defer rows.Close()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return pk.Record{}, err
		}
		return pk.Record{}, pk.ErrMissing
	}
	r, err := scanPasskey(rows)
	if err != nil {
		return pk.Record{}, err
	}
	if rows.Next() {
		return pk.Record{}, pk.ErrAuthentication
	}
	return r, rows.Err()
}
func duplicateConstraint(err error) bool {
	var my *mysql.MySQLError
	var pg *pgconn.PgError
	var lite sqlite3.Error
	return (errors.As(err, &my) && my.Number == 1062) || (errors.As(err, &pg) && pg.Code == "23505") || (errors.As(err, &lite) && (lite.ExtendedCode == sqlite3.ErrConstraintPrimaryKey || lite.ExtendedCode == sqlite3.ErrConstraintUnique))
}
func (s *Store) CreatePasskey(ctx context.Context, r pk.Record, source string, now time.Time) error {
	if source == "" {
		return pk.ErrSession
	}
	_, err := s.CommitPasskeyRegistration(ctx, r, source, nil, nil, now)
	return err
}

func (s *Store) CommitPasskeyRegistration(ctx context.Context, r pk.Record, source string, create *auth.User, session *auth.StoredSession, now time.Time) (auth.User, error) {
	var user auth.User
	if r.UserID == "" || (create != nil && (create.ID != r.UserID || source != "")) || session != nil && session.UserID != r.UserID {
		return user, pk.ErrRegistration
	}
	// The canonical credentialID index is not unique. Serialize all registrations for the same
	// credential, including simultaneous enrollments under different account and record IDs.
	sum := sha256.Sum256([]byte("passkey-credential:" + r.CredentialID))
	digest := hex.EncodeToString(sum[:])
	lock := emailOTPKey{owner: "passkey-credential:" + digest, digest: digest}
	err := s.emailOTPTransaction(ctx, lock, func(tx *sql.Tx) (error, error) {
		if create != nil {
			_, err := tx.ExecContext(ctx, s.bind(`INSERT INTO "user"("id","name","email","emailVerified","createdAt","updatedAt") VALUES(?,?,?,?,?,?)`), create.ID, create.Name, create.Email, false, s.date(now), s.date(now))
			if duplicateConstraint(err) {
				return nil, &auth.APIError{Status: 409, Code: "USER_ALREADY_EXISTS", Message: "User already exists"}
			}
			if err != nil {
				return nil, err
			}
		}
		var err error
		if source != "" {
			err = s.lockActiveAccount(ctx, tx, r.UserID, source, now)
		} else {
			_, err = s.lockAllowedAccount(ctx, tx, r.UserID, now)
		}
		if errors.Is(err, auth.ErrNotFound) {
			if source != "" {
				return pk.ErrSession, nil
			}
			return &auth.APIError{Status: 500, Code: "USER_NOT_FOUND", Message: "User not found"}, nil
		}
		if err != nil {
			return nil, err
		}
		var exists bool
		if err = tx.QueryRowContext(ctx, s.bind(`SELECT EXISTS(SELECT 1 FROM "passkey" WHERE `+s.passkeyMatch()+`)`), r.CredentialID).Scan(&exists); err != nil {
			return nil, err
		}
		if exists {
			return nil, pk.ErrDuplicate
		}
		_, err = tx.ExecContext(ctx, s.bind(`INSERT INTO "passkey" (`+passkeyFields+`) VALUES(?,?,?,?,?,?,?,?,?,?,?)`), r.ID, r.Name, r.PublicKey, r.UserID, r.CredentialID, r.Counter, r.DeviceType, r.BackedUp, r.Transports, s.date(now), r.AAGUID)
		if duplicateConstraint(err) {
			return nil, pk.ErrDuplicate
		}
		if err != nil {
			return nil, err
		}
		if session != nil {
			if err = s.insertSession(ctx, tx, *session); err != nil {
				return nil, err
			}
		}
		err = tx.QueryRowContext(ctx, s.bind(`SELECT `+userColumns+` FROM "user" u WHERE u."id"=?`), r.UserID).Scan(userFields(&user)...)
		return nil, err
	})
	return user, err
}
func (s *Store) FinishPasskeyLogin(ctx context.Context, expected pk.Record, count uint32, backed bool, session auth.StoredSession) (auth.User, error) {
	var user auth.User
	if session.UserID != expected.UserID {
		return user, pk.ErrAuthentication
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return user, err
	}
	defer tx.Rollback()
	if err = s.lockAccount(ctx, tx, expected.UserID); err != nil {
		if errors.Is(err, auth.ErrNotFound) {
			return user, pk.ErrAuthentication
		}
		return user, err
	}
	r, err := scanPasskey(tx.QueryRowContext(ctx, s.readForUpdate(`SELECT `+passkeyFields+` FROM "passkey" WHERE "id"=? AND "userId"=?`), expected.ID, expected.UserID))
	if err != nil {
		return user, err
	}
	if r.CredentialID != expected.CredentialID || r.PublicKey != expected.PublicKey || r.DeviceType != expected.DeviceType || (count <= r.Counter && (count != 0 || r.Counter != 0)) {
		return user, pk.ErrAuthentication
	}
	if _, err = tx.ExecContext(ctx, s.bind(`UPDATE "passkey" SET "counter"=?,"backedUp"=? WHERE "id"=?`), count, backed, r.ID); err != nil {
		return user, err
	}
	if err = s.insertSession(ctx, tx, session); err != nil {
		return user, err
	}
	err = tx.QueryRowContext(ctx, s.bind(`SELECT `+userColumns+` FROM "user" u WHERE u."id"=?`), expected.UserID).Scan(userFields(&user)...)
	if err != nil {
		return user, err
	}
	return user, tx.Commit()
}
func (s *Store) ManagePasskey(ctx context.Context, userID, session, id string, newName *string, now time.Time) (pk.Record, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return pk.Record{}, err
	}
	defer tx.Rollback()
	if err := s.lockActiveAccount(ctx, tx, userID, session, now); err != nil {
		if errors.Is(err, auth.ErrNotFound) {
			return pk.Record{}, pk.ErrSession
		}
		return pk.Record{}, err
	}
	r, err := scanPasskey(tx.QueryRowContext(ctx, s.readForUpdate(`SELECT `+passkeyFields+` FROM "passkey" WHERE "id"=? AND "userId"=?`), id, userID))
	if err != nil {
		return pk.Record{}, err
	}
	if newName == nil {
		_, err = tx.ExecContext(ctx, s.bind(`DELETE FROM "passkey" WHERE "id"=? AND "userId"=?`), id, userID)
	} else {
		_, err = tx.ExecContext(ctx, s.bind(`UPDATE "passkey" SET "name"=? WHERE "id"=? AND "userId"=?`), *newName, id, userID)
		r.Name = newName
	}
	if err != nil {
		return pk.Record{}, err
	}
	return r, tx.Commit()
}
func (s *Store) cleanupPasskeys(ctx context.Context, tx *sql.Tx, userID string) error {
	if s.dialect != "mysql" {
		return nil
	}
	var exists bool
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM information_schema.columns WHERE table_schema=database() AND table_name='passkey' AND column_name='credentialID')`).Scan(&exists); err != nil {
		return err
	}
	if exists {
		_, err := tx.ExecContext(ctx, s.bind(`DELETE FROM "passkey" WHERE "userId"=?`), userID)
		return err
	}
	return nil
}
