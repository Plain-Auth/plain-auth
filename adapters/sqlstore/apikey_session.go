package sqlstore

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"slices"
	"time"

	stonewrit "github.com/Stonewrit/stonewrit-auth"
	ak "github.com/Stonewrit/stonewrit-auth/plugins/apikey"
)

// UniqueSessionKeyConfiguration resolves a shared header only when exactly one
// credential in its accepted configurations matches. Imported stores need not
// enforce uniqueness on the digest index.
func (s *Store) UniqueSessionKeyConfiguration(ctx context.Context, digest string, configs []string) (string, error) {
	if len(configs) == 0 {
		return "", nil
	}
	keyParam, _ := s.deviceTokenParameters([]string{digest})
	configParams, args := s.deviceTokenParameters(configs)
	rows, err := s.db.QueryContext(ctx, s.bind(`SELECT "configId" FROM "apikey" WHERE "key"=`+keyParam+` AND "configId" IN (`+configParams+`) LIMIT 2`), append([]any{digest}, args...)...)
	if err != nil {
		return "", err
	}
	defer rows.Close()
	var id string
	if rows.Next() {
		if err = rows.Scan(&id); err != nil {
			return "", err
		}
		if rows.Next() {
			return "", nil
		}
	}
	return id, rows.Err()
}

func (s *Store) APIKeySessionUser(ctx context.Context, id string) (stonewrit.User, error) {
	var u stonewrit.User
	fields := userFields(&u)
	cols := userColumns
	var finish func()
	if s.adminSchema {
		fields, finish = s.adminUserScanner(&u)
		cols += "," + adminUserColumns
	}
	e := s.db.QueryRowContext(ctx, s.bind("SELECT "+cols+` FROM "user" u WHERE u."id"=?`), id).Scan(fields...)
	if errors.Is(e, sql.ErrNoRows) {
		return u, ak.ErrSession
	}
	if e != nil {
		return u, e
	}
	if finish != nil {
		finish()
		if u.Banned && (u.BanExpires == nil || u.BanExpires.After(time.Now())) {
			return u, ak.ErrBanned
		}
	}
	return u, nil
}
func (s *Store) lockKeySession(ctx context.Context, tx *sql.Tx, p ak.SessionProof, resource, action string, now time.Time) error {
	if s.adminSchema {
		if e := s.adminSessionGate(ctx, tx, p.UserID, now); e != nil {
			return e
		}
	} else if e := s.lockAccount(ctx, tx, p.UserID); e != nil {
		return e
	}
	param, _ := s.deviceTokenParameters([]string{p.Digest})
	var saved sql.NullString
	e := tx.QueryRowContext(ctx, s.readForUpdate(`SELECT "permissions" FROM "apikey" WHERE "id"=? AND "referenceId"=? AND "configId"=? AND "key"=`+param+` AND COALESCE("enabled",true) AND ("expiresAt" IS NULL OR "expiresAt">?)`), p.ID, p.UserID, p.ConfigID, p.Digest, s.date(now)).Scan(&saved)
	if errors.Is(e, sql.ErrNoRows) {
		return stonewrit.ErrNotFound
	}
	if e != nil {
		return e
	}
	if saved.Valid && saved.String != "" {
		var grants ak.Permissions
		if e = json.Unmarshal([]byte(saved.String), &grants); e != nil {
			return e
		}
		if grants != nil && !slices.Contains(grants[resource], action) {
			return ak.ErrPermission
		}
	}
	return nil
}

func (s *Store) SupportsKeyFactorEnrollment() bool { return true }

// UpdateCredentialProfile rechecks the key and write scope while the user row is locked.
func (s *Store) UpdateCredentialProfile(ctx context.Context, user string, update stonewrit.ProfileUpdate, now time.Time) error {
	p, ok := ak.SessionProofFrom(ctx)
	if !ok || user != p.UserID || update.Username != nil || update.DisplayUsername != nil || update.ClearUsername || update.ClearDisplayUsername {
		return ak.ErrPermission
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err = s.lockKeySession(ctx, tx, p, "user", "update", now); err != nil {
		return err
	}
	if err = s.updateProfile(ctx, tx, user, update, now); err != nil {
		return err
	}
	return tx.Commit()
}

func keyFactorPrefix(user string) string {
	sum := sha256.Sum256([]byte(user))
	return "apikey-factor-" + hex.EncodeToString(sum[:16]) + "-"
}
func enrollmentMarker(p ak.SessionProof) string {
	return keyFactorPrefix(p.UserID) + ak.Digest(p.ConfigID+"\x00"+p.ID)
}
func (s *Store) checkKeyEnrollment(ctx context.Context, tx *sql.Tx, p ak.SessionProof, state stonewrit.FactorState, now time.Time) error {
	if state.Record == nil {
		return stonewrit.ErrNotFound
	}
	var present int
	err := tx.QueryRowContext(ctx, s.readForUpdate(`SELECT 1 FROM "verification" WHERE "identifier"=? AND "value"=? AND "expiresAt">?`), enrollmentMarker(p), ak.Digest(state.PasswordHash+"\x00"+state.Record.Secret), s.date(now)).Scan(&present)
	if errors.Is(err, sql.ErrNoRows) {
		return stonewrit.ErrNotFound
	}
	return err
}
func (s *Store) saveKeyEnrollment(ctx context.Context, tx *sql.Tx, p ak.SessionProof, sub stonewrit.FactorSubject, state stonewrit.FactorState, ch stonewrit.FactorChange) error {
	if ch.SaveRecord == nil {
		return nil
	}
	staging := sub.ApplicationOperation == "/two-factor/enable"
	if !staging && (ch.Enabled == nil || !*ch.Enabled) {
		return nil
	}
	marker := enrollmentMarker(p)
	if _, e := tx.ExecContext(ctx, s.bind(`DELETE FROM "verification" WHERE "identifier"=?`), marker); e != nil {
		return e
	}
	if !staging || ch.SaveRecord.Verified {
		return nil
	}
	_, e := tx.ExecContext(ctx, s.bind(`INSERT INTO "verification" ("id","identifier","value","expiresAt","createdAt","updatedAt") VALUES (?,?,?,?,?,?)`), rand.Text(), marker, ak.Digest(state.PasswordHash+"\x00"+ch.SaveRecord.Secret), s.date(sub.Now.Add(10*time.Minute)), s.date(sub.Now), s.date(sub.Now))
	return e
}
