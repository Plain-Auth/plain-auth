package sqlstore

import (
	"context"
	"crypto/rand"
	"database/sql"
	"errors"
	"strconv"
	"time"

	auth "github.com/nabuhadba/go-better-auth"
)

var _ auth.TwoFactorStore = (*Store)(nil)

func (s *Store) detectFactorSchema(ctx context.Context, db rowQuerier) (bool, error) {
	if s.factorSchema {
		return true, nil
	}
	var q string
	switch s.dialect {
	case "sqlite":
		q = `SELECT count(*) FROM pragma_table_info('user') WHERE name='twoFactorEnabled'`
	case "postgres":
		q = `SELECT count(*) FROM information_schema.columns WHERE table_schema=current_schema() AND table_name='user' AND column_name='twoFactorEnabled'`
	case "mysql":
		q = `SELECT count(*) FROM information_schema.columns WHERE table_schema=database() AND table_name='user' AND column_name='twoFactorEnabled'`
	}
	var n int
	err := db.QueryRowContext(ctx, q).Scan(&n)
	return n > 0, err
}
func (s *Store) FactorEnabled(ctx context.Context, id string) (bool, error) {
	var enabled sql.NullBool
	err := s.db.QueryRowContext(ctx, s.bind(`SELECT "twoFactorEnabled" FROM "user" WHERE "id"=?`), id).Scan(&enabled)
	if errors.Is(err, sql.ErrNoRows) {
		return false, auth.ErrNotFound
	}
	return enabled.Bool, err
}
func (s *Store) TwoFactorReady() bool { return s.factorSchema }
func (s *Store) readForUpdate(query string) string {
	if s.dialect != "sqlite" {
		query += " FOR UPDATE"
	}
	return s.bind(query)
}

func (s *Store) factorUser(ctx context.Context, tx *sql.Tx, id string) (auth.FactorState, error) {
	var state auth.FactorState
	var enabled sql.NullBool
	err := tx.QueryRowContext(ctx, s.readForUpdate(`SELECT `+userColumns+`,u."twoFactorEnabled" FROM "user" u WHERE u."id"=?`), id).Scan(append(userFields(&state.User), &enabled)...)
	if errors.Is(err, sql.ErrNoRows) {
		return state, auth.ErrNotFound
	}
	if err != nil {
		return state, err
	}
	state.Enabled = enabled.Bool
	state.User.TwoFactorEnabled = &state.Enabled
	hash, err := s.credentialHash(ctx, tx, id)
	if err != nil && !errors.Is(err, auth.ErrNotFound) {
		return state, err
	}
	state.PasswordHash = hash
	var rec auth.FactorRecord
	var verified sql.NullBool
	var count sql.NullInt64
	var locked sql.NullTime
	err = tx.QueryRowContext(ctx, s.readForUpdate(`SELECT "id","secret","backupCodes","verified","failedVerificationCount","lockedUntil" FROM "twoFactor" WHERE "userId"=? ORDER BY "id" LIMIT 1`), id).Scan(&rec.ID, &rec.Secret, &rec.BackupCodes, &verified, &count, &locked)
	if errors.Is(err, sql.ErrNoRows) {
		return state, nil
	}
	if err != nil {
		return state, err
	}
	rec.Verified = !verified.Valid || verified.Bool
	rec.Failures = int(count.Int64)
	if locked.Valid {
		rec.LockedUntil = &locked.Time
	}
	state.Record = &rec
	state.LastTOTPStep = -1
	var step string
	err = tx.QueryRowContext(ctx, s.readForUpdate(`SELECT "value" FROM "verification" WHERE "identifier"=?`), "2fa-totp-step-"+id).Scan(&step)
	if errors.Is(err, sql.ErrNoRows) {
		return state, nil
	}
	if err != nil {
		return state, err
	}
	state.LastTOTPStep, err = strconv.ParseInt(step, 10, 64)
	return state, err
}

// All operations take the owner lock first. A session or challenge looked up
// to identify its owner is rechecked under that lock before any mutation.
func (s *Store) WithTwoFactor(ctx context.Context, sub auth.FactorSubject, decide func(auth.FactorState) (auth.FactorChange, error)) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	owner := sub.UserID
	var q, key string
	if sub.SessionToken != "" {
		q = `SELECT "userId" FROM "session" WHERE "token"=? AND "expiresAt">?`
		key = sub.SessionToken
	}
	if sub.Challenge != "" {
		q = `SELECT "value" FROM "verification" WHERE "identifier"=? AND "expiresAt">?`
		key = sub.Challenge
	}
	if q != "" {
		if err = tx.QueryRowContext(ctx, s.bind(q), key, s.date(sub.Now)).Scan(&owner); err != nil {
			return factorRowError(err)
		}
	}
	state, err := s.factorUser(ctx, tx, owner)
	if err != nil {
		return err
	}
	if sub.SessionToken != "" {
		var ss auth.StoredSession
		err = tx.QueryRowContext(ctx, s.readForUpdate(`SELECT `+sessionColumns+` FROM "session" s WHERE s."token"=? AND s."userId"=? AND s."expiresAt">?`), sub.SessionToken, owner, s.date(sub.Now)).Scan(sessionFields(&ss)...)
		if err != nil {
			return factorRowError(err)
		}
		state.Session = &ss.Session
	}
	if sub.Challenge != "" {
		var bound string
		if err = tx.QueryRowContext(ctx, s.readForUpdate(q), key, s.date(sub.Now)).Scan(&bound); err != nil {
			return factorRowError(err)
		}
		if bound != owner {
			return auth.ErrNotFound
		}
		var attempts string
		err = tx.QueryRowContext(ctx, s.readForUpdate(q), "2fa-attempts-"+key, s.date(sub.Now)).Scan(&attempts)
		if err != nil {
			return factorRowError(err)
		}
		state.Attempts, err = strconv.Atoi(attempts)
		if err != nil || state.Attempts < 0 || state.Attempts >= 5 {
			return auth.ErrNotFound
		}
	}
	change, err := decide(state)
	if err != nil {
		return err
	}
	if err = s.writeFactorChange(ctx, tx, sub, state, change); err != nil {
		return err
	}
	return tx.Commit()
}

func factorRowError(err error) error {
	if errors.Is(err, sql.ErrNoRows) {
		return auth.ErrNotFound
	}
	return err
}

func (s *Store) writeFactorChange(ctx context.Context, tx *sql.Tx, sub auth.FactorSubject, state auth.FactorState, ch auth.FactorChange) error {
	uid := state.User.ID
	exec := func(q string, args ...any) error { _, err := tx.ExecContext(ctx, s.bind(q), args...); return err }
	if ch.SaveRecord != nil {
		rec := ch.SaveRecord
		var until any
		if rec.LockedUntil != nil {
			until = s.date(*rec.LockedUntil)
		}
		if state.Record == nil {
			err := exec(`INSERT INTO "twoFactor" ("id","userId","secret","backupCodes","verified","failedVerificationCount","lockedUntil") VALUES (?,?,?,?,?,?,?)`, rec.ID, uid, rec.Secret, rec.BackupCodes, rec.Verified, rec.Failures, until)
			if err != nil {
				return err
			}
		} else {
			err := exec(`UPDATE "twoFactor" SET "secret"=?,"backupCodes"=?,"verified"=?,"failedVerificationCount"=?,"lockedUntil"=? WHERE "id"=? AND "userId"=?`, rec.Secret, rec.BackupCodes, rec.Verified, rec.Failures, until, state.Record.ID, uid)
			if err != nil {
				return err
			}
		}
	}
	if ch.UsedTOTPStep != nil || ch.DeleteRecord {
		key := "2fa-totp-step-" + uid
		if err := exec(`DELETE FROM "verification" WHERE "identifier"=?`, key); err != nil {
			return err
		}
		if ch.UsedTOTPStep != nil {
			err := exec(`INSERT INTO "verification" ("id","identifier","value","expiresAt","createdAt","updatedAt") VALUES (?,?,?,?,?,?)`, rand.Text(), key, strconv.FormatInt(*ch.UsedTOTPStep, 10), s.date(sub.Now.Add(2*time.Minute)), s.date(sub.Now), s.date(sub.Now))
			if err != nil {
				return err
			}
		}
	}
	if ch.DeleteRecord {
		if err := exec(`DELETE FROM "twoFactor" WHERE "userId"=?`, uid); err != nil {
			return err
		}
	}
	if ch.Enabled != nil {
		if err := exec(`UPDATE "user" SET "twoFactorEnabled"=?,"updatedAt"=? WHERE "id"=?`, *ch.Enabled, s.date(sub.Now), uid); err != nil {
			return err
		}
	}
	if ch.CreateChallenge != "" {
		for _, item := range []struct{ id, value string }{{ch.CreateChallenge, uid}, {"2fa-attempts-" + ch.CreateChallenge, "0"}} {
			err := exec(`INSERT INTO "verification" ("id","identifier","value","expiresAt","createdAt","updatedAt") VALUES (?,?,?,?,?,?)`, rand.Text(), item.id, item.value, s.date(ch.ChallengeExpires), s.date(sub.Now), s.date(sub.Now))
			if err != nil {
				return err
			}
		}
	}
	if ch.ConsumeChallenge {
		if err := exec(`DELETE FROM "verification" WHERE "identifier" IN (?,?)`, sub.Challenge, "2fa-attempts-"+sub.Challenge); err != nil {
			return err
		}
	} else if ch.IncrementAttempts {
		if err := exec(`UPDATE "verification" SET "value"=?,"updatedAt"=? WHERE "identifier"=?`, strconv.Itoa(state.Attempts+1), s.date(sub.Now), "2fa-attempts-"+sub.Challenge); err != nil {
			return err
		}
	}
	if ch.RevokeSessions {
		if err := exec(`DELETE FROM "session" WHERE "userId"=?`, uid); err != nil {
			return err
		}
		if err := s.invalidateFactorChallenges(ctx, tx, uid); err != nil {
			return err
		}
	}
	if ch.Session != nil {
		if ch.Session.UserID != uid {
			return errors.New("sqlstore: session owner differs from factor owner")
		}
		if err := s.insertSession(ctx, tx, *ch.Session); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) invalidateFactorChallenges(ctx context.Context, tx *sql.Tx, uid string) error {
	// Challenge rows contain the account ID. Counters are harmless without a
	// challenge, but remove them as well while the account is locked.
	rows, err := tx.QueryContext(ctx, s.bind(`SELECT "identifier" FROM "verification" WHERE "value"=? AND "identifier" LIKE '2fa-%'`), uid)
	if err != nil {
		return err
	}
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		ids = append(ids, id)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	for _, id := range ids {
		if _, err = tx.ExecContext(ctx, s.bind(`DELETE FROM "verification" WHERE "identifier" IN (?,?)`), id, "2fa-attempts-"+id); err != nil {
			return err
		}
	}
	return nil
}
