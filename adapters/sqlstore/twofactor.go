package sqlstore

import (
	"context"
	"crypto/rand"
	"database/sql"
	"errors"
	"strconv"
	"strings"
	"time"

	auth "github.com/Plain-Auth/plain-auth"
	ak "github.com/Plain-Auth/plain-auth/plugins/apikey"
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
		q = `SELECT count(*) FROM pg_catalog.pg_attribute WHERE attrelid=pg_catalog.to_regclass('"user"') AND attname='twoFactorEnabled' AND attnum>0 AND NOT attisdropped`
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
	cols, fields := userColumns, userFields(&state.User)
	var finish func()
	if s.adminRole != "" {
		cols += "," + adminUserColumns
		fields, finish = s.adminUserScanner(&state.User)
	}
	err := tx.QueryRowContext(ctx, s.readForUpdate(`SELECT `+cols+`,u."twoFactorEnabled" FROM "user" u WHERE u."id"=?`), id).Scan(append(fields, &enabled)...)
	if errors.Is(err, sql.ErrNoRows) {
		return state, auth.ErrNotFound
	}
	if err != nil {
		return state, err
	}
	if finish != nil {
		finish()
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
	rec.Verified = verified.Valid && verified.Bool
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
	state.LastTOTPPeriod = 30 * time.Second
	if period, value, ok := strings.Cut(step, ":"); ok {
		seconds, err := strconv.ParseUint(period, 10, 32)
		if err != nil || seconds == 0 {
			return state, errors.New("invalid stored authenticator period")
		}
		state.LastTOTPPeriod = time.Duration(seconds) * time.Second
		step = value
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
	var sessionWhere string
	if sub.SessionToken != "" {
		parameter, _ := s.deviceTokenParameters([]string{sub.SessionToken})
		sessionWhere = `s."token"=` + parameter + ` AND s."expiresAt">?`
		q = `SELECT s."userId" FROM "session" s WHERE ` + sessionWhere
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
	admin, err := s.lockAllowedAccount(ctx, tx, owner, sub.Now)
	if err != nil {
		return err
	}
	if admin {
		// Only an owner's own session may rotate keys or enroll a new factor.
		sessionWhere += ` AND s."impersonatedBy" IS NULL`
	}
	var keyProof ak.SessionProof
	if sub.ApplicationKeyID != "" {
		var ok bool
		keyProof, ok = ak.SessionProofFrom(ctx)
		if !ok || keyProof.ID != sub.ApplicationKeyID || keyProof.UserID != owner {
			return auth.ErrNotFound
		}
		if err := s.lockKeySession(ctx, tx, keyProof, "twoFactor", "enable", time.Now()); err != nil {
			return err
		}
	}
	state, err := s.factorUser(ctx, tx, owner)
	if err != nil {
		return err
	}
	if err = s.checkPhoneLogin(ctx, tx, owner); err != nil {
		return err
	}
	if sub.SessionToken != "" {
		var ss auth.StoredSession
		err = tx.QueryRowContext(ctx, s.readForUpdate(`SELECT `+sessionColumns+` FROM "session" s WHERE `+sessionWhere+` AND s."userId"=?`), sub.SessionToken, s.date(sub.Now), owner).Scan(sessionFields(&ss)...)
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
	if sub.ReadDelivery {
		state.Delivery, err = s.readFactorDelivery(ctx, tx, factorDeliveryKey(sub, state))
		if err != nil {
			return err
		}
	}
	if sub.TrustedGrant != "" {
		var actual string
		err := tx.QueryRowContext(ctx, s.readForUpdate(`SELECT "identifier" FROM "verification" WHERE "identifier"=? AND "value"=? AND "expiresAt">?`), sub.TrustedGrant, owner, s.date(sub.Now)).Scan(&actual)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		if actual == sub.TrustedGrant {
			state.TrustedGrant = actual
		}
	}
	if sub.ApplicationOperation == "/two-factor/verify-totp" {
		if err := s.checkKeyEnrollment(ctx, tx, keyProof, state, sub.Now); err != nil {
			return err
		}
	}
	change, err := decide(state)
	if err != nil {
		return err
	}
	if err = s.writeFactorChange(ctx, tx, sub, state, change); err != nil {
		return err
	}
	if sub.ApplicationKeyID != "" {
		if err := s.saveKeyEnrollment(ctx, tx, keyProof, sub, state, change); err != nil {
			return err
		}
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
			seconds := int64(ch.UsedTOTPPeriod / time.Second)
			if seconds <= 0 {
				seconds = 30
			}
			value := strconv.FormatInt(seconds, 10) + ":" + strconv.FormatInt(*ch.UsedTOTPStep, 10)
			expiry := time.Unix((*ch.UsedTOTPStep+2)*seconds, 0).UTC()
			err := exec(`INSERT INTO "verification" ("id","identifier","value","expiresAt","createdAt","updatedAt") VALUES (?,?,?,?,?,?)`, rand.Text(), key, value, s.date(expiry), s.date(sub.Now), s.date(sub.Now))
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
	if err := s.writeFactorDelivery(ctx, tx, sub, state, ch); err != nil {
		return err
	}
	if ch.ConsumeChallenge {
		if err := exec(`DELETE FROM "verification" WHERE "identifier" IN (?,?,?,?)`, sub.Challenge, "2fa-attempts-"+sub.Challenge, "2fa-otp-"+sub.Challenge, pendingFactorDeliveryKey("2fa-otp-"+sub.Challenge)); err != nil {
			return err
		}
	} else if ch.IncrementAttempts {
		if err := exec(`UPDATE "verification" SET "value"=?,"updatedAt"=? WHERE "identifier"=?`, strconv.Itoa(state.Attempts+1), s.date(sub.Now), "2fa-attempts-"+sub.Challenge); err != nil {
			return err
		}
	}
	if ch.RevokeSessions {
		if _, err := s.deleteSessionsTx(ctx, tx, `"userId"=?`, uid); err != nil {
			return err
		}
		if err := s.invalidateFactorChallenges(ctx, tx, uid); err != nil {
			return err
		}
	}
	if ch.CreateTrustedGrant != "" {
		if state.TrustedGrant != "" {
			res, err := tx.ExecContext(ctx, s.bind(`DELETE FROM "verification" WHERE "identifier"=? AND "value"=? AND "expiresAt">?`), state.TrustedGrant, uid, s.date(sub.Now))
			if err != nil {
				return err
			}
			n, err := res.RowsAffected()
			if err != nil {
				return err
			}
			if n != 1 {
				return auth.ErrNotFound
			}
		}
		if err := exec(`DELETE FROM "verification" WHERE "value"=? AND "identifier" LIKE 'trust-device-%' AND "expiresAt"<=?`, uid, s.date(sub.Now)); err != nil {
			return err
		}
		if err := exec(`INSERT INTO "verification" ("id","identifier","value","expiresAt","createdAt","updatedAt") VALUES (?,?,?,?,?,?)`, rand.Text(), ch.CreateTrustedGrant, uid, s.date(ch.TrustedUntil), s.date(sub.Now), s.date(sub.Now)); err != nil {
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
	if _, err := tx.ExecContext(ctx, s.bind(`DELETE FROM "verification" WHERE "identifier" LIKE ?`), keyFactorPrefix(uid)+"%"); err != nil {
		return err
	}

	if _, err := tx.ExecContext(ctx, s.bind(`DELETE FROM "verification" WHERE "value"=? AND "identifier" LIKE 'trust-device-%'`), uid); err != nil {
		return err
	}
	sessionPattern := "2fa-otp-" + strings.NewReplacer("!", "!!", "%", "!%", "_", "!_").Replace(uid) + "!!%"
	if _, err := tx.ExecContext(ctx, s.bind(`DELETE FROM "verification" WHERE "identifier" LIKE ? ESCAPE '!' OR "identifier" LIKE ? ESCAPE '!'`), sessionPattern, pendingFactorDeliveryKey(sessionPattern)); err != nil {
		return err
	}
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
		if _, err = tx.ExecContext(ctx, s.bind(`DELETE FROM "verification" WHERE "identifier" IN (?,?,?,?)`), id, "2fa-attempts-"+id, "2fa-otp-"+id, pendingFactorDeliveryKey("2fa-otp-"+id)); err != nil {
			return err
		}
	}
	return nil
}
