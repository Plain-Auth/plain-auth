package sqlstore

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"
	"time"

	auth "github.com/Plain-Auth/plain-auth"
)

var _ auth.EmailOTPStore = (*Store)(nil)

type emailOTPKey struct{ identifier, owner, digest string }

func newEmailOTPKey(req auth.EmailOTPRequest) emailOTPKey {
	address := req.Email
	if req.Source != nil {
		address = req.Source.UserID + ":" + address
	}
	id := string(req.Purpose) + "-otp-" + address
	sum := sha256.Sum256([]byte(id))
	digest := hex.EncodeToString(sum[:])
	// MySQL's canonical verification.identifier has a 255-character limit.
	if len(id) > 255 {
		id = string(req.Purpose) + "-otp-sha256:" + digest
	}
	return emailOTPKey{id, "email-otp-owner:" + digest, digest}
}

// A mailbox can have no row yet. Serializing on the logical key also covers
// concurrent first issuance, across separate processes and connection pools.
// Business denials commit attempt counts and expiry/replay cleanup.
func (s *Store) emailOTPTransaction(ctx context.Context, key emailOTPKey, run func(*sql.Tx) (denial, errorDB error)) error {
	var err error
	for range 3 {
		err = s.emailOTPTransactionOnce(ctx, key, run)
		if !retryIdentity(err) {
			break
		}
	}
	return err
}
func (s *Store) emailOTPTransactionOnce(ctx context.Context, key emailOTPKey, run func(*sql.Tx) (error, error)) error {
	const lockName = "SHA2(CONCAT(DATABASE(), '/auth/email-otp/', ?), 256)"
	tx, end, err := s.beginTransactionWithMySQLLock(ctx, nil, lockName, 15, errors.New("email OTP mailbox lock unavailable"), key.digest)
	if err != nil {
		return err
	}
	defer end.rollback()
	if s.dialect == "postgres" {
		if _, err = tx.ExecContext(ctx, "SELECT pg_advisory_xact_lock(hashtextextended($1,0))", key.owner); err != nil {
			return err
		}
	}
	denial, err := run(tx)
	if err != nil {
		return err
	}
	if err = end.commit(); err != nil {
		return err
	}
	return denial
}

type storedEmailOTP struct {
	auth.EmailOTPRecord
	id string
}

func (s *Store) readEmailOTP(ctx context.Context, tx *sql.Tx, key emailOTPKey) (*storedEmailOTP, error) {
	var rec storedEmailOTP
	var value, actual string
	err := tx.QueryRowContext(ctx, s.readForUpdate(`SELECT "id","identifier","value","expiresAt" FROM "verification" WHERE "identifier"=? ORDER BY "createdAt" DESC,"id" DESC LIMIT 1`), key.identifier).Scan(&rec.id, &actual, &value, &rec.ExpiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if actual != key.identifier {
		return nil, nil
	}
	rec.Stored = value
	if i := strings.LastIndexByte(value, ':'); i >= 0 {
		rec.Stored = value[:i]
		rec.Attempts, err = strconv.Atoi(value[i+1:])
		if err != nil || rec.Attempts < 0 {
			return nil, errors.New("invalid stored email OTP attempt count")
		}
	}
	return &rec, nil
}
func (s *Store) emailOTPUser(ctx context.Context, tx *sql.Tx, email string) (auth.User, error) {
	var u auth.User
	err := tx.QueryRowContext(ctx, s.readForUpdate(`SELECT `+userColumns+` FROM "user" u WHERE u."email"=?`), email).Scan(userFields(&u)...)
	if errors.Is(err, sql.ErrNoRows) {
		return auth.User{}, nil
	}
	return u, err
}

// A successful preflight in another runtime may replace the physical row.
// Bind to the stored proof so that its owner survives such a replacement.
func emailOTPBinding(stored string) string {
	digest := sha256.Sum256([]byte(stored))
	return hex.EncodeToString(digest[:])
}
func (s *Store) sameOTPOwner(ctx context.Context, tx *sql.Tx, key emailOTPKey, rec *storedEmailOTP, id string) (bool, error) {
	var binding string
	err := tx.QueryRowContext(ctx, s.readForUpdate(`SELECT "value" FROM "verification" WHERE "identifier"=?`), key.owner).Scan(&binding)
	if errors.Is(err, sql.ErrNoRows) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	challenge, owner, ok := strings.Cut(binding, ":")
	if !ok {
		return false, errors.New("invalid email OTP ownership binding")
	}
	// A different proof can have been issued by another implementation.
	return challenge != emailOTPBinding(rec.Stored) || owner == id, nil
}
func (s *Store) clearEmailOTP(ctx context.Context, tx *sql.Tx, key emailOTPKey) error {
	_, err := tx.ExecContext(ctx, s.bind(`DELETE FROM "verification" WHERE "identifier" IN (?,?)`), key.identifier, key.owner)
	return err
}

func (s *Store) SaveEmailOTP(ctx context.Context, req auth.EmailOTPRequest, allowNew bool, expires time.Time, prepare func(*auth.EmailOTPRecord) (string, string, int, error)) (string, error) {
	key := newEmailOTPKey(req)
	var delivery string
	err := s.emailOTPTransaction(ctx, key, func(tx *sql.Tx) (error, error) {
		delivery = ""
		var owner string
		if req.Source != nil {
			denial, err := s.authorizeEmailOTPChange(ctx, tx, req)
			if denial != nil || err != nil {
				return denial, err
			}
			other, err := s.emailOTPUser(ctx, tx, req.Email)
			if err != nil {
				return nil, err
			}
			if other.ID != "" {
				return nil, s.clearEmailOTP(ctx, tx, key)
			}
			owner = req.Source.UserID + ":" + req.Source.Email
		} else {
			u, err := s.emailOTPUser(ctx, tx, req.Email)
			if err != nil {
				return nil, err
			}
			owner = u.ID
			if owner == "" && !allowNew {
				return nil, s.clearEmailOTP(ctx, tx, key)
			}
		}
		prior, err := s.readEmailOTP(ctx, tx, key)
		if err != nil {
			return nil, err
		}
		var state *auth.EmailOTPRecord
		if prior != nil {
			bound, err := s.sameOTPOwner(ctx, tx, key, prior, owner)
			if err != nil {
				return nil, err
			}
			if bound {
				state = &prior.EmailOTPRecord
			}
		}
		raw, stored, attempts, err := prepare(state)
		if err != nil {
			return nil, err
		}
		if err = s.clearEmailOTP(ctx, tx, key); err != nil {
			return nil, err
		}
		insert := s.bind(`INSERT INTO "verification" ("id","identifier","value","expiresAt","createdAt","updatedAt") VALUES (?,?,?,?,?,?)`)
		id := rand.Text()
		now := s.date(req.Now)
		if _, err = tx.ExecContext(ctx, insert, id, key.identifier, stored+":"+strconv.Itoa(attempts), s.date(expires), now, now); err != nil {
			return nil, err
		}
		if owner != "" {
			if _, err = tx.ExecContext(ctx, insert, rand.Text(), key.owner, emailOTPBinding(stored)+":"+owner, s.date(expires), now, now); err != nil {
				return nil, err
			}
		}
		delivery = raw
		return nil, nil
	})
	return delivery, err
}

func (s *Store) UseEmailOTPRegistration(ctx context.Context, act auth.EmailOTPAction, matches func(string) (bool, error), fields auth.EmailOTPRegistrationFields) (auth.User, error) {
	if fields == nil || act.Purpose != auth.OTPSignIn || act.Source != nil || act.CheckOnly || act.Session.Token == "" || !act.AllowSignUp {
		return auth.User{}, errors.New("invalid email OTP registration action")
	}
	return s.useEmailOTP(ctx, act, matches, false, fields)
}

func (s *Store) UseEmailOTP(ctx context.Context, act auth.EmailOTPAction, matches func(string) (bool, error)) (auth.User, error) {
	return s.useEmailOTP(ctx, act, matches, false, nil)
}

// ConsumeObservedEmailOTP spends a valid code without verifying the address.
func (s *Store) ConsumeObservedEmailOTP(ctx context.Context, req auth.EmailOTPRequest, matches func(string) (bool, error)) (auth.User, error) {
	if req.Observation == nil || req.Observation.ID == "" || !req.Observation.ExpiresAt.After(req.Now) || !(req.Purpose == auth.OTPVerifyEmail && req.Source == nil || req.Purpose == auth.OTPChangeEmail && req.Source != nil) || req.CurrentMatches != nil {
		return auth.User{}, errors.New("invalid observed email OTP verification")
	}
	return s.useEmailOTP(ctx, auth.EmailOTPAction{EmailOTPRequest: req, MaxAttempts: req.MaxAttempts}, matches, true, nil)
}

// UseEmailOTPBeforeVerification commits one recovery proof, the new password,
// and requested session revocation, leaving mailbox verification to the caller.
func (s *Store) UseEmailOTPBeforeVerification(ctx context.Context, act auth.EmailOTPAction, matches func(string) (bool, error)) (auth.User, error) {
	if act.Purpose != auth.OTPResetPassword || act.PasswordHash == "" || act.Source != nil || act.CheckOnly || act.Session.Token != "" {
		return auth.User{}, errors.New("invalid email OTP password reset action")
	}
	return s.useEmailOTP(ctx, act, matches, true, nil)
}

func (s *Store) useEmailOTP(ctx context.Context, act auth.EmailOTPAction, matches func(string) (bool, error), deferVerification bool, fields auth.EmailOTPRegistrationFields) (auth.User, error) {
	key := newEmailOTPKey(act.EmailOTPRequest)
	invalid := &auth.APIError{Status: 400, Code: "INVALID_OTP", Message: "Invalid OTP"}
	missing := &auth.APIError{Status: 400, Code: "USER_NOT_FOUND", Message: "User not found"}
	var user auth.User
	err := s.emailOTPTransaction(ctx, key, func(tx *sql.Tx) (error, error) {
		user = auth.User{}
		rec, denial, err := s.checkEmailOTP(ctx, tx, key, act.Now, act.MaxAttempts, matches)
		if denial != nil || err != nil {
			return denial, err
		}
		if act.Source != nil {
			denial, err = s.authorizeEmailOTPChange(ctx, tx, act.EmailOTPRequest)
			if denial != nil || err != nil {
				return denial, err
			}
			bound, err := s.sameOTPOwner(ctx, tx, key, rec, act.Source.UserID+":"+act.Source.Email)
			if err != nil {
				return nil, err
			}
			if !bound {
				return invalid, s.clearEmailOTP(ctx, tx, key)
			}
			if err = s.clearEmailOTP(ctx, tx, key); err != nil {
				return nil, err
			}
			target, err := s.emailOTPUser(ctx, tx, act.Email)
			if err != nil {
				return nil, err
			}
			if target.ID != "" {
				return &auth.APIError{Status: 400, Code: "BAD_REQUEST", Message: "Email already in use"}, nil
			}
			if deferVerification {
				user, err = s.emailOTPUser(ctx, tx, act.Source.Email)
				if err == nil && (user.ID != act.Source.UserID || user.Email != act.Source.Email) {
					return invalid, nil
				}
				if err == nil {
					err = s.saveVerificationReceipt(ctx, tx, act.ObservationReceipt(user), act.Now)
				}
				return nil, err
			}
			_, err = tx.ExecContext(ctx, s.bind(`UPDATE "user" SET "email"=?,"emailVerified"=?,"updatedAt"=? WHERE "id"=? AND "email"=?`), act.Email, true, s.date(act.Now), act.Source.UserID, act.Source.Email)
			return nil, err
		}
		user, err = s.emailOTPUser(ctx, tx, act.Email)
		if err != nil {
			return nil, err
		}
		bound, err := s.sameOTPOwner(ctx, tx, key, rec, user.ID)
		if err != nil {
			return nil, err
		}
		if !bound {
			return invalid, s.clearEmailOTP(ctx, tx, key)
		}
		if act.CheckOnly {
			if user.ID == "" {
				return missing, nil
			}
			return nil, nil
		}
		if err = s.clearEmailOTP(ctx, tx, key); err != nil {
			return nil, err
		}
		if user.ID == "" && act.Purpose != auth.OTPSignIn {
			return missing, nil
		}
		if deferVerification && act.Purpose == auth.OTPVerifyEmail && user.Email != act.Email {
			return invalid, nil
		}
		switch act.Purpose {
		case auth.OTPSignIn:
			if user.ID == "" {
				if !act.AllowSignUp {
					return invalid, nil
				}
				user = act.NewUser
				user.Email = act.Email
				user.EmailVerified = true
				user.CreatedAt = act.Now
				user.UpdatedAt = act.Now
				var values auth.UserFieldValues
				if fields != nil {
					values, err = fields()
					if err != nil {
						return err, nil
					}
				}
				query, args := s.userInsert(user, values.Columns())
				_, err = tx.ExecContext(ctx, s.bind(query), args...)
				if err != nil {
					return nil, err
				}
			} else if !user.EmailVerified {
				if err = s.promoteMagicLinkOwner(ctx, tx, user.ID, act.Session); err != nil {
					return nil, err
				}
				user.EmailVerified = true
				user.UpdatedAt = act.Now
			}
			session := act.Session
			session.UserID = user.ID
			return nil, s.insertSession(ctx, tx, session)
		case auth.OTPResetPassword:
			if act.PasswordHash == "" {
				return nil, errors.New("empty OTP reset password hash")
			}
			if err = s.replaceResetCredential(ctx, tx, user.ID, act.PasswordHash, act.Now, act.RevokeSessions); err != nil {
				return nil, err
			}
		case auth.OTPVerifyEmail:
			if deferVerification {
				return nil, s.saveVerificationReceipt(ctx, tx, act.ObservationReceipt(user), act.Now)
			}
		default:
			return nil, errors.New("unsupported email OTP action")
		}
		if !deferVerification && !user.EmailVerified {
			_, err = tx.ExecContext(ctx, s.bind(`UPDATE "user" SET "emailVerified"=?,"updatedAt"=? WHERE "id"=?`), true, s.date(act.Now), user.ID)
			user.EmailVerified = true
			user.UpdatedAt = act.Now
		}
		if err == nil && act.Purpose == auth.OTPVerifyEmail && act.Session.Token != "" {
			session := act.Session
			session.UserID = user.ID
			err = s.insertSession(ctx, tx, session)
		}
		return nil, err
	})
	return user, err
}

func (s *Store) checkEmailOTP(ctx context.Context, tx *sql.Tx, key emailOTPKey, now time.Time, maxAttempts int, matches func(string) (bool, error)) (*storedEmailOTP, error, error) {
	invalid := &auth.APIError{Status: 400, Code: "INVALID_OTP", Message: "Invalid OTP"}
	rec, err := s.readEmailOTP(ctx, tx, key)
	if err != nil {
		return nil, nil, err
	}
	if rec == nil {
		return nil, invalid, nil
	}
	if !rec.ExpiresAt.After(now) {
		return nil, &auth.APIError{Status: 400, Code: "OTP_EXPIRED", Message: "OTP expired"}, s.clearEmailOTP(ctx, tx, key)
	}
	if rec.Attempts >= maxAttempts {
		return nil, &auth.APIError{Status: 403, Code: "TOO_MANY_ATTEMPTS", Message: "Too many attempts"}, s.clearEmailOTP(ctx, tx, key)
	}
	valid, err := matches(rec.Stored)
	if err != nil {
		return nil, nil, err
	}
	if !valid {
		_, err = tx.ExecContext(ctx, s.bind(`UPDATE "verification" SET "value"=?,"updatedAt"=? WHERE "id"=?`), rec.Stored+":"+strconv.Itoa(rec.Attempts+1), s.date(now), rec.id)
		return nil, invalid, err
	}
	return rec, nil, nil
}

func (s *Store) ReadEmailOTP(ctx context.Context, req auth.EmailOTPRequest) (*auth.EmailOTPRecord, error) {
	key := newEmailOTPKey(req)
	var found *auth.EmailOTPRecord
	err := s.emailOTPTransaction(ctx, key, func(tx *sql.Tx) (error, error) {
		rec, err := s.readEmailOTP(ctx, tx, key)
		if err != nil {
			return nil, err
		}
		if rec != nil && rec.ExpiresAt.After(req.Now) {
			found = &rec.EmailOTPRecord
		}
		return nil, nil
	})
	return found, err
}

func (s *Store) authorizeEmailOTPChange(ctx context.Context, tx *sql.Tx, req auth.EmailOTPRequest) (error, error) {
	src := req.Source
	if req.Purpose != auth.OTPChangeEmail || src.UserID == "" || src.SessionToken == "" {
		return nil, errors.New("invalid email OTP source")
	}
	if err := s.lockActiveAccount(ctx, tx, src.UserID, src.SessionToken, req.Now); err != nil {
		if errors.Is(err, auth.ErrNotFound) {
			return &auth.APIError{Status: 401, Code: "UNAUTHORIZED", Message: "Invalid session"}, nil
		}
		return nil, err
	}
	owner, err := s.emailOTPUser(ctx, tx, src.Email)
	if err != nil {
		return nil, err
	}
	if owner.ID != src.UserID {
		return &auth.APIError{Status: 400, Code: "INVALID_OTP", Message: "Invalid OTP"}, nil
	}
	if req.CurrentMatches == nil {
		return nil, nil
	}
	key := newEmailOTPKey(auth.EmailOTPRequest{Email: src.Email, Purpose: auth.OTPVerifyEmail})
	rec, denial, err := s.checkEmailOTP(ctx, tx, key, req.Now, req.MaxAttempts, req.CurrentMatches)
	if denial != nil || err != nil {
		return denial, err
	}
	bound, err := s.sameOTPOwner(ctx, tx, key, rec, src.UserID)
	if err != nil {
		return nil, err
	}
	if !bound {
		return &auth.APIError{Status: 400, Code: "INVALID_OTP", Message: "Invalid OTP"}, s.clearEmailOTP(ctx, tx, key)
	}
	return nil, s.clearEmailOTP(ctx, tx, key)
}

// FinishObservedEmailOTP commits the mailbox mutation after the host callback.
// The spent code cannot be used to switch accounts or to revive a lost session.
func (s *Store) FinishObservedEmailOTP(ctx context.Context, req auth.EmailOTPRequest, before auth.User) (auth.User, error) {
	started := time.Now()
	invalid := &auth.APIError{Status: 400, Code: "INVALID_OTP", Message: "Invalid OTP"}
	if req.Observation == nil || req.Observation.ID == "" || before.ID == "" || req.Source == nil && (req.Purpose != auth.OTPVerifyEmail || before.Email != req.Email) ||
		req.Source != nil && (req.Purpose != auth.OTPChangeEmail || req.Source.Email != before.Email || req.Source.UserID != before.ID || req.CurrentMatches != nil) {
		return auth.User{}, invalid
	}
	tx, err := s.beginMembershipChange(ctx)
	if err != nil {
		return auth.User{}, err
	}
	defer tx.Rollback()
	if req.Source != nil {
		denial, err := s.authorizeEmailOTPChange(ctx, tx, req)
		if err != nil {
			return auth.User{}, err
		}
		if denial != nil {
			return auth.User{}, denial
		}
	}
	owner, err := s.emailOTPUser(ctx, tx, before.Email)
	if err != nil {
		return auth.User{}, err
	}
	if owner.ID != before.ID || owner.Email != before.Email || !owner.UpdatedAt.Equal(before.UpdatedAt) {
		return auth.User{}, invalid
	}
	if req.Source != nil {
		other, err := s.emailOTPUser(ctx, tx, req.Email)
		if err != nil {
			return auth.User{}, err
		}
		if other.ID != "" {
			return auth.User{}, &auth.APIError{Status: 400, Code: "BAD_REQUEST", Message: "Email already in use"}
		}
	}
	valid, err := s.takeVerificationReceipt(ctx, tx, req.ObservationReceipt(before), req.Now.Add(time.Since(started)))
	if err != nil {
		return auth.User{}, err
	}
	if !valid {
		return auth.User{}, invalid
	}
	_, err = tx.ExecContext(ctx, s.bind(`UPDATE "user" SET "email"=?,"emailVerified"=?,"updatedAt"=? WHERE "id"=?`), req.Email, true, s.date(req.Now), owner.ID)
	if err != nil {
		if req.Source != nil {
			if rollbackErr := tx.Rollback(); rollbackErr == nil {
				if other, lookupErr := s.FindAccountUser(ctx, req.Email); lookupErr == nil && other.ID != owner.ID {
					return auth.User{}, &auth.APIError{Status: 400, Code: "BAD_REQUEST", Message: "Email already in use"}
				}
			}
		}
		return auth.User{}, err
	}
	after, err := s.emailOTPUser(ctx, tx, req.Email)
	if err != nil {
		return auth.User{}, err
	}
	if after.Email != req.Email || after.ID != owner.ID {
		return auth.User{}, invalid
	}
	if v := req.ObservationAttempt(after); v.NewSession != nil {
		_, allowed, err := s.emailVerificationSessionPolicy(ctx, tx, v)
		if err != nil {
			return auth.User{}, err
		}
		if allowed {
			if err := s.saveVerificationReceipt(ctx, tx, v.SessionReceipt(after), req.Now); err != nil {
				return auth.User{}, err
			}
		}
	}
	return after, tx.Commit()
}
