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

func (s *Store) ReadPhoneNumber(ctx context.Context, id string) (*auth.PhoneNumberFields, error) {
	var f auth.PhoneNumberFields
	err := s.db.QueryRowContext(ctx, s.bind(`SELECT u."phoneNumber",u."phoneNumberVerified" FROM "user" u WHERE u."id"=?`), id).Scan(&f.PhoneNumber, &f.PhoneNumberVerified)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, auth.ErrNotFound
	}
	return &f, err
}
func (s *Store) phoneOwner(ctx context.Context, tx *sql.Tx, number string) (auth.User, error) {
	var u auth.User
	f := &auth.PhoneNumberFields{}
	where := `u."phoneNumber"=?`
	if s.dialect == "mysql" {
		where = `BINARY u."phoneNumber"=BINARY ?`
	}
	columns, fields := userColumns, userFields(&u)
	var finish func()
	if s.adminRole != "" {
		columns += "," + adminUserColumns
		fields, finish = s.adminUserScanner(&u)
	}
	err := tx.QueryRowContext(ctx, s.readForUpdate(`SELECT `+columns+`,u."phoneNumber",u."phoneNumberVerified" FROM "user" u WHERE `+where), number).Scan(append(fields, &f.PhoneNumber, &f.PhoneNumberVerified)...)
	if errors.Is(err, sql.ErrNoRows) {
		return auth.User{}, nil
	}
	if err == nil && finish != nil {
		finish()
	}
	u.PhoneNumberFields = f
	return u, err
}
func (s *Store) PhoneCredential(ctx context.Context, n string) (auth.User, string, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return auth.User{}, "", err
	}
	defer tx.Rollback()
	u, err := s.phoneOwner(ctx, tx, n)
	if err != nil {
		return u, "", err
	}
	if u.ID == "" {
		return u, "", auth.ErrNotFound
	}
	hash, err := s.credentialHash(ctx, tx, u.ID)
	if err != nil {
		return u, "", err
	}
	return u, hash, tx.Commit()
}
func (s *Store) ReadPhoneOTP(ctx context.Context, n string, p auth.PhoneOTPPurpose) (*auth.PhoneOTPRecord, error) {
	key := phoneProofKey(n, p)
	var rec *auth.PhoneOTPRecord
	err := s.emailOTPTransaction(ctx, key, func(tx *sql.Tx) (error, error) {
		var err error
		rec, err = s.readPhoneProof(ctx, tx, key)
		return nil, err
	})
	return rec, err
}
func (s *Store) ClearPhoneProfile(ctx context.Context, id, token string, p auth.ProfileUpdate, now time.Time) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err = s.lockActiveAccount(ctx, tx, id, token, now); err != nil {
		return err
	}
	if err = s.updateProfile(ctx, tx, id, p, now); err != nil {
		return err
	}
	return tx.Commit()
}
func (s *Store) savePhone(ctx context.Context, r auth.PhoneOTPRecord, verified bool) (bool, error) {
	key := phoneProofKey(r.PhoneNumber, r.Purpose)
	var deliver bool
	err := s.emailOTPTransaction(ctx, key, func(tx *sql.Tx) (error, error) {
		u, err := s.phoneOwner(ctx, tx, r.PhoneNumber)
		if err != nil {
			return nil, err
		}
		deliver = r.Purpose != auth.PhonePasswordReset || u.ID != "" && (!verified || u.PhoneNumberVerified != nil && *u.PhoneNumberVerified)
		if err = s.removePhoneProof(ctx, tx, key); err != nil {
			return nil, err
		}
		insert := s.bind(`INSERT INTO "verification" ("id","identifier","value","expiresAt","createdAt","updatedAt") VALUES(?,?,?,?,?,?)`)
		now, expiry := s.date(r.CreatedAt), s.date(r.ExpiresAt)
		if _, err = tx.ExecContext(ctx, insert, r.ID, key.identifier, r.Code+":0", expiry, now, now); err != nil {
			return nil, err
		}
		_, err = tx.ExecContext(ctx, insert, rand.Text(), key.owner, r.ID+":"+u.ID, expiry, now, now)
		return nil, err
	})
	return deliver, err
}
func (s *Store) removePhoneProof(ctx context.Context, tx *sql.Tx, k emailOTPKey) error {
	_, err := tx.ExecContext(ctx, s.bind(`DELETE FROM "verification" WHERE `+s.phoneIdentifierMatch()+` OR `+s.phoneIdentifierMatch()), k.identifier, k.owner)
	return err
}
func (s *Store) SavePhoneReset(ctx context.Context, r auth.PhoneOTPRecord, verified bool) (bool, error) {
	return s.savePhone(ctx, r, verified)
}
func (s *Store) ApplyPhoneOTP(ctx context.Context, act auth.PhoneAccountAction) (auth.PhoneAccountResult, error) {
	key := phoneProofKey(act.Use.PhoneNumber, act.Use.Purpose)
	var out auth.PhoneAccountResult
	err := s.emailOTPTransaction(ctx, key, func(tx *sql.Tx) (error, error) {
		out = auth.PhoneAccountResult{}
		rec, denied, err := s.consumePhoneProof(ctx, tx, key, act.Use)
		if denied != nil || err != nil {
			return denied, err
		}
		user, err := s.phoneOwner(ctx, tx, act.Use.PhoneNumber)
		if err != nil {
			return nil, err
		}
		if rec.OwnerBound && rec.BoundOwner != user.ID {
			return &auth.APIError{Status: 400, Code: "INVALID_OTP", Message: "Invalid OTP"}, nil
		}
		if act.SourceID != "" {
			if err = s.lockActiveAccount(ctx, tx, act.SourceID, act.SourceToken, act.Use.Now); err != nil {
				if errors.Is(err, auth.ErrNotFound) {
					return &auth.APIError{Status: 401, Code: "USER_NOT_FOUND", Message: "User not found"}, nil
				}
				return nil, err
			}
			if user.ID != "" {
				return auth.ErrPhoneNumberExists, nil
			}
			if err = tx.QueryRowContext(ctx, s.bind(`SELECT `+userColumns+` FROM "user" u WHERE u."id"=?`), act.SourceID).Scan(userFields(&user)...); err != nil {
				return nil, err
			}
		}
		if act.Use.Purpose == auth.PhonePasswordReset {
			if user.ID == "" {
				return &auth.APIError{Status: 400, Code: "UNEXPECTED_ERROR", Message: "Unexpected error"}, nil
			}
			if act.RequireVerification && (user.PhoneNumberVerified == nil || !*user.PhoneNumberVerified) {
				return &auth.APIError{Status: 400, Code: "PHONE_NUMBER_PENDING_VERIFICATION", Message: "Phone number requires account ownership proof"}, nil
			}
			return nil, s.replaceResetCredential(ctx, tx, user.ID, act.PasswordHash, act.Use.Now, act.RevokeSessions)
		}
		if user.ID == "" {
			if act.Create == nil {
				return &auth.APIError{Status: 500, Code: "FAILED_TO_UPDATE_USER", Message: "Failed to update user"}, nil
			}
			user = *act.Create
			_, err = tx.ExecContext(ctx, s.bind(`INSERT INTO "user"("id","email","name","emailVerified","createdAt","updatedAt") VALUES (?,?,?,?,?,?)`), user.ID, user.Email, user.Name, false, s.date(act.Use.Now), s.date(act.Use.Now))
			if duplicateConstraint(err) {
				return nil, auth.ErrEmailTaken
			}
			if err != nil {
				return nil, err
			}
		}
		_, err = tx.ExecContext(ctx, s.bind(`UPDATE "user" SET "phoneNumber"=?,"phoneNumberVerified"=?,"updatedAt"=? WHERE "id"=?`), act.Use.PhoneNumber, true, s.date(act.Use.Now), user.ID)
		if duplicateConstraint(err) {
			return nil, auth.ErrPhoneNumberExists
		}
		if err != nil {
			return nil, err
		}
		user.UpdatedAt = act.Use.Now
		verified := true
		user.PhoneNumberFields = &auth.PhoneNumberFields{PhoneNumber: &act.Use.PhoneNumber, PhoneNumberVerified: &verified}
		out.User = user
		if act.Session != nil {
			// Another instance may have enabled the factor profile after this pool opened.
			hasFactor, err := s.detectFactorSchema(ctx, tx)
			if err != nil {
				return nil, err
			}
			if hasFactor {
				var enabled sql.NullBool
				if err = tx.QueryRowContext(ctx, s.bind(`SELECT "twoFactorEnabled" FROM "user" WHERE "id"=?`), user.ID).Scan(&enabled); err != nil {
					return nil, err
				}
				if enabled.Bool {
					out.NeedsFactor = true
					out.ExpectedHash, err = s.credentialHash(ctx, tx, user.ID)
					if errors.Is(err, auth.ErrNotFound) {
						err = nil
					}
					return nil, err
				}
			}
			ss := *act.Session
			ss.UserID = user.ID
			return nil, s.insertSession(ctx, tx, ss)
		}
		return nil, nil
	})
	return out, err
}
func (s *Store) bindPhoneProof(ctx context.Context, tx *sql.Tx, r *auth.PhoneOTPRecord, key emailOTPKey) error {
	var v string
	err := tx.QueryRowContext(ctx, s.bind(`SELECT "value" FROM "verification" WHERE "identifier"=?`), key.owner).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	id, owner, ok := strings.Cut(v, ":")
	if ok && id == r.ID {
		r.OwnerBound, r.BoundOwner = true, owner
	}
	return nil
}

// checkPhoneLogin runs after the caller has locked the canonical user row.
func (s *Store) checkPhoneLogin(ctx context.Context, tx *sql.Tx, userID string) error {
	binding, ok := auth.PhoneLoginFrom(ctx)
	if !ok {
		return nil
	}
	var f auth.PhoneNumberFields
	err := tx.QueryRowContext(ctx, s.readForUpdate(`SELECT "phoneNumber","phoneNumberVerified" FROM "user" WHERE "id"=?`), userID).Scan(&f.PhoneNumber, &f.PhoneNumberVerified)
	if errors.Is(err, sql.ErrNoRows) || err == nil && !binding.Matches(&f) {
		return &auth.APIError{Status: 401, Code: "INVALID_PHONE_NUMBER_OR_PASSWORD", Message: "Invalid phone number or password"}
	}
	return err
}
