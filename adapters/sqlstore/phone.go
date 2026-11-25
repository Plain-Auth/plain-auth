package sqlstore

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"

	auth "github.com/Plain-Org/plain-auth"
)

func (s *Store) CheckPhoneNumberSchema(ctx context.Context) error {
	rows, err := s.db.QueryContext(ctx, s.bind(`SELECT u."phoneNumber",u."phoneNumberVerified" FROM "user" u WHERE 1=0`))
	if err != nil {
		return err
	}
	return rows.Close()
}
func phoneProofKey(n string, purpose auth.PhoneOTPPurpose) emailOTPKey {
	prefix := "phone-number-otp-"
	if purpose == auth.PhonePasswordReset {
		prefix = "phone-number-reset-"
	}
	id := prefix + n
	hash := sha256.Sum256([]byte(id))
	digest := hex.EncodeToString(hash[:])
	if len(id) > 255 {
		id = "phone-proof-sha256-" + digest
	}
	return emailOTPKey{identifier: id, owner: "phone-proof-owner:" + digest, digest: digest}
}
func (s *Store) phoneIdentifierMatch() string {
	if s.dialect == "mysql" {
		return `BINARY "identifier"=BINARY ?`
	}
	return `"identifier"=?`
}
func (s *Store) SavePhoneOTP(ctx context.Context, r auth.PhoneOTPRecord) error {
	_, err := s.savePhone(ctx, r, false)
	return err
}

var _ auth.PhoneOTPReporter = (*Store)(nil)

// ReportsPhoneOTPDecisions marks the store as reporting, through
// PhoneOTPUse.Decided, what it commits to a phone code.
func (*Store) ReportsPhoneOTPDecisions() {}

func (s *Store) ConsumePhoneOTP(ctx context.Context, u auth.PhoneOTPUse) error {
	key := phoneProofKey(u.PhoneNumber, u.Purpose)
	var decision auth.PhoneOTPDecision
	committed, err := s.codeTransaction(ctx, key, func(tx *sql.Tx) (error, error) {
		decision = auth.PhoneKeepProof
		_, denied, err := s.consumePhoneProof(ctx, tx, key, u, &decision)
		return denied, err
	})
	reportCode(u.Decided, committed, decision)
	return err
}

// consumePhoneProof judges u against the code stored under key and writes
// the decision, which it also records in decided.
func (s *Store) consumePhoneProof(ctx context.Context, tx *sql.Tx, key emailOTPKey, u auth.PhoneOTPUse, decided *auth.PhoneOTPDecision) (*auth.PhoneOTPRecord, error, error) {
	rec, err := s.readPhoneProof(ctx, tx, key)
	if err != nil {
		return nil, nil, err
	}
	decision, denied := u.Check(rec)
	*decided = decision
	switch decision {
	case auth.PhoneCountAttempt:
		_, err = tx.ExecContext(ctx, s.bind(`UPDATE "verification" SET "value"=?,"updatedAt"=? WHERE "id"=?`), rec.Code+":"+strconv.Itoa(rec.Attempts+1), s.date(u.Now), rec.ID)
	case auth.PhoneRemoveProof:
		err = s.removePhoneProof(ctx, tx, key)
	}
	return rec, denied, err
}
func (s *Store) readPhoneProof(ctx context.Context, tx *sql.Tx, key emailOTPKey) (*auth.PhoneOTPRecord, error) {
	var rec auth.PhoneOTPRecord
	var raw string
	err := tx.QueryRowContext(ctx, s.readForUpdate(`SELECT "id","value","expiresAt" FROM "verification" WHERE `+s.phoneIdentifierMatch()+` ORDER BY "createdAt" DESC,"id" DESC LIMIT 1`), key.identifier).Scan(&rec.ID, &raw, &rec.ExpiresAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	code, attempts, counted := strings.Cut(raw, ":")
	rec.Code = code
	if counted {
		rec.Attempts, err = strconv.Atoi(attempts)
		if err != nil || rec.Attempts < 0 {
			return nil, errors.New("invalid phone OTP attempt count")
		}
	}
	return &rec, s.bindPhoneProof(ctx, tx, &rec, key)
}
