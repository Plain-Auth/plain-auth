package sqlstore

import auth "github.com/Plain-Org/plain-auth"

func (t *adminTX) SelectPhoneFields() { t.phone = true }

func equalPhoneValue[T comparable](first, second *T) bool {
	if first == nil || second == nil {
		return first == second
	}
	return *first == *second
}

// The admin transaction already holds the target account lock. Change the two fields and revoke
// proofs for the previous and new numbers in the same commit.
func (t *adminTX) persistPhone(u auth.User) error {
	if !t.phone || u.PhoneNumberFields == nil {
		return nil
	}
	var prior auth.PhoneNumberFields
	err := t.tx.QueryRowContext(t.ctx, t.s.readForUpdate(`SELECT "phoneNumber","phoneNumberVerified" FROM "user" WHERE "id"=?`), u.ID).Scan(&prior.PhoneNumber, &prior.PhoneNumberVerified)
	if err != nil {
		return err
	}
	if equalPhoneValue(prior.PhoneNumber, u.PhoneNumber) && equalPhoneValue(prior.PhoneNumberVerified, u.PhoneNumberVerified) {
		return nil
	}
	_, err = t.tx.ExecContext(t.ctx, t.s.bind(`UPDATE "user" SET "phoneNumber"=?,"phoneNumberVerified"=? WHERE "id"=?`), u.PhoneNumber, u.PhoneNumberVerified, u.ID)
	if duplicateConstraint(err) {
		return auth.ErrPhoneNumberExists
	}
	if err != nil {
		return err
	}
	numbers := []*string{prior.PhoneNumber}
	if !equalPhoneValue(prior.PhoneNumber, u.PhoneNumber) {
		numbers = append(numbers, u.PhoneNumber)
	}
	for _, n := range numbers {
		if n == nil {
			continue
		}
		for _, p := range []auth.PhoneOTPPurpose{auth.PhoneVerify, auth.PhonePasswordReset} {
			if err = t.s.removePhoneProof(t.ctx, t.tx, phoneProofKey(*n, p)); err != nil {
				return err
			}
		}
	}
	return nil
}
