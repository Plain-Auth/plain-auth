package sqlstore

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"time"

	op "github.com/Plain-Auth/plain-auth/plugins/oauthprovider"
)

var _ op.DPoPReplayStore = (*Store)(nil)

func (s *Store) verificationReservationID(identifier string) string {
	hash := sha256.Sum256([]byte("reserve:" + identifier))
	if s.dialect != "mysql" {
		return base64.RawURLEncoding.EncodeToString(hash[:])
	}
	// The canonical MySQL primary key fits the UUID form of the reservation.
	hash[6] = hash[6]&15 | 0x50
	hash[8] = hash[8]&63 | 0x80
	v := hex.EncodeToString(hash[:16])
	return v[:8] + "-" + v[8:12] + "-" + v[12:16] + "-" + v[16:20] + "-" + v[20:]
}

// ReserveDPoPProof records a verified proof in the shared verification table.
// The primary key elects one winner, including concurrent reservations made
// from independent processes. Cleanup only removes expired proof reservations.
func (s *Store) ReserveDPoPProof(ctx context.Context, key string, now, expires time.Time) (bool, error) {
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(key)
	if err != nil || len(decoded) != sha256.Size || len(key) != 43 || !expires.After(now) {
		return false, errors.New("sqlstore: invalid DPoP replay reservation")
	}
	identifier := "dpop-proof:" + key
	id := s.verificationReservationID(identifier)
	cutoff := s.date(now)
	next := s.dpopNextSweep.Load()
	if now.Unix() >= next && s.dpopNextSweep.CompareAndSwap(next, now.Add(time.Minute).Unix()) {
		_, err = s.db.ExecContext(ctx, s.bind(`DELETE FROM "verification" WHERE "identifier" LIKE 'dpop-proof:%' AND "expiresAt"<=?`), cutoff)
	} else {
		_, err = s.db.ExecContext(ctx, s.bind(`DELETE FROM "verification" WHERE "id"=? AND "identifier"=? AND "expiresAt"<=?`), id, identifier, cutoff)
	}
	if err != nil {
		return false, err
	}
	const insert = `INSERT INTO "verification" ("id","identifier","value","expiresAt","createdAt","updatedAt") VALUES(?,?,?,?,?,?)`
	_, err = s.db.ExecContext(ctx, s.bind(insert), id, identifier, key, s.date(expires), cutoff, cutoff)
	if duplicateConstraint(err) {
		return false, nil
	}
	return err == nil, err
}
