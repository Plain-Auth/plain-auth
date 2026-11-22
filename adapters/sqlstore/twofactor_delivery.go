package sqlstore

import (
	"context"
	"database/sql"
	"errors"
	"strconv"
	"strings"

	auth "github.com/Plain-Auth/plain-auth"
)

func factorDeliveryKey(sub auth.FactorSubject, st auth.FactorState) string {
	if sub.Challenge != "" {
		return "2fa-otp-" + sub.Challenge
	}
	if st.Session == nil {
		return ""
	}
	return "2fa-otp-" + st.User.ID + "!" + st.Session.ID
}
func (s *Store) readFactorDelivery(ctx context.Context, tx *sql.Tx, key string) (*auth.FactorDelivery, error) {
	var rec auth.FactorDelivery
	var value, identifier string
	err := tx.QueryRowContext(ctx, s.readForUpdate(`SELECT "id","identifier","value","createdAt","expiresAt" FROM "verification" WHERE "identifier" IN (?,?) ORDER BY "createdAt" DESC,"id" DESC LIMIT 1`), key, pendingFactorDeliveryKey(key)).Scan(&rec.ID, &identifier, &value, &rec.CreatedAt, &rec.ExpiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	rec.Pending = identifier == pendingFactorDeliveryKey(key)
	if identifier != key && !rec.Pending {
		return nil, nil
	}
	i := strings.LastIndexByte(value, ':')
	if i < 0 {
		return nil, errors.New("malformed factor delivery record")
	}
	rec.Stored = value[:i]
	rec.Attempts, err = strconv.Atoi(value[i+1:])
	if err != nil || rec.Attempts < 0 {
		return nil, errors.New("invalid factor delivery counter")
	}
	return &rec, nil
}
func (s *Store) writeFactorDelivery(ctx context.Context, tx *sql.Tx, sub auth.FactorSubject, state auth.FactorState, ch auth.FactorChange) error {
	if ch.SaveDelivery == nil && !ch.RemoveDelivery {
		return nil
	}
	key := factorDeliveryKey(sub, state)
	if key == "" {
		return errors.New("factor delivery has no session or challenge")
	}
	if _, err := tx.ExecContext(ctx, s.bind(`DELETE FROM "verification" WHERE "identifier" IN (?,?)`), key, pendingFactorDeliveryKey(key)); err != nil {
		return err
	}
	if d := ch.SaveDelivery; d != nil {
		if d.Pending {
			key = pendingFactorDeliveryKey(key)
		}
		_, err := tx.ExecContext(ctx, s.bind(`INSERT INTO "verification" ("id","identifier","value","expiresAt","createdAt","updatedAt") VALUES (?,?,?,?,?,?)`), d.ID, key, d.Stored+":"+strconv.Itoa(d.Attempts), s.date(d.ExpiresAt), s.date(d.CreatedAt), s.date(sub.Now))
		return err
	}
	return nil
}

func pendingFactorDeliveryKey(key string) string { return "pending-" + key }
