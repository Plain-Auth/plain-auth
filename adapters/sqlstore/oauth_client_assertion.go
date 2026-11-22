package sqlstore

import (
	"context"
	"time"

	op "github.com/Plain-Auth/plain-auth/plugins/oauthprovider"
)

var _ op.ClientAssertionStore = (*Store)(nil)

func (s *Store) ConsumeOAuthClientAssertion(ctx context.Context, id, digest string, expires time.Time, check func(op.MachineClient) error) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	client, err := scanMachineClient(tx.QueryRowContext(ctx, s.readForUpdate(machineClientSelect), id), id)
	if err != nil {
		return err
	}
	if err := check(client); err != nil {
		return err
	}
	const insert = `INSERT INTO "oauthClientAssertion" ("id","expiresAt") VALUES (?,?)`
	if _, err := tx.ExecContext(ctx, s.bind(insert), digest, s.date(expires)); err != nil {
		if duplicateConstraint(err) {
			return op.ErrAssertionReplay
		}
		return err
	}
	return tx.Commit()
}
