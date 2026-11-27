package sqlstore

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	op "github.com/Plain-Org/plain-auth/plugins/oauthprovider"
)

var _ op.ClientAssertionStore = (*Store)(nil)
var _ op.ClientKeyRotationStore = (*Store)(nil)
var _ op.ClientAssertionReplayStore = (*Store)(nil)

// ReserveOAuthClientAssertion spends an extension strategy's assertion
// digest once. The row's primary key makes the spend atomic across
// processes, and the digest shares the table with private_key_jwt.
func (s *Store) ReserveOAuthClientAssertion(ctx context.Context, digest string, expires time.Time) error {
	const insert = `INSERT INTO "oauthClientAssertion" ("id","expiresAt") VALUES (?,?)`
	if _, err := s.db.ExecContext(ctx, s.bind(insert), digest, s.date(expires)); err != nil {
		if duplicateConstraint(err) {
			return op.ErrAssertionReplay
		}
		return err
	}
	return nil
}

func (s *Store) ConsumeOAuthClientAssertion(ctx context.Context, id, digest string, expires time.Time, check func(op.MachineClient) error) error {
	return s.useOAuthClientAssertion(ctx, id, digest, expires, nil, check)
}

func (s *Store) RotateOAuthClientKeys(ctx context.Context, id, digest string, expires time.Time, keys json.RawMessage, check func(op.MachineClient) error) error {
	if len(keys) == 0 {
		return errors.New("sqlstore: missing replacement key set")
	}
	return s.useOAuthClientAssertion(ctx, id, digest, expires, keys, check)
}

func (s *Store) useOAuthClientAssertion(ctx context.Context, id, digest string, expires time.Time, keys json.RawMessage, check func(op.MachineClient) error) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	client, err := scanMachineClient(tx.QueryRowContext(ctx, s.readForUpdate(machineClientSelect), id, op.ResolvedDiscovery(ctx, id)), id)
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
	if keys != nil {
		const update = `UPDATE "oauthClient" SET "jwks"=?, "updatedAt"=? WHERE "id"=? AND "clientId"=?`
		if _, err := tx.ExecContext(ctx, s.bind(update), string(keys), s.date(time.Now().UTC()), client.RowID, id); err != nil {
			return err
		}
	}
	return tx.Commit()
}
