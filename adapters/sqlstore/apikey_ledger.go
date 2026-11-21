package sqlstore

import (
	"context"
	"crypto/sha256"
	"errors"
	"strings"
)

// PrepareAPIKeyLedger installs the adapter's non-expiring credential digest ledger
// and records every digest still in the canonical apikey table. Call this during
// a coordinated upgrade after pausing legacy key writers. Repeating it imports
// any additional live digests without changing keys or their ownership.
func (s *Store) PrepareAPIKeyLedger(ctx context.Context) error {
	return s.prepareAPIKeyLedger(ctx, true)
}

func (s *Store) prepareAPIKeyLedger(ctx context.Context, rescan bool) error {
	if err := s.CheckAPIKeySchema(ctx); err != nil {
		return err
	}
	err := s.withMigrationConnection(ctx, func(db migrationConnection) error {
		exists, err := s.hasKeyOwnerTable(ctx, db, "stonewrit_api_key_digest")
		if err != nil {
			return err
		}
		binaryType := "BLOB"
		switch s.dialect {
		case "postgres":
			binaryType = "bytea"
		case "mysql":
			binaryType = "varbinary(32)"
		}
		if !exists {
			q := `CREATE TABLE "stonewrit_api_key_digest" ("digest" ` + binaryType + ` NOT NULL PRIMARY KEY)`
			if _, err = db.ExecContext(ctx, s.bind(q)); err != nil {
				return err
			}
		}
		if err := s.checkAPIKeyLedger(ctx, db); err != nil {
			return err
		}
		// A one-byte completion marker cannot collide with a 32-byte fingerprint.
		// On MySQL, DDL and earlier batches may have committed before an interruption.
		// Only publish the marker after the last successful batch.
		version := []byte{1}
		if !rescan {
			var complete bool
			if err := db.QueryRowContext(ctx, s.bind(`SELECT EXISTS(SELECT 1 FROM "stonewrit_api_key_digest" WHERE "digest"=?)`), version).Scan(&complete); err != nil {
				return err
			}
			if complete {
				return nil
			}
		}
		if err := s.backfillAPIKeyLedger(ctx, db); err != nil {
			return err
		}
		return s.mergeAPIKeyDigests(ctx, db, []any{version})

	})
	if err == nil {
		s.apiKeyLedgerReady.Store(true)
	}
	return err
}

// Fingerprint the exact stored bytes. A noncanonical import may contain
// plaintext and must not copy recoverable credentials into permanent history.
func apiKeyFingerprint(stored string) []byte {
	hash := sha256.Sum256([]byte(stored))
	return hash[:]
}

func (s *Store) backfillAPIKeyLedger(ctx context.Context, db migrationConnection) error {
	const chunk = 256
	var after string
	first := true
	for {
		q := `SELECT "id","key" FROM "apikey"`
		var args []any
		if !first {
			q += ` WHERE "id">?`
			args = append(args, after)
		}
		rows, err := db.QueryContext(ctx, s.bind(q+` ORDER BY "id" LIMIT ?`), append(args, chunk)...)
		if err != nil {
			return err
		}
		var values []any
		for rows.Next() {
			var value string
			if err = rows.Scan(&after, &value); err != nil {
				rows.Close()
				return err
			}
			values = append(values, apiKeyFingerprint(value))
		}
		if err = rows.Err(); err != nil {
			rows.Close()
			return err
		}
		if err = rows.Close(); err != nil {
			return err
		}
		if len(values) == 0 {
			return nil
		}
		if err := s.mergeAPIKeyDigests(ctx, db, values); err != nil {
			return err
		}
		if len(values) < chunk {
			return nil
		}
		first = false
	}
}

func (s *Store) mergeAPIKeyDigests(ctx context.Context, db migrationConnection, values []any) error {
	q := `INSERT INTO "stonewrit_api_key_digest" ("digest") VALUES ` + strings.TrimSuffix(strings.Repeat("(?),", len(values)), ",")
	if s.dialect == "mysql" {
		q += ` ON DUPLICATE KEY UPDATE "digest"="stonewrit_api_key_digest"."digest"`
	} else {
		q += ` ON CONFLICT ("digest") DO NOTHING`
	}
	_, err := db.ExecContext(ctx, s.bind(q), values...)
	return err
}

func (s *Store) ensureAPIKeyLedger(ctx context.Context) error {
	if s.apiKeyLedgerReady.Load() {
		return nil
	}
	return s.prepareAPIKeyLedger(ctx, false)
}

// An existing extension table must enforce a whole, binary primary key. A table
// with the same name and a nonunique or text-collated column cannot reserve keys.
func (s *Store) checkAPIKeyLedger(ctx context.Context, db migrationConnection) error {
	var query string
	switch s.dialect {
	case "sqlite":
		query = `SELECT count(*)=1 AND count(CASE WHEN name='digest' AND upper(type)='BLOB' AND pk=1 AND "notnull"=1 THEN 1 END)=1 FROM pragma_table_info('stonewrit_api_key_digest')`
	case "postgres":
		query = `SELECT EXISTS(SELECT 1 FROM pg_constraint pk JOIN pg_attribute col ON col.attrelid=pk.conrelid AND pk.conkey=ARRAY[col.attnum]
		WHERE pk.conrelid=to_regclass('stonewrit_api_key_digest') AND pk.contype='p' AND col.attname='digest' AND col.atttypid='bytea'::regtype AND col.attnotnull)`
	case "mysql":
		query = `SELECT EXISTS(SELECT 1 FROM information_schema.columns c JOIN information_schema.statistics i
		ON i.table_schema=c.table_schema AND i.table_name=c.table_name AND i.column_name=c.column_name
		WHERE c.table_schema=DATABASE() AND c.table_name='stonewrit_api_key_digest' AND c.column_name='digest' AND c.data_type='varbinary' AND c.character_maximum_length=32
		AND i.index_name='PRIMARY' AND i.seq_in_index=1 AND i.sub_part IS NULL AND NOT EXISTS (SELECT 1 FROM information_schema.statistics j
		WHERE j.table_schema=c.table_schema AND j.table_name=c.table_name AND j.index_name='PRIMARY' AND j.seq_in_index>1))`
	}
	var valid bool
	if err := db.QueryRowContext(ctx, query).Scan(&valid); err != nil {
		return err
	}
	if !valid {
		return errors.New("sqlstore: invalid API key digest ledger; a full binary digest primary key is required")
	}
	return nil
}
