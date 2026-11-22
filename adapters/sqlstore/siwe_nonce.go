package sqlstore

import (
	"context"
	"crypto/sha256"
	"time"
)

// PrepareWalletNonceHistory installs an optional digest-only extension for a
// host generator. Spent or expired challenges can be pruned independently.
func (s *Store) PrepareWalletNonceHistory(ctx context.Context) error {
	const table = "plainauth_siwe_nonce_digest"
	return s.withMigrationConnection(ctx, func(db migrationConnection) error {
		exists, err := s.hasKeyOwnerTable(ctx, db, table)
		if err != nil {
			return err
		}
		if !exists {
			kind := "BLOB"
			switch s.dialect {
			case "postgres":
				kind = "bytea"
			case "mysql":
				kind = "varbinary(32)"
			}
			_, err = db.ExecContext(ctx, s.bind(`CREATE TABLE "plainauth_siwe_nonce_digest" ("digest" `+kind+` NOT NULL PRIMARY KEY)`))
			if err != nil {
				return err
			}
		}
		if err := s.checkDigestLedger(ctx, db, table); err != nil {
			return err
		}
		// Migrate outstanding challenges from a database that has only used
		// the built-in issuer so far. Repeating the scan is safe for live rows.
		const batch = 250
		var after string
		for {
			rows, err := db.QueryContext(ctx, s.bind(`SELECT "id","identifier","value" FROM "verification" WHERE "id">? AND "identifier" LIKE 'siwe:%' ORDER BY "id" LIMIT ?`), after, batch)
			if err != nil {
				return err
			}
			var digests []any
			count := 0
			for rows.Next() {
				var identifier, value string
				if err = rows.Scan(&after, &identifier, &value); err != nil {
					rows.Close()
					return err
				}
				count++
				if identifier == "siwe:"+value {
					digest := sha256.Sum256([]byte(value))
					digests = append(digests, digest[:])
				}
			}
			err = rows.Err()
			rows.Close()
			if err != nil {
				return err
			}
			if len(digests) > 0 {
				if err = s.mergeDigests(ctx, db, table, digests); err != nil {
					return err
				}
			}
			if count < batch {
				return nil
			}
		}
	})
}

// SaveCustomWalletNonce reserves the digest and issues its single-use challenge
// in one transaction.
func (s *Store) SaveCustomWalletNonce(ctx context.Context, nonce string, now, expires time.Time) error {
	return s.saveWalletNonce(ctx, nonce, now, expires, true)
}
