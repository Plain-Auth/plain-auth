package sqlstore

import (
	"context"
	"errors"
	"strings"

	"github.com/Plain-Auth/plain-auth/internal/walletschema"
	"github.com/Plain-Auth/plain-auth/plugins/siwe"
	"github.com/Plain-Auth/plain-auth/schema"
)

var errWalletLayout = errors.New("siwe: wallet associations disagree with the configured schema; check the wallet mapping on every node")

func (s *Store) walletNames() walletschema.Mapping {
	if s.walletQueryNames == nil {
		return walletschema.Default()
	}
	return s.walletMapping
}

func (s *Store) walletSQL(q string) string { return s.bind(s.mapWalletSQL(q)) }

func (s *Store) mapWalletSQL(q string) string {
	if s.walletQueryNames != nil {
		q = s.walletQueryNames.Replace(q)
	}
	return q
}

func (s *Store) CheckWalletMapping(_ context.Context, configured siwe.Schema) error {
	m, err := schema.NormalizeWallet(configured)
	if err != nil {
		return err
	}
	if m != s.walletNames() {
		return errWalletLayout
	}
	return nil
}

func (s *Store) preflightWalletMapping(ctx context.Context, db migrationConnection) error {
	m := s.walletNames()
	canonical := walletschema.Default()
	if m.Table != canonical.Table {
		exists, err := s.tableExists(ctx, db, canonical.Table)
		if err != nil {
			return err
		}
		if exists {
			same := strings.EqualFold(m.Table, canonical.Table) && s.dialect == "sqlite"
			if strings.EqualFold(m.Table, canonical.Table) && s.dialect == "mysql" {
				if err := db.QueryRowContext(ctx, "SELECT @@lower_case_table_names <> 0").Scan(&same); err != nil {
					return err
				}
			}
			if !same {
				return errors.New("siwe: canonical wallet table already exists; migrate the wallet data before selecting another table")
			}
		}
	}
	exists, err := s.tableExists(ctx, db, m.Table)
	if err != nil {
		return err
	}
	if exists {
		// Reopening must never add a second set of columns to live wallet data.
		rows, err := db.QueryContext(ctx, s.walletSQL(`SELECT w."id",w."userId",w."address",w."chainId",w."isPrimary",w."createdAt" FROM "walletAddress" w WHERE 1=0`))
		if err != nil {
			return errWalletLayout
		}
		return rows.Close()
	}
	core, err := s.tableExists(ctx, db, "account")
	if err != nil || !core {
		return err
	}
	var prior bool
	if err := db.QueryRowContext(ctx, s.bind(`SELECT EXISTS(SELECT 1 FROM "account" WHERE "providerId"='siwe' AND "accountId" LIKE '0x%:%')`)).Scan(&prior); err != nil {
		return err
	}
	if prior {
		return errWalletLayout
	}
	return nil
}
