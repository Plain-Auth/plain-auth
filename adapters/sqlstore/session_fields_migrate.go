package sqlstore

import (
	"context"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"time"

	auth "github.com/Plain-Auth/plain-auth"
	"github.com/Plain-Auth/plain-auth/internal/sessionfields"
	"github.com/Plain-Auth/plain-auth/schema"
)

// OpenWithSessionFields creates a fresh configured schema or applies additive
// migrations to an existing database under the same cross-process migration lock.
func OpenWithSessionFields(ctx context.Context, dialect, dsn string, profiles []string, fields map[string]auth.SessionField) (*Store, error) {
	return OpenWithAdditionalFields(ctx, dialect, dsn, profiles, schema.AdditionalFields{Session: fields})
}

// OpenWithAdditionalFields applies selected profiles and both sets of additional columns.
func OpenWithAdditionalFields(ctx context.Context, dialect, dsn string, profiles []string, fields schema.AdditionalFields) (*Store, error) {
	return OpenWithOptions(ctx, dialect, dsn, profiles, schema.Options{AdditionalFields: fields})
}

// OpenWithOptions keeps the wallet layout on this store, including for account
// cleanup when a node has not mounted the wallet plugin.
func OpenWithOptions(ctx context.Context, dialect, dsn string, profiles []string, opts schema.Options) (*Store, error) {
	fields, err := opts.AdditionalFields.Normalize()
	if err != nil {
		return nil, err
	}
	if _, err := schema.GenerateWithOptions(dialect, profiles, opts); err != nil {
		return nil, err
	}
	s, err := connectDB(ctx, dialect, dsn, true)
	if err != nil {
		return nil, err
	}
	if opts.Wallet != (schema.WalletSchema{}) {
		s.walletMapping, err = schema.NormalizeWallet(opts.Wallet)
		if err != nil {
			s.Close()
			return nil, err
		}
		s.walletQueryNames = s.walletMapping.Replacer(`"`)
	}
	err = s.withMigrationConnection(ctx, func(db migrationConnection) error {
		if s.walletQueryNames != nil {
			if err := s.preflightWalletMapping(ctx, db); err != nil {
				return err
			}
		}
		type add struct {
			model string
			field auth.SessionField
		}
		var additions []add
		var fresh schema.AdditionalFields
		for _, entry := range []struct {
			model string
			defs  map[string]auth.SessionField
		}{{"user", fields.User}, {"session", fields.Session}} {
			columns, err := s.fieldColumnCatalog(ctx, db, entry.model)
			if err != nil {
				return err
			}
			if len(columns) == 0 {
				if entry.model == "user" {
					fresh.User = entry.defs
				} else {
					fresh.Session = entry.defs
				}
				continue
			}
			missing, err := s.missingModelFields(ctx, db, entry.model, entry.defs, columns)
			if err != nil {
				return err
			}
			for _, name := range missing {
				additions = append(additions, add{entry.model, entry.defs[name]})
			}
		}
		full, err := schema.GenerateWithOptions(dialect, profiles, schema.Options{AdditionalFields: fresh, Wallet: opts.Wallet})
		if err != nil {
			return err
		}
		if err := s.applyMigrations(ctx, db, full); err != nil {
			return err
		}
		for _, col := range additions {
			f := col.field
			column := f.Definition(s.dialect)
			if f.Default != nil {
				column += " default " + s.sessionFieldDefault(f.Default)
			}
			if _, err := db.ExecContext(ctx, s.bind(`ALTER TABLE "`+col.model+`" ADD COLUMN `)+column); err != nil {
				return fmt.Errorf("sqlstore: add %s column %q: %w", col.model, f.Column, err)
			}
		}
		return nil
	})
	if err == nil {
		err = s.ValidateSessionFields(fields.Session)
	}
	if err == nil {
		err = s.ValidateUserFields(fields.User)
	}
	if err != nil {
		s.Close()
		return nil, err
	}
	return s.detectInitialProfiles(ctx)
}

func (s *Store) missingModelFields(ctx context.Context, db migrationConnection, model string, fields map[string]auth.SessionField, have map[string]sessionColumn) ([]string, error) {
	var missing []string
	var populated bool
	var checked bool
	for _, key := range sessionfields.Names(fields) {
		f := fields[key]
		column, ok := have[strings.ToLower(f.Column)]
		if ok {
			if err := s.checkModelField(model, f, column); err != nil {
				return nil, err
			}
			continue
		}
		if f.Required && f.Default == nil {
			if !checked {
				if err := db.QueryRowContext(ctx, s.bind(`SELECT EXISTS (SELECT 1 FROM "`+model+`")`)).Scan(&populated); err != nil {
					return nil, err
				}
				checked = true
			}
			if populated {
				return nil, fmt.Errorf("sqlstore: explicitly backfill required %s column %q before migrating existing %ss", model, f.Column, model)
			}
		}
		missing = append(missing, key)
	}
	return missing, nil
}

// SQLite forbids nonconstant defaults on populated ALTERs; MySQL requires an
// expression for TEXT defaults. Encode MySQL text independently of SQL mode.
func (s *Store) sessionFieldDefault(value any) string {
	switch v := value.(type) {
	case bool:
		if s.dialect == "sqlite" {
			if v {
				return "1"
			}
			return "0"
		}
		return strconv.FormatBool(v)
	case int64:
		return strconv.FormatInt(v, 10)
	case time.Time:
		if s.dialect == "mysql" {
			return "'" + v.UTC().Format("2006-01-02 15:04:05.000") + "'"
		}
		return "'" + v.UTC().Format(sessionfields.MillisecondUTC) + "'"
	case string:
		if s.dialect == "mysql" {
			return "(CONVERT(X'" + hex.EncodeToString([]byte(v)) + "' USING utf8mb4))"
		}
		if s.dialect == "postgres" {
			return "E'" + strings.NewReplacer("\\", "\\\\", "'", "''").Replace(v) + "'"
		}
		return "'" + strings.ReplaceAll(v, "'", "''") + "'"
	default:
		panic("unvalidated session field default")
	}
}
