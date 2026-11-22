package sqlstore

import (
	"context"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"

	auth "github.com/Plain-Auth/plain-auth"
	"github.com/Plain-Auth/plain-auth/internal/sessionfields"
	"github.com/Plain-Auth/plain-auth/schema"
)

// OpenWithSessionFields creates a fresh configured schema or applies additive
// migrations to an existing database under the same cross-process migration lock.
func OpenWithSessionFields(ctx context.Context, dialect, dsn string, profiles []string, fields map[string]auth.SessionField) (*Store, error) {
	fields, err := sessionfields.Normalize(fields)
	if err != nil {
		return nil, err
	}
	base, err := schema.Generate(dialect, profiles)
	if err != nil {
		return nil, err
	}
	full, err := schema.GenerateWithSessionFields(dialect, profiles, fields)
	if err != nil {
		return nil, err
	}
	s, err := connectDB(ctx, dialect, dsn, true)
	if err != nil {
		return nil, err
	}
	err = s.withMigrationConnection(ctx, func(db migrationConnection) error {
		columns, err := s.sessionColumnCatalog(ctx, db)
		if err != nil {
			return err
		}
		if len(columns) == 0 {
			return s.applyMigrations(ctx, db, full)
		}
		// Preflight every required backfill before any custom DDL. MySQL DDL
		// commits implicitly; retries discover columns from the actual database.
		missing, err := s.missingSessionFields(ctx, db, fields, columns)
		if err != nil {
			return err
		}
		if err = s.applyMigrations(ctx, db, base); err != nil {
			return err
		}
		for _, name := range missing {
			f := fields[name]
			column := f.Definition(s.dialect)
			if f.Default != nil {
				column += " default " + s.sessionFieldDefault(f.Default)
			}
			if _, err := db.ExecContext(ctx, s.bind(`ALTER TABLE "session" ADD COLUMN `)+column); err != nil {
				return fmt.Errorf("sqlstore: add session column %q: %w", f.Column, err)
			}
		}
		return nil
	})
	if err == nil {
		err = s.ValidateSessionFields(fields)
	}
	if err != nil {
		s.Close()
		return nil, err
	}
	return s.detectInitialProfiles(ctx)
}

func (s *Store) missingSessionFields(ctx context.Context, db migrationConnection, fields map[string]auth.SessionField, have map[string]sessionColumn) ([]string, error) {
	var missing []string
	var populated bool
	var checked bool
	for _, key := range sessionfields.Names(fields) {
		f := fields[key]
		column, ok := have[strings.ToLower(f.Column)]
		if ok {
			if err := s.checkSessionField(f, column); err != nil {
				return nil, err
			}
			continue
		}
		if f.Required && f.Default == nil {
			if !checked {
				if err := db.QueryRowContext(ctx, s.bind(`SELECT EXISTS (SELECT 1 FROM "session")`)).Scan(&populated); err != nil {
					return nil, err
				}
				checked = true
			}
			if populated {
				return nil, fmt.Errorf("sqlstore: explicitly backfill required session column %q before migrating existing sessions", f.Column)
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
