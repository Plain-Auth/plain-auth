package sqlstore

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
)

//go:embed schema/*.sql
var schemas embed.FS

// Schema returns the full initialization script for an empty database.
// Open inspects existing tables and indexes before applying the baseline.
func Schema(dialect string) (string, error) {
	name, err := normalizeDialect(dialect)
	if err != nil {
		return "", err
	}
	script, err := schemas.ReadFile("schema/" + name + ".sql")
	return string(script), err
}

type migrationConnection interface {
	executor
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func (s *Store) migrate(ctx context.Context) error {
	if s.dialect == "mysql" {
		// MySQL's DDL commits implicitly. Keep the lock on one connection until
		// the full set of tables and indexes has been initialized.
		conn, err := s.db.Conn(ctx)
		if err != nil {
			return err
		}
		defer conn.Close()
		const lock = "CONCAT('go-better-auth/migration/', MD5(DATABASE()))"
		var locked sql.NullInt64
		if err := conn.QueryRowContext(ctx, "SELECT GET_LOCK("+lock+", 30)").Scan(&locked); err != nil {
			return err
		}
		if !locked.Valid || locked.Int64 != 1 {
			return errors.New("sqlstore: unable to acquire MySQL schema migration lock")
		}
		defer func() {
			cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_, _ = conn.ExecContext(cleanup, "SELECT RELEASE_LOCK("+lock+")")
		}()
		return s.applyMigrations(ctx, conn)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if s.dialect == "postgres" {
		// Serialize schema creation across independent application processes.
		if _, err := tx.ExecContext(ctx, "SELECT pg_advisory_xact_lock(hashtext('go-better-auth/schema'))"); err != nil {
			return err
		}
	}
	if err := s.applyMigrations(ctx, tx); err != nil {
		return err
	}
	return tx.Commit()
}

// These expressions match the immutable initialization scripts embedded above.
var indexDDL = regexp.MustCompile("(?i)^create index [`\"]([^\"`]+)[`\"] on [`\"]([^\"`]+)[`\"]")

func (s *Store) applyMigrations(ctx context.Context, db migrationConnection) error {
	script, err := Schema(s.dialect)
	if err != nil {
		return err
	}
	for statement := range strings.SplitSeq(script, ";") {
		stmt := strings.TrimSpace(statement)
		if stmt == "" {
			continue
		}
		switch {
		case strings.HasPrefix(stmt, "create table "):
			stmt = strings.Replace(stmt, "create table ", "create table if not exists ", 1)
		case strings.HasPrefix(stmt, "create index "):
			if s.dialect == "mysql" {
				// MySQL has no CREATE INDEX IF NOT EXISTS.
				match := indexDDL.FindStringSubmatch(stmt)
				if match == nil {
					return errors.New("sqlstore: invalid embedded index statement")
				}
				var exists int
				if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM information_schema.statistics
      WHERE table_schema = DATABASE() AND table_name = ? AND index_name = ?`, match[2], match[1]).Scan(&exists); err != nil {
					return err
				}
				if exists > 0 {
					continue
				}
			} else {
				stmt = strings.Replace(stmt, "create index ", "create index if not exists ", 1)
			}
		default:
			return errors.New("sqlstore: unexpected embedded schema statement")
		}
		if _, err := db.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("sqlstore: initialize %s schema: %w", s.dialect, err)
		}
	}
	// Fail at startup when an existing table uses an incompatible layout.
	for _, query := range []string{
		`SELECT t."id",t."name",t."email",t."emailVerified",t."image",t."createdAt",t."updatedAt" FROM "user" t WHERE 1=0`,
		`SELECT t."id",t."expiresAt",t."token",t."createdAt",t."updatedAt",t."ipAddress",t."userAgent",t."userId" FROM "session" t WHERE 1=0`,
		`SELECT t."id",t."accountId",t."providerId",t."userId",t."accessToken",t."refreshToken",t."idToken",t."accessTokenExpiresAt",t."refreshTokenExpiresAt",t."scope",t."password",t."createdAt",t."updatedAt" FROM "account" t WHERE 1=0`,
		`SELECT t."id",t."identifier",t."value",t."expiresAt",t."createdAt",t."updatedAt" FROM "verification" t WHERE 1=0`,
	} {
		rows, err := db.QueryContext(ctx, s.bind(query))
		if err != nil {
			return fmt.Errorf("sqlstore: incompatible %s schema: %w", s.dialect, err)
		}
		if err := rows.Close(); err != nil {
			return err
		}
	}
	return nil
}
