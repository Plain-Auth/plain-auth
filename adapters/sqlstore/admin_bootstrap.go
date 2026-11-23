package sqlstore

import (
	"context"
	"database/sql"
	"errors"
	"slices"
	"strings"
	"time"

	authn "github.com/Plain-Org/plain-auth"
)

// OpenForAdminBootstrap opens an existing database and checks its admin profile.
func OpenForAdminBootstrap(ctx context.Context, dialect, dsn string) (*Store, error) {
	s, err := connectDB(ctx, dialect, dsn, false)
	if err != nil {
		return nil, err
	}
	enabled, err := s.detectAdminSchema(ctx, s.db)
	if err != nil || !enabled {
		s.Close()
		if err != nil {
			return nil, err
		}
		return nil, errors.New("sqlstore: apply the admin schema before creating an administrator")
	}
	return s, nil
}

// CreateFirstAdmin serializes bootstrap attempts using a temporary transaction
// lock row. The row is removed before commit. The administrator and credential
// are created together, and an existing account cannot be promoted this way.
func (s *Store) CreateFirstAdmin(ctx context.Context, user authn.User, hash string) error {
	enabled, err := s.detectAdminSchema(ctx, s.db)
	if err != nil {
		return err
	}
	if !enabled {
		return errors.New("sqlstore: apply the admin schema before creating an administrator")
	}
	if user.AdminUserFields == nil || user.Role != "admin" || user.Banned || hash == "" {
		return errors.New("sqlstore: invalid bootstrap credential")
	}
	opts := &sql.TxOptions{}
	if s.dialect != "sqlite" {
		opts.Isolation = sql.LevelReadCommitted
	}
	tx, err := s.db.BeginTx(ctx, opts)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	now := time.Now().UTC()
	const lock = "authn-create-first-admin"
	query := `INSERT INTO "verification" ("id","identifier","value","expiresAt","createdAt","updatedAt") VALUES (?,?,?, ?,?,?)`
	if s.dialect == "mysql" {
		query += ` ON DUPLICATE KEY UPDATE "id"="id"`
	} else {
		query += ` ON CONFLICT("id") DO NOTHING`
	}
	if _, err = tx.ExecContext(ctx, s.bind(query), lock, lock, "bootstrap", s.date(now.Add(time.Minute)), s.date(now), s.date(now)); err != nil {
		return err
	}
	var identifier string
	if err = tx.QueryRowContext(ctx, s.readForUpdate(`SELECT "identifier" FROM "verification" WHERE "id"=?`), lock).Scan(&identifier); err != nil {
		return err
	}
	if identifier != lock {
		return errors.New("sqlstore: bootstrap lock unavailable")
	}
	rows, err := tx.QueryContext(ctx, s.bind(`SELECT DISTINCT "role" FROM "user" WHERE "role" IS NOT NULL`))
	if err != nil {
		return err
	}
	found := false
	for rows.Next() {
		var role string
		if err = rows.Scan(&role); err != nil {
			rows.Close()
			return err
		}
		if slices.Contains(strings.Split(role, ","), "admin") {
			found = true
			break
		}
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	if found {
		return authn.ErrAdminExists
	}
	if err = (&adminTX{s: s, ctx: ctx, tx: tx, now: now}).CreateUser(user, hash); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, s.bind(`DELETE FROM "verification" WHERE "id"=? AND "identifier"=?`), lock, lock); err != nil {
		return err
	}
	return tx.Commit()
}
