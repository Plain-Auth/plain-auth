package sqlstore

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/Stonewrit/stonewrit-auth"
)

var _ stonewrit.UsernameStore = (*Store)(nil)

func (s *Store) CheckUsernameSchema(ctx context.Context, display bool) error {
	cols := `u."username"`
	if display {
		cols += `,u."displayUsername"`
	}
	rows, err := s.db.QueryContext(ctx, s.bind(`SELECT `+cols+` FROM "user" u WHERE 1=0`))
	if err != nil {
		return errors.New("sqlstore: apply the configured username schema profile")
	}
	if err := rows.Close(); err != nil {
		return err
	}
	// A manually provisioned table with the right column names still needs
	// a unique key so two independent servers cannot claim the same name.
	query := `SELECT EXISTS(SELECT 1 FROM pragma_index_list('user') i WHERE i."unique"=1 AND i.partial=0 AND (SELECT COUNT(*) FROM pragma_index_info(i.name))=1 AND EXISTS(SELECT 1 FROM pragma_index_info(i.name) f WHERE f.name='username'))`
	switch s.dialect {
	case "postgres":
		query = `SELECT EXISTS(SELECT 1 FROM pg_index i JOIN pg_attribute a ON a.attrelid=i.indrelid AND a.attnum=i.indkey[0] WHERE i.indrelid=to_regclass('"user"') AND i.indisunique AND i.indisvalid AND i.indpred IS NULL AND i.indnkeyatts=1 AND a.attname='username')`
	case "mysql":
		query = `SELECT EXISTS(SELECT 1 FROM information_schema.statistics WHERE table_schema=DATABASE() AND table_name='user' AND non_unique=0 GROUP BY index_name HAVING COUNT(*)=1 AND MAX(column_name)='username' AND MAX(sub_part) IS NULL)`
	}
	var unique bool
	if err := s.db.QueryRowContext(ctx, query).Scan(&unique); err != nil {
		return err
	}
	if !unique {
		return errors.New("sqlstore: username requires a unique constraint on user.username")
	}
	return nil
}

func (s *Store) UsernameExists(ctx context.Context, name string) (bool, error) {
	var exists bool
	err := s.db.QueryRowContext(ctx, s.bind(`SELECT EXISTS(SELECT 1 FROM "user" u WHERE u."username"=?)`), name).Scan(&exists)
	return exists, err
}

func (s *Store) UsernameCredential(ctx context.Context, name string) (stonewrit.User, string, error) {
	return s.findCredential(ctx, `u."username"`, name)
}

func (s *Store) ReadUsername(ctx context.Context, user string, display bool) (*stonewrit.UsernameFields, error) {
	f := &stonewrit.UsernameFields{}
	cols := `u."username"`
	fields := []any{&f.Username}
	if display {
		f.DisplayUsernameFields = &stonewrit.DisplayUsernameFields{}
		cols += `,u."displayUsername"`
		fields = append(fields, &f.DisplayUsername)
	}
	err := s.db.QueryRowContext(ctx, s.bind(`SELECT `+cols+` FROM "user" u WHERE u."id"=?`), user).Scan(fields...)
	if errors.Is(err, sql.ErrNoRows) {
		err = stonewrit.ErrNotFound
	}
	return f, err
}

func (s *Store) UpdateUsernameProfile(ctx context.Context, userID string, p stonewrit.ProfileUpdate, now time.Time, immutable bool) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err = s.lockAccount(ctx, tx, userID); err != nil {
		return err
	}
	if immutable && p.Username != nil {
		var current *string
		if err = tx.QueryRowContext(ctx, s.bind(`SELECT "username" FROM "user" WHERE "id"=?`), userID).Scan(&current); err != nil {
			return err
		}
		if current != nil && *current != "" && *current != *p.Username {
			return stonewrit.ErrUsernameImmutable
		}
	}
	if err = s.updateProfile(ctx, tx, userID, p, now); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) persistUsernames(ctx context.Context, tx *sql.Tx, u stonewrit.User) error {
	f := u.UsernameFields
	if f == nil {
		return nil
	}
	patch := stonewrit.ProfileUpdate{Username: f.Username}
	if f.DisplayUsernameFields != nil {
		patch.DisplayUsername = f.DisplayUsername
	}
	if patch.Username == nil && patch.DisplayUsername == nil {
		return nil
	}
	return s.updateProfile(ctx, tx, u.ID, patch, u.UpdatedAt)
}

func (t *adminTX) SelectUsernameFields(display bool) { t.names = true; t.displayNames = display }

func (t *adminTX) publicColumns() string {
	cols := userColumns + "," + adminUserColumns
	if t.names {
		cols += `,u."username"`
	}
	if t.displayNames {
		cols += `,u."displayUsername"`
	}
	return cols
}

func (t *adminTX) publicFields(u *stonewrit.User) ([]any, func()) {
	fields, finish := t.s.adminUserScanner(u)
	if t.names {
		u.UsernameFields = &stonewrit.UsernameFields{}
		fields = append(fields, &u.Username)
	}
	if t.displayNames {
		u.DisplayUsernameFields = &stonewrit.DisplayUsernameFields{}
		fields = append(fields, &u.DisplayUsername)
	}
	return fields, finish
}
