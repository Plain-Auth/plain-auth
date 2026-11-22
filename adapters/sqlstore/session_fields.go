package sqlstore

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	auth "github.com/Stonewrit/stonewrit-auth"
	"github.com/Stonewrit/stonewrit-auth/internal/sessionfields"
)

func (s *Store) ValidateSessionFields(fields map[string]auth.SessionField) error {
	fields, err := sessionfields.Normalize(fields)
	if err != nil {
		return err
	}
	if len(fields) == 0 {
		return nil
	}
	columns, err := s.sessionColumnCatalog(context.Background(), s.db)
	if err != nil {
		return err
	}
	for name, field := range fields {
		column, ok := columns[strings.ToLower(field.Column)]
		if !ok {
			return fmt.Errorf("sqlstore: session column %q for %q is missing", field.Column, name)
		}
		if err := s.checkSessionField(field, column); err != nil {
			return err
		}
	}
	return nil
}

type sessionColumn struct {
	name, kind          string
	required, generated bool
}

// Resolve the same session relation as subsequent selects, including a
// PostgreSQL search path whose first schema contains no session table.
func (s *Store) sessionColumnCatalog(ctx context.Context, db interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}) (map[string]sessionColumn, error) {
	query := `SELECT name,type,"notnull",hidden<>0 FROM pragma_table_xinfo('session')`
	switch s.dialect {
	case "postgres":
		query = `SELECT a.attname,t.typname,a.attnotnull,(a.attidentity<>'' OR a.attgenerated<>'') FROM pg_catalog.pg_attribute a JOIN pg_catalog.pg_type t ON a.atttypid=t.oid WHERE a.attrelid=pg_catalog.to_regclass('session') AND a.attnum>0 AND NOT a.attisdropped`
	case "mysql":
		query = `SELECT column_name,data_type,is_nullable='NO',(COALESCE(generation_expression,'')<>'' OR extra LIKE '%auto_increment%') FROM information_schema.columns WHERE table_schema=DATABASE() AND table_name='session'
			AND (@@lower_case_table_names<>0 OR (BINARY table_schema=BINARY DATABASE() AND BINARY table_name=BINARY 'session'))`
	}
	rows, err := db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make(map[string]sessionColumn)
	for rows.Next() {
		var col sessionColumn
		if err = rows.Scan(&col.name, &col.kind, &col.required, &col.generated); err != nil {
			return nil, err
		}
		result[strings.ToLower(col.name)] = col
	}
	return result, rows.Err()
}

func (s *Store) checkSessionField(f auth.SessionField, column sessionColumn) error {
	if f.Column != column.name {
		return fmt.Errorf("sqlstore: session column %q collides with existing %q", f.Column, column.name)
	}
	t := strings.ToLower(column.kind)
	var matching bool
	switch f.Type {
	case auth.FieldBoolean:
		matching = t == "bool" || t == "boolean" || s.dialect == "sqlite" && t == "integer" || s.dialect == "mysql" && t == "tinyint"
	case auth.FieldNumber:
		matching = t == "int4" || t == "integer" || t == "int"
	case auth.FieldString:
		matching = t == "text"
	}
	if column.generated {
		return fmt.Errorf("sqlstore: session column %q must accept explicit writes", f.Column)
	}
	if !matching || f.Required != column.required {
		return fmt.Errorf("sqlstore: incompatible type or nullability for session column %q", f.Column)
	}
	return nil
}

func (s *Store) ReadSessionFields(ctx context.Context, wanted []auth.Session, fields map[string]auth.SessionField) (map[string]map[string]any, error) {
	normalized, err := sessionfields.Normalize(fields)
	if err != nil {
		return nil, err
	}
	names := sessionfields.Names(normalized)
	cols := `s."id",s."userId",s."token"`
	public := make([]string, 0, len(names))
	for _, name := range names {
		f := normalized[name]
		if !f.Hidden {
			public = append(public, name)
			cols += `,s."` + f.Column + `"`
		}
	}
	out := make(map[string]map[string]any, len(wanted))
	for group := range slices.Chunk(wanted, 200) {
		target := make(map[string]auth.Session, len(group))
		tokens := make([]string, 0, len(group))
		for _, row := range group {
			tokens = append(tokens, row.Token)
			target[row.Token] = row
		}
		params, args := s.deviceTokenParameters(tokens)
		rows, err := s.db.QueryContext(ctx, s.bind(`SELECT `+cols+` FROM "session" s WHERE s."token" IN (`+params+`)`), args...)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var id, owner, token string
			dest := []any{&id, &owner, &token}
			for _, name := range public {
				switch normalized[name].Type {
				case auth.FieldString:
					dest = append(dest, new(sql.NullString))
				case auth.FieldNumber:
					dest = append(dest, new(sql.NullInt64))
				case auth.FieldBoolean:
					dest = append(dest, new(sql.NullBool))
				}
			}
			if err = rows.Scan(dest...); err != nil {
				rows.Close()
				return nil, err
			}
			if want, ok := target[token]; !ok || want.ID != id || want.UserID != owner {
				continue
			}
			values := make(map[string]any, len(public))
			for i, name := range public {
				var value any
				switch v := dest[i+3].(type) {
				case *sql.NullString:
					if v.Valid {
						value = v.String
					}
				case *sql.NullInt64:
					if v.Valid {
						value = v.Int64
					}
				case *sql.NullBool:
					if v.Valid {
						value = v.Bool
					}
				}
				values[name] = value
			}
			out[token] = values
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return nil, err
		}
	}
	return out, nil
}

func (s *Store) UpdateSessionFields(ctx context.Context, actor auth.Session, fields map[string]auth.SessionField, changes map[string]any, now time.Time) error {
	if err := actor.RequireOwner(); err != nil {
		return auth.ErrNotFound
	}
	started := time.Now()
	normalized, err := sessionfields.Normalize(fields)
	if err != nil {
		return err
	}
	tx, err := s.beginMembershipChange(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := s.lockActiveAccount(ctx, tx, actor.UserID, actor.Token, now); err != nil {
		return err
	}
	params := []any{s.date(now)}
	cols := []string{`"updatedAt"=?`}
	for _, name := range sessionfields.Names(normalized) {
		value, exists := changes[name]
		if !exists {
			continue
		}
		f := normalized[name]
		if f.ServerOnly {
			return errors.New("sqlstore: server-owned session field in public patch")
		}
		value, err = f.Value(value)
		if err != nil {
			return err
		}
		params = append(params, value)
		cols = append(cols, `"`+f.Column+`"=?`)
	}
	if len(cols)-1 != len(changes) || len(changes) == 0 {
		return errors.New("sqlstore: invalid session field update")
	}
	parameter, _ := s.deviceTokenParameters([]string{actor.Token})
	q := `UPDATE "session" SET ` + strings.Join(cols, ",") + ` WHERE ` + s.scimExact(`"id"`) + `=? AND ` + s.scimExact(`"userId"`) + `=? AND "token"=` + parameter
	// Validate the ID under the existing token's lock; MySQL can report zero
	// affected rows for a successful, unchanged update in the same millisecond.
	var actual string
	var expires time.Time
	if err := tx.QueryRowContext(ctx, s.bind(`SELECT "id","expiresAt" FROM "session" WHERE "token"=`+parameter), actor.Token).Scan(&actual, &expires); err != nil {
		return err
	}
	if actual != actor.ID || !expires.After(now.Add(time.Since(started))) {
		return auth.ErrNotFound
	}
	if _, err := tx.ExecContext(ctx, s.bind(q), append(params, actor.ID, actor.UserID, actor.Token)...); err != nil {
		return err
	}
	return tx.Commit()
}
