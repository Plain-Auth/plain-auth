package sqlstore

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	auth "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/internal/sessionfields"
)

func (s *Store) ValidateSessionFields(fields map[string]auth.SessionField) error {
	fields, err := sessionfields.Normalize(fields)
	if err != nil {
		return err
	}
	if len(fields) == 0 {
		return nil
	}
	return s.validateModelFields("session", fields)
}

func (s *Store) ValidateUserFields(fields map[string]auth.UserField) error {
	fields, err := sessionfields.NormalizeUser(fields)
	if err != nil {
		return err
	}
	return s.validateModelFields("user", fields)
}

func (s *Store) validateModelFields(model string, fields map[string]auth.SessionField) error {
	if len(fields) == 0 {
		return nil
	}
	columns, err := s.fieldColumnCatalog(context.Background(), s.db, model)
	if err != nil {
		return err
	}
	for name, field := range fields {
		column, ok := columns[strings.ToLower(field.Column)]
		if !ok {
			return fmt.Errorf("sqlstore: %s column %q for %q is missing", model, field.Column, name)
		}
		if err := s.checkModelField(model, field, column); err != nil {
			return err
		}
	}
	return nil
}

type sessionColumn struct {
	name, kind                     string
	precision                      int
	required, generated, ambiguous bool
}

// Resolve the same session relation as subsequent selects, including a
// PostgreSQL search path whose first schema contains no session table.
func (s *Store) sessionColumnCatalog(ctx context.Context, db interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}) (map[string]sessionColumn, error) {
	return s.fieldColumnCatalog(ctx, db, "session")
}

func (s *Store) fieldColumnCatalog(ctx context.Context, db interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}, model string) (map[string]sessionColumn, error) {
	if model != "user" && model != "session" && model != "account" && model != "organizationRole" {
		return nil, errors.New("sqlstore: invalid profile table")
	}
	query := `SELECT name,type,"notnull",hidden<>0,3 FROM pragma_table_xinfo(?)`
	args := []any{model}
	switch s.dialect {
	case "postgres":
		query = `SELECT a.attname,t.typname,a.attnotnull,(a.attidentity<>'' OR a.attgenerated<>''),a.atttypmod FROM pg_catalog.pg_attribute a JOIN pg_catalog.pg_type t ON a.atttypid=t.oid WHERE a.attrelid=pg_catalog.to_regclass(pg_catalog.quote_ident(?::text)) AND a.attnum>0 AND NOT a.attisdropped`
	case "mysql":
		query = `SELECT column_name,data_type,is_nullable='NO',(COALESCE(generation_expression,'')<>'' OR extra LIKE '%auto_increment%'),COALESCE(datetime_precision,0) FROM information_schema.columns WHERE table_schema=DATABASE() AND table_name=?
			AND (@@lower_case_table_names<>0 OR (BINARY table_schema=BINARY DATABASE() AND BINARY table_name=BINARY ?))`
		args = append(args, model)
	}
	rows, err := db.QueryContext(ctx, s.bind(query), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make(map[string]sessionColumn)
	for rows.Next() {
		var col sessionColumn
		if err = rows.Scan(&col.name, &col.kind, &col.required, &col.generated, &col.precision); err != nil {
			return nil, err
		}
		folded := strings.ToLower(col.name)
		_, col.ambiguous = result[folded]
		result[folded] = col
	}
	return result, rows.Err()
}

func (s *Store) checkModelField(model string, f auth.SessionField, column sessionColumn) error {
	if column.ambiguous {
		return fmt.Errorf("sqlstore: multiple columns match the %s field %q", model, f.Column)
	}
	if f.Column != column.name {
		return fmt.Errorf("sqlstore: %s column %q collides with existing %q", model, f.Column, column.name)
	}
	t := strings.ToLower(column.kind)
	var matching bool
	switch f.Type {
	case sessionfields.JSON, sessionfields.StringArray, sessionfields.NumberArray:
		matching = s.dialect == "sqlite" && t == "text" || s.dialect == "postgres" && t == "jsonb" || s.dialect == "mysql" && t == "json"
	case auth.FieldBoolean:
		matching = t == "bool" || t == "boolean" || s.dialect == "sqlite" && t == "integer" || s.dialect == "mysql" && t == "tinyint"
	case auth.FieldNumber:
		matching = t == "int4" || t == "integer" || t == "int"
	case auth.FieldString:
		matching = t == "text"
	case auth.FieldDate:
		switch s.dialect {
		case "sqlite":
			matching = t == "date"
		case "postgres":
			matching = t == "timestamptz" && (column.precision == -1 || column.precision >= 3)
		case "mysql":
			matching = t == "timestamp" && column.precision >= 3
		}
	}
	if column.generated {
		return fmt.Errorf("sqlstore: %s column %q must accept explicit writes", model, f.Column)
	}
	if !matching || f.Required != column.required {
		return fmt.Errorf("sqlstore: incompatible type or nullability for %s column %q", model, f.Column)
	}
	return nil
}

func (s *Store) fieldParameter(value any) any {
	if raw, ok := value.(json.RawMessage); ok {
		return string(raw)
	}
	if instant, ok := value.(time.Time); ok {
		return s.date(instant)
	}
	return value
}

func scalarDestination(kind sessionfields.Type) any {
	switch kind {
	case auth.FieldBoolean:
		return new(sql.NullBool)
	case auth.FieldNumber:
		return new(sql.NullInt64)
	case auth.FieldDate:
		return new(sql.NullTime)
	default:
		return new(sql.NullString)
	}
}

func scannedScalar(dest any) any {
	switch value := dest.(type) {
	case *sql.NullString:
		if value.Valid {
			return value.String
		}
	case *sql.NullInt64:
		if value.Valid {
			return value.Int64
		}
	case *sql.NullTime:
		if value.Valid {
			return value.Time.UTC()
		}
	case *sql.NullBool:
		if value.Valid {
			return value.Bool
		}
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
				dest = append(dest, scalarDestination(normalized[name].Type))
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
				values[name] = scannedScalar(dest[i+3])
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
		params = append(params, s.fieldParameter(value))
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
