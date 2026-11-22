package sqlstore

import (
	"context"
	"database/sql"
	"errors"
	"net/url"
	"path/filepath"
	"slices"
	"strings"

	"github.com/Stonewrit/stonewrit-auth/internal/sessionfields"
	"github.com/Stonewrit/stonewrit-auth/schema"
)

// SchemaFinding identifies a mismatch between selected columns and a live table.
type SchemaFinding struct {
	Kind   string `json:"kind"`
	Table  string `json:"table"`
	Column string `json:"column,omitempty"`
}

// CheckSchema reads the live catalog without creating or migrating databases.
// It reports missing tables and columns, and extra required columns an insert
// could not omit. Additional tables and optional columns are allowed.
func CheckSchema(ctx context.Context, dialect, dsn string, profiles []string) ([]SchemaFinding, error) {
	return CheckSchemaWithSessionFields(ctx, dialect, dsn, profiles, nil)
}

// CheckSchemaWithSessionFields additionally checks each configured physical
// session column using the same compatibility rules as the SQL store.
func CheckSchemaWithSessionFields(ctx context.Context, dialect, dsn string, profiles []string, fields map[string]schema.SessionField) ([]SchemaFinding, error) {
	fields, err := sessionfields.Normalize(fields)
	if err != nil {
		return nil, err
	}
	name, err := normalizeDialect(dialect)
	if err != nil {
		return nil, err
	}
	tables, err := schema.Tables(name, profiles)
	if err != nil {
		return nil, err
	}
	if dsn == "" {
		return nil, errors.New("sqlstore: empty target database")
	}
	if name == "sqlite" && dsn == ":memory:" {
		return nil, errors.New("sqlstore: checking SQLite requires an existing database file")
	}
	findings, err := readSchema(ctx, name, dsn, tables, fields)
	if err == nil {
		return findings, nil
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	// Drivers can include credentials, hostnames or paths in connection errors.
	return nil, errors.New("could not read the database schema (check the connection and permissions)")
}

func readSchema(ctx context.Context, dialect, dsn string, tables []schema.Table, fields map[string]schema.SessionField) ([]SchemaFinding, error) {
	var db *sql.DB
	var query string
	var err error
	switch dialect {
	case "sqlite":
		path, pathErr := filepath.Abs(dsn)
		if pathErr != nil {
			return nil, pathErr
		}
		u := url.URL{Scheme: "file", Path: "/" + strings.TrimPrefix(filepath.ToSlash(path), "/"), RawQuery: "mode=ro"}
		db, err = sql.Open("sqlite3", u.String())
		query = `SELECT col.name,
			(col."notnull" = 0 OR col.dflt_value IS NOT NULL OR col.hidden <> 0 OR
				(col.pk = 1 AND upper(col.type) = 'INTEGER' AND NOT EXISTS (
					SELECT 1 FROM pragma_index_list(obj.name, 'main') WHERE origin = 'pk'
				)))
			FROM main.sqlite_schema AS obj
			JOIN pragma_table_xinfo(obj.name, 'main') AS col
			WHERE obj.type IN ('table','view') AND obj.name = ?
			ORDER BY col.cid`
	case "mysql":
		db, err = openMySQL(dsn)
		query = `SELECT column_name, (is_nullable = 'YES' OR column_default IS NOT NULL
			OR extra LIKE '%GENERATED%' OR extra LIKE '%auto_increment%')
			FROM information_schema.columns JOIN (SELECT ? AS name) AS requested ON table_name = requested.name
			WHERE table_schema = DATABASE()
			AND (@@lower_case_table_names <> 0 OR
				(BINARY table_schema = BINARY DATABASE() AND BINARY table_name = BINARY requested.name))
			ORDER BY ordinal_position`
	case "postgres":
		db, err = sql.Open("pgx", dsn)
		query = `SELECT a.attname, (NOT a.attnotnull OR a.atthasdef OR a.attidentity <> '' OR a.attgenerated <> '')
			FROM pg_catalog.pg_class AS c
			LEFT JOIN pg_catalog.pg_attribute AS a
			  ON a.attrelid = c.oid AND a.attnum > 0 AND NOT a.attisdropped
			WHERE c.oid = pg_catalog.to_regclass(pg_catalog.quote_ident($1)) AND c.relkind IN ('r','p','v','f')
			ORDER BY a.attnum`
	}
	if err != nil {
		return nil, err
	}
	defer db.Close()
	tx, err := db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	findings := []SchemaFinding{}
	for _, table := range tables {
		cols, err := checkColumns(ctx, tx, query, table.Name)
		if err != nil {
			return nil, err
		}
		if cols == nil {
			findings = append(findings, SchemaFinding{Kind: "missing-table", Table: table.Name})
			continue
		}
		for _, col := range table.Columns {
			if _, found := cols[col]; !found {
				findings = append(findings, SchemaFinding{Kind: "missing-column", Table: table.Name, Column: col})
			}
			delete(cols, col)
		}
		if table.Name == "session" && len(fields) > 0 {
			store := Store{dialect: dialect}
			catalog, err := store.sessionColumnCatalog(ctx, tx)
			if err != nil {
				return nil, err
			}
			for _, name := range sessionfields.Names(fields) {
				f := fields[name]
				column, ok := catalog[strings.ToLower(f.Column)]
				if !ok {
					findings = append(findings, SchemaFinding{Kind: "missing-column", Table: table.Name, Column: f.Column})
					continue
				}
				delete(cols, column.name)
				if store.checkSessionField(f, column) != nil {
					findings = append(findings, SchemaFinding{Kind: "incompatible-column", Table: table.Name, Column: f.Column})
				}
			}
		}
		var required []string
		for col, optional := range cols {
			if !optional {
				required = append(required, col)
			}
		}
		slices.Sort(required)
		for _, col := range required {
			findings = append(findings, SchemaFinding{Kind: "unexpected-required-column", Table: table.Name, Column: col})
		}
	}
	return findings, tx.Commit()
}

func checkColumns(ctx context.Context, tx *sql.Tx, query, tableName string) (map[string]bool, error) {
	rows, err := tx.QueryContext(ctx, query, tableName)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var cols map[string]bool
	for rows.Next() {
		var col sql.NullString
		var optional sql.NullBool
		if err := rows.Scan(&col, &optional); err != nil {
			return nil, err
		}
		if cols == nil {
			cols = make(map[string]bool)
		}
		if col.Valid {
			cols[col.String] = optional.Bool
		}
	}
	return cols, rows.Err()
}
