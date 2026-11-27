package polar

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/Plain-Org/plain-auth/internal/polarledger"
	"github.com/google/uuid"
)

// Ledger stores checkout reservations and verified delivery receipts in the same database as the auth accounts.
type Ledger struct {
	db      *sql.DB
	dialect string
}

// OpenLedger creates the two independent billing tables. The caller owns the connection pool.
func OpenLedger(ctx context.Context, db *sql.DB, dialect string) (*Ledger, error) {
	if db == nil || dialect != "sqlite" && dialect != "postgres" && dialect != "mysql" {
		return nil, errors.New("polar: expected a SQLite, PostgreSQL or MySQL database")
	}
	l := &Ledger{db: db, dialect: dialect}
	exec := db.ExecContext
	var tx *sql.Tx
	if dialect != "mysql" {
		var err error
		tx, err = db.BeginTx(ctx, nil)
		if err != nil {
			return nil, err
		}
		defer tx.Rollback()
		exec = tx.ExecContext
	}
	if dialect == "postgres" {
		if _, err := tx.ExecContext(ctx, polarledger.PostgresSchemaLock); err != nil {
			return nil, err
		}
	}
	for _, table := range polarledger.Tables(dialect) {
		ddl := "CREATE TABLE IF NOT EXISTS " + table.Name + " (" + strings.Join(table.Columns, ", ") + ")"
		if _, err := exec(ctx, ddl); err != nil {
			return nil, err
		}
		var conn ledgerConn = db
		if tx != nil {
			conn = tx
		}
		if err := addMissingColumns(ctx, conn, table, dialect); err != nil {
			return nil, err
		}
	}
	if tx != nil {
		if err := tx.Commit(); err != nil {
			return nil, err
		}
	}
	return l, nil
}

type ledgerConn interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}

// addMissingColumns upgrades a ledger table in place: it adds each missing
// column that has a default, so tables with rows accept it, and refuses
// any other missing column. On MySQL, whose DDL runs outside a transaction,
// a column another node added first is accepted.
func addMissingColumns(ctx context.Context, conn ledgerConn, table polarledger.Table, dialect string) error {
	existing := func() (map[string]bool, error) {
		rows, err := conn.QueryContext(ctx, "SELECT * FROM "+table.Name+" WHERE 1=0")
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		names, err := rows.Columns()
		found := make(map[string]bool, len(names))
		for _, name := range names {
			found[strings.ToLower(name)] = true
		}
		return found, err
	}
	have, err := existing()
	if err != nil {
		return err
	}
	for _, column := range table.Columns {
		name, _, _ := strings.Cut(column, " ")
		name = strings.Trim(name, "`\"")
		if have[name] {
			continue
		}
		if !strings.Contains(column, " default ") {
			return fmt.Errorf("polar: ledger table %s lacks column %s; run authctl migrate --plugins polar", table.Name, name)
		}
		if _, err := conn.ExecContext(ctx, "ALTER TABLE "+table.Name+" ADD COLUMN "+column); err != nil {
			if dialect != "mysql" {
				return err
			}
			if have, rerr := existing(); rerr != nil || !have[name] {
				return err
			}
		}
	}
	return nil
}

type reservation struct {
	Slot, Attempt      string
	Owner, ContactHash string
	// Product is the first offered product, kept for rows written before
	// several products were offered; Products lists every one in order.
	Product, Merchant string
	Products          []string
	Success, Return   string
	ID, URL, Status   string
	Expires, Changed  int64
}

const columns = "slot,attempt,owner_id,contact_hash,product,products,merchant,success_url,return_url,COALESCE(checkout_id,''),hosted_url,status,expires_ms,changed_us"

func scan(r *sql.Row) (reservation, error) {
	var v reservation
	var products string
	err := r.Scan(&v.Slot, &v.Attempt, &v.Owner, &v.ContactHash, &v.Product, &products, &v.Merchant, &v.Success, &v.Return, &v.ID, &v.URL, &v.Status, &v.Expires, &v.Changed)
	v.Products = strings.Split(products, ",")
	if products == "" {
		v.Products = []string{v.Product}
	}
	return v, err
}

func (l *Ledger) bind(q string) string {
	if l.dialect != "postgres" {
		return q
	}
	var b strings.Builder
	n := 0
	for _, c := range q {
		if c == '?' {
			n++
			b.WriteByte('$')
			b.WriteString(strconv.Itoa(n))
		} else {
			b.WriteRune(c)
		}
	}
	return b.String()
}

func (l *Ledger) ignore(column string) string {
	if l.dialect == "mysql" {
		return " ON DUPLICATE KEY UPDATE " + column + "=" + column
	}
	return " ON CONFLICT (" + column + ") DO NOTHING"
}

func (l *Ledger) read(ctx context.Context, slot string) (reservation, error) {
	return scan(l.db.QueryRowContext(ctx, l.bind("SELECT "+columns+" FROM plainauth_polar_checkout WHERE slot=?"), slot))
}

func (l *Ledger) reserve(ctx context.Context, v reservation) (reservation, bool, error) {
	q := `INSERT INTO plainauth_polar_checkout (slot,attempt,owner_id,contact_hash,product,products,merchant,success_url,return_url,hosted_url,status,expires_ms,changed_us) VALUES (?,?,?,?,?,?,?,?,?,'','pending',0,0)`
	_, err := l.db.ExecContext(ctx, l.bind(q+l.ignore("slot")), v.Slot, v.Attempt, v.Owner, v.ContactHash, v.Products[0], strings.Join(v.Products, ","), v.Merchant, v.Success, v.Return)
	if err != nil {
		return v, false, err
	}
	row, err := l.read(ctx, v.Slot)
	if err == nil && (row.Owner != v.Owner || row.ContactHash != v.ContactHash || !slices.Equal(row.Products, v.Products) || row.Merchant != v.Merchant || row.Success != v.Success || row.Return != v.Return) {
		return v, false, conflict()
	}
	return row, err == nil && row.Attempt == v.Attempt, err
}

func (l *Ledger) claimDelivery(ctx context.Context, tx *sql.Tx, event *delivery) (bool, error) {
	nonce := uuid.NewString()
	q := "INSERT INTO plainauth_polar_delivery(event_key,body_hash,claim) VALUES (?,?,?)" + l.ignore("event_key")
	_, err := tx.ExecContext(ctx, l.bind(q), event.key, event.hash, nonce)
	if err != nil {
		return false, err
	}
	var stored, claim string
	err = tx.QueryRowContext(ctx, l.bind("SELECT body_hash,claim FROM plainauth_polar_delivery WHERE event_key=?"), event.key).Scan(&stored, &claim)
	if err != nil {
		return false, err
	}
	if stored != event.hash {
		return false, conflict()
	}
	return nonce == claim, nil
}

// Check the canonical account even when other nodes enabled the anonymous schema
// but this serving node did not install its presentation plugin.
func (l *Ledger) verifiedPersonalOwner(ctx context.Context, id, email string) (bool, error) {
	var existence string
	switch l.dialect {
	case "sqlite":
		existence = `SELECT COUNT(*) FROM pragma_table_info('user') WHERE name='isAnonymous'`
	case "postgres":
		existence = `SELECT COUNT(*) FROM pg_catalog.pg_attribute WHERE attrelid=pg_catalog.to_regclass('"user"') AND attname='isAnonymous' AND attnum>0 AND NOT attisdropped`
	case "mysql":
		existence = `SELECT COUNT(*) FROM information_schema.columns WHERE table_schema=database() AND table_name='user' AND column_name='isAnonymous'`
	}
	var guestColumn int
	if err := l.db.QueryRowContext(ctx, existence).Scan(&guestColumn); err != nil {
		return false, err
	}
	query := `SELECT u."id",u."email",u."emailVerified" FROM "user" u WHERE u."id"=?`
	if guestColumn != 0 {
		query += ` AND COALESCE(u."isAnonymous",false)=false`
	}
	if l.dialect == "mysql" {
		query = strings.ReplaceAll(query, "\"", "`")
	}
	var actual, accountEmail string
	var verified bool
	err := l.db.QueryRowContext(ctx, l.bind(query), id).Scan(&actual, &accountEmail, &verified)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	return actual == id && accountEmail == email && verified, err
}
