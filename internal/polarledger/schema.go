// Package polarledger describes the tables shared by the migration CLI and
// the optional Polar checkout module.
package polarledger

import "strings"

const CheckoutTable = "plainauth_polar_checkout"

// PostgresSchemaLock serializes optional runtime provisioning with CLI DDL.
const PostgresSchemaLock = "SELECT pg_advisory_xact_lock(hashtext(current_schema()),hashtext('plainauth_polar_ledger'))"

type Table struct {
	Name    string
	Columns []string // quoted column definitions for the selected dialect
}

func Tables(dialect string) []Table {
	quote := `"`
	if dialect == "mysql" {
		quote = "`"
	}
	tables := []Table{
		{CheckoutTable, []string{
			"slot char(64) primary key", "attempt char(36) not null unique",
			"owner_id varchar(512) not null", "contact_hash char(64) not null",
			"merchant char(36) not null", "product char(36) not null",
			"success_url text not null", "return_url text not null", "checkout_id char(36) unique",
			"hosted_url text not null", "status varchar(16) not null", "expires_ms bigint not null", "changed_us bigint not null",
			// Every offered product, comma-joined; '' on rows written before
			// several products were offered, which read as product alone.
			"products varchar(400) not null default ''",
		}},
		{"plainauth_polar_delivery", []string{
			"event_key char(64) primary key", "body_hash char(64) not null", "claim char(36) not null",
		}},
	}
	for i, table := range tables {
		tables[i].Name = quote + table.Name + quote
		for j, col := range table.Columns {
			name, definition, _ := strings.Cut(col, " ")
			table.Columns[j] = quote + name + quote + " " + definition
		}
	}
	return tables
}
