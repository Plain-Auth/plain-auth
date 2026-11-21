package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"unicode"

	"github.com/FineStack/frost-auth/adapters/sqlstore"
	"github.com/FineStack/frost-auth/schema"
)

var errSchemaMismatch = errors.New("the database does not match the selected schema")

func failureCode(args []string, err error) int {
	if len(args) > 0 && args[0] == "check" && !errors.Is(err, errSchemaMismatch) {
		return 2
	}
	return 1
}

func checkDatabase(ctx context.Context, dialect string, profiles []string, asJSON bool, out io.Writer) error {
	dsn := os.Getenv("AUTH_DSN")
	if dsn == "" {
		if _, err := schema.Tables(dialect, profiles); err != nil {
			return err
		}
		return errors.New("set AUTH_DSN to the target database")
	}
	findings, err := sqlstore.CheckSchema(ctx, dialect, dsn, profiles)
	if err != nil {
		return err
	}
	if asJSON {
		if err := json.NewEncoder(out).Encode(findings); err != nil {
			return err
		}
	} else if len(findings) == 0 {
		_, err = fmt.Fprintln(out, "Schema check passed.")
		return err
	} else {
		for _, f := range findings {
			name := f.Table
			if f.Column != "" {
				column := f.Column
				if strings.ContainsFunc(column, unicode.IsControl) {
					column = strconv.Quote(column)
				}
				name += "." + column
			}
			if _, err := fmt.Fprintln(out, f.Kind, name); err != nil {
				return err
			}
		}
	}
	if len(findings) > 0 {
		return errSchemaMismatch
	}
	return nil
}
