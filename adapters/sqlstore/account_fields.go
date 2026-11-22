package sqlstore

import (
	"context"
	"crypto/rand"
	"database/sql"
	"fmt"
	"maps"
	"strings"
	"time"

	auth "github.com/Plain-Auth/plain-auth"
	"github.com/Plain-Auth/plain-auth/internal/sessionfields"
)

// WithAccountFields returns an independent view of the pool and validates its account schema.
func (s *Store) WithAccountFields(fields map[string]auth.AccountField, rules map[string]auth.AccountFieldRule) (auth.Store, error) {
	defs, err := sessionfields.NormalizeAccount(fields)
	if err != nil {
		return nil, err
	}
	if err := s.validateModelFields("account", defs); err != nil {
		return nil, err
	}
	configured := *s
	configured.accountFields = defs
	configured.accountFieldRules = maps.Clone(rules)
	return &configured, nil
}

// Apply transforms at write time, after the transaction has selected the owner
// and decided whether this grant may change the account.
func (s *Store) accountFieldParameter(name string, value any) (any, error) {
	var err error
	if transform := s.accountFieldRules[name].TransformInput; transform != nil {
		value, err = transform(value)
	}
	if err == nil {
		value, err = s.accountFields[name].Value(value)
	}
	if err != nil {
		return nil, &auth.APIError{Status: 400, Code: "VALIDATION_ERROR", Message: "Invalid account field " + name}
	}
	return s.fieldParameter(value), nil
}

func (s *Store) newAccountFieldParameter(name string, mapped *auth.MappedAccountFields) (any, error) {
	f := s.accountFields[name]
	if value, ok := mapped.Get(name); ok {
		if f.ServerOnly {
			return nil, fmt.Errorf("sqlstore: protected account field %q", name)
		}
		return s.accountFieldParameter(name, value)
	}
	if f.Default == nil {
		if f.Required {
			return nil, &auth.APIError{Status: 400, Code: "MISSING_FIELD", Message: "Missing required account field " + name}
		}
		return nil, nil
	}
	value, err := f.CreationDefault()
	if err != nil {
		return nil, fmt.Errorf("sqlstore: invalid default for account field %q: %w", name, err)
	}
	return s.accountFieldParameter(name, value)
}

// insertAccount applies defaults to new accounts, including credentials established
// outside OAuth. Columns and parameter expressions are fixed at the call sites.
func (s *Store) insertAccount(ctx context.Context, tx *sql.Tx, columns, params string, args []any, mapped *auth.MappedAccountFields) error {
	for _, name := range sessionfields.Names(s.accountFields) {
		param, err := s.newAccountFieldParameter(name, mapped)
		if err != nil {
			return err
		}
		columns += `,"` + s.accountFields[name].Column + `"`
		params += ",?"
		args = append(args, param)
	}
	_, err := tx.ExecContext(ctx, s.bind(`INSERT INTO "account" (`+columns+`) VALUES (`+params+`)`), args...)
	return err
}

func (s *Store) insertPasswordAccount(ctx context.Context, tx *sql.Tx, owner, hash string, created, updated time.Time) error {
	return s.insertAccount(ctx, tx, `"id","userId","accountId","providerId","password","createdAt","updatedAt"`, "?,?,?,'credential',?,?,?",
		[]any{rand.Text(), owner, owner, hash, s.date(created), s.date(updated)}, nil)
}

func (s *Store) accountFieldUpdates(mapped *auth.MappedAccountFields) (string, []any, error) {
	if mapped == nil {
		return "", nil, nil
	}
	var columns []string
	var args []any
	for _, name := range sessionfields.Names(s.accountFields) {
		field := s.accountFields[name]
		if value, ok := mapped.Get(name); ok && !field.ServerOnly {
			param, err := s.accountFieldParameter(name, value)
			if err != nil {
				return "", nil, err
			}
			columns = append(columns, `,"`+field.Column+`"=?`)
			args = append(args, param)
		}
	}
	return strings.Join(columns, ""), args, nil
}
