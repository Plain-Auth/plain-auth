package sqlstore

import (
	"context"
	"database/sql"
	"strings"

	auth "github.com/Plain-Org/plain-auth"
	"github.com/Plain-Org/plain-auth/internal/sessionfields"
)

func (s *Store) ListUserAccounts(ctx context.Context, userID string) ([]auth.LinkedAccount, error) {
	columns := `"id","accountId","providerId","userId","scope","createdAt","updatedAt"`
	var visible []string
	for _, name := range sessionfields.Names(s.accountFields) {
		f := s.accountFields[name]
		if !f.Hidden {
			columns += `,"` + f.Column + `"`
			visible = append(visible, name)
		}
	}
	query := `SELECT ` + columns + ` FROM "account" WHERE ` + s.exactSQLValue(`"userId"`) + `=? ORDER BY "createdAt","id"`
	rows, err := s.db.QueryContext(ctx, s.bind(query), userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	accounts := []auth.LinkedAccount{}
	for rows.Next() {
		row := auth.LinkedAccount{Scopes: []string{}}
		var scope sql.NullString
		dest := []any{&row.ID, &row.AccountID, &row.ProviderID, &row.UserID, &scope, &row.CreatedAt, &row.UpdatedAt}
		coreCount := len(dest)
		for _, name := range visible {
			dest = append(dest, scalarDestination(s.accountFields[name].Type))
		}
		if err := rows.Scan(dest...); err != nil {
			return nil, err
		}
		if len(visible) > 0 {
			row.AdditionalFields = make(map[string]any, len(visible))
			for i, name := range visible {
				value, err := s.accountFields[name].PublicValue(scannedScalar(dest[coreCount+i]))
				if err != nil {
					return nil, err
				}
				row.AdditionalFields[name] = value
			}
		}
		for field := range strings.SplitSeq(scope.String, ",") {
			if v := strings.TrimSpace(field); v != "" {
				row.Scopes = append(row.Scopes, v)
			}
		}
		accounts = append(accounts, row)
	}
	return accounts, rows.Err()
}

func (s *Store) UnlinkAccount(ctx context.Context, userID, id string, allowLast bool) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := s.lockAccount(ctx, tx, userID); err != nil {
		return err
	}
	if !allowLast {
		var count int
		if err := tx.QueryRowContext(ctx, s.bind(`SELECT COUNT(*) FROM "account" WHERE "userId"=?`), userID).Scan(&count); err != nil {
			return err
		}
		if count == 1 {
			return auth.ErrLastAccount
		}
	}
	if err := s.unlinkWallet(ctx, tx, userID, id); err != nil {
		return err
	}
	result, err := tx.ExecContext(ctx, s.bind(`DELETE FROM "account" WHERE "id"=? AND "userId"=?`), id, userID)
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return auth.ErrNotFound
	}
	_, err = tx.ExecContext(ctx, s.bind(`DELETE FROM "verification" WHERE "id"=? AND "identifier"=?`), sourceID(id), sourceOwner(userID))
	if err != nil {
		return err
	}
	return tx.Commit()
}
