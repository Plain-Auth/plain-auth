package sqlstore

import (
	"context"
	"database/sql"
	"strings"

	auth "github.com/FineStack/finestack-auth"
)

func (s *Store) ListUserAccounts(ctx context.Context, userID string) ([]auth.LinkedAccount, error) {
	rows, err := s.db.QueryContext(ctx, s.bind(`SELECT "id","accountId","providerId","userId","scope","createdAt","updatedAt" FROM "account" WHERE "userId"=? ORDER BY "createdAt","id"`), userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	accounts := []auth.LinkedAccount{}
	for rows.Next() {
		row := auth.LinkedAccount{Scopes: []string{}}
		var scope sql.NullString
		if err := rows.Scan(&row.ID, &row.AccountID, &row.ProviderID, &row.UserID, &scope, &row.CreatedAt, &row.UpdatedAt); err != nil {
			return nil, err
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
	return tx.Commit()
}
