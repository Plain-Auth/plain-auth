package sqlstore

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

func (s *Store) CheckLastLogin() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	rows, err := s.db.QueryContext(ctx, s.bind(`SELECT u."lastLoginMethod" FROM "user" u WHERE 1=0`))
	if err != nil {
		return errors.New("last-login-method: apply the last-login-method schema profile")
	}
	return rows.Close()
}

func (s *Store) SaveSessionLoginMethod(ctx context.Context, token, method string, now time.Time) error {
	_, err := s.db.ExecContext(ctx, s.bind(`UPDATE "user" SET "lastLoginMethod"=? WHERE "id"=(SELECT "userId" FROM "session" WHERE "token"=? AND "expiresAt">?)`), method, token, s.date(now))
	return err
}

func (s *Store) UserLoginMethod(ctx context.Context, id string) (string, error) {
	var method sql.NullString
	err := s.db.QueryRowContext(ctx, s.bind(`SELECT "lastLoginMethod" FROM "user" WHERE "id"=?`), id).Scan(&method)
	return method.String, err
}
