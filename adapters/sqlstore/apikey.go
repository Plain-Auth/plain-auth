package sqlstore

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"

	stonewrit "github.com/Stonewrit/stonewrit-auth"
	ak "github.com/Stonewrit/stonewrit-auth/plugins/apikey"
)

var _ ak.Store = (*Store)(nil)

const apiKeyFields = `"id","configId","referenceId","name","prefix","start","enabled","rateLimitEnabled","rateLimitTimeWindow","rateLimitMax","requestCount","remaining","refillInterval","refillAmount","lastRefillAt","lastRequest","expiresAt","createdAt","updatedAt","permissions","metadata"`

func (s *Store) CheckAPIKeySchema(ctx context.Context) error {
	rows, err := s.db.QueryContext(ctx, s.bind(`SELECT `+apiKeyFields+`,"key" FROM "apikey" WHERE 1=0`))
	if err != nil {
		return err
	}
	return rows.Close()
}
func (s *Store) cleanupAPIKeys(ctx context.Context, tx *sql.Tx, uid string) error {
	q := `SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='apikey')`
	switch s.dialect {
	case "mysql":
		q = `SELECT EXISTS(SELECT 1 FROM information_schema.tables WHERE table_schema=database() AND table_name='apikey')`
	case "postgres":
		q = `SELECT EXISTS(SELECT 1 FROM information_schema.tables WHERE table_schema=current_schema() AND table_name='apikey')`
	}
	var exists bool
	if err := tx.QueryRowContext(ctx, q).Scan(&exists); err != nil {
		return err
	}
	if !exists {
		return nil
	}
	_, err := tx.ExecContext(ctx, s.bind(`DELETE FROM "apikey" WHERE "referenceId"=?`), uid)
	return err
}
func (s *Store) apiKeyOwner(ctx context.Context, tx *sql.Tx, owner ak.Owner, now time.Time) error {
	if owner.UserID == "" {
		return ak.ErrSession
	}
	var err error
	switch {
	case owner.SessionToken != "":
		err = s.lockActiveAccount(ctx, tx, owner.UserID, owner.SessionToken, now)
	case s.adminSchema:
		err = s.adminSessionGate(ctx, tx, owner.UserID, now)
	default:
		err = s.lockAccount(ctx, tx, owner.UserID)
	}
	if errors.Is(err, stonewrit.ErrNotFound) {
		return ak.ErrSession
	}
	var api *stonewrit.APIError
	if errors.As(err, &api) && api.Code == "BANNED_USER" {
		return ak.ErrBanned
	}
	return err
}
func (s *Store) apiKeyDate(v *time.Time) any {
	if v == nil {
		return nil
	}
	return s.date(*v)
}
func apiJSON[T any](v map[string]T) (any, error) {
	if v == nil {
		return nil, nil
	}
	b, err := json.Marshal(v)
	return string(b), err
}
func (s *Store) keyValues(k ak.Key) ([]any, error) {
	p, err := apiJSON(k.Permissions)
	if err != nil {
		return nil, err
	}
	m, err := apiJSON(k.Metadata)
	if err != nil {
		return nil, err
	}
	return []any{k.ID, k.ConfigID, k.ReferenceID, k.Name, k.Prefix, k.Start, k.Enabled, k.RateLimitEnabled, k.RateLimitTimeWindow, k.RateLimitMax, k.RequestCount, k.Remaining, k.RefillInterval, k.RefillAmount, s.apiKeyDate(k.LastRefillAt), s.apiKeyDate(k.LastRequest), s.apiKeyDate(k.ExpiresAt), s.date(k.CreatedAt), s.date(k.UpdatedAt), p, m}, nil
}
func scanAPIKey(row rowScanner) (ak.Key, error) {
	var k ak.Key
	var enabled, rate sql.NullBool
	var count sql.NullInt64
	var permissions, metadata sql.NullString
	err := row.Scan(&k.ID, &k.ConfigID, &k.ReferenceID, &k.Name, &k.Prefix, &k.Start, &enabled, &rate, &k.RateLimitTimeWindow, &k.RateLimitMax, &count, &k.Remaining, &k.RefillInterval, &k.RefillAmount, &k.LastRefillAt, &k.LastRequest, &k.ExpiresAt, &k.CreatedAt, &k.UpdatedAt, &permissions, &metadata)
	if err != nil {
		return k, err
	}
	k.Enabled = !enabled.Valid || enabled.Bool
	k.RateLimitEnabled = !rate.Valid || rate.Bool
	k.RequestCount = count.Int64
	if permissions.Valid && permissions.String != "" {
		if err = json.Unmarshal([]byte(permissions.String), &k.Permissions); err != nil {
			return k, err
		}
	}
	if metadata.Valid && metadata.String != "" {
		raw := []byte(metadata.String)
		if len(raw) > 0 && raw[0] == '"' {
			var inner string
			if err = json.Unmarshal(raw, &inner); err != nil {
				return k, err
			}
			raw = []byte(inner)
		}
		if err = json.Unmarshal(raw, &k.Metadata); err != nil {
			return k, err
		}
	}
	return k, nil
}
func (s *Store) CreateAPIKey(ctx context.Context, owner ak.Owner, k ak.Key, digest string) error {
	if owner.UserID != k.ReferenceID || k.ID == "" || digest == "" {
		return ak.ErrSession
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err = s.apiKeyOwner(ctx, tx, owner, k.CreatedAt); err != nil {
		return err
	}
	args, err := s.keyValues(k)
	if err != nil {
		return err
	}
	args = append(args, digest)
	q := `INSERT INTO "apikey" (` + apiKeyFields + `,"key") VALUES (` + strings.TrimSuffix(strings.Repeat("?,", len(args)), ",") + `)`
	if _, err = tx.ExecContext(ctx, s.bind(q), args...); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) WithAPIKey(ctx context.Context, owner ak.Owner, l ak.Lookup, now time.Time, decide func(*ak.Key) (ak.Mutation, error)) error {
	if (l.ID == "") == (l.Digest == "") || l.ConfigID == "" {
		return ak.ErrMissing
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	value, field := l.ID, `"id"`
	if l.Digest != "" {
		value, field = l.Digest, `"key"`
	}
	parameter, _ := s.deviceTokenParameters([]string{value})
	where := field + `=` + parameter + ` AND "configId"=` + parameter
	if l.Digest != "" {
		// The canonical key-digest index is nonunique. Ambiguous imports fail
		// closed, including when different owners have the same stored digest.
		rows, err := tx.QueryContext(ctx, s.bind(`SELECT "referenceId" FROM "apikey" WHERE `+where+` LIMIT 2`), value, l.ConfigID)
		if err != nil {
			return err
		}
		if !rows.Next() {
			err = rows.Err()
			rows.Close()
			if err != nil {
				return err
			}
			return ak.ErrMissing
		}
		var id string
		err = rows.Scan(&id)
		more := rows.Next()
		if err == nil {
			err = rows.Err()
		}
		rows.Close()
		if err != nil {
			return err
		}
		if more {
			return ak.ErrMissing
		}
		owner = ak.Owner{UserID: id}
	}
	if err = s.apiKeyOwner(ctx, tx, owner, now); err != nil {
		if l.Digest != "" && errors.Is(err, ak.ErrSession) {
			return ak.ErrMissing
		}
		return err
	}
	where += ` AND "referenceId"=` + parameter
	k, err := scanAPIKey(tx.QueryRowContext(ctx, s.readForUpdate(`SELECT `+apiKeyFields+` FROM "apikey" WHERE `+where), value, l.ConfigID, owner.UserID))
	if errors.Is(err, sql.ErrNoRows) {
		return ak.ErrMissing
	}
	if err != nil {
		return err
	}
	id := k.ID
	action, err := decide(&k)
	if err != nil {
		return err
	}
	if k.ID != id || k.ReferenceID != owner.UserID || k.ConfigID != l.ConfigID {
		return ak.ErrMissing
	}
	switch action {
	case ak.Read:
	case ak.Save:
		vals, err := s.keyValues(k)
		if err != nil {
			return err
		}
		cols := strings.Split(apiKeyFields, ",")[3:]
		for i := range cols {
			cols[i] += "=?"
		}
		args := append(vals[3:], id, l.ConfigID, owner.UserID)
		_, err = tx.ExecContext(ctx, s.bind(`UPDATE "apikey" SET `+strings.Join(cols, ",")+` WHERE "id"=? AND "configId"=? AND "referenceId"=?`), args...)
		if err != nil {
			return err
		}
	case ak.Remove:
		_, err = tx.ExecContext(ctx, s.bind(`DELETE FROM "apikey" WHERE "id"=? AND "configId"=? AND "referenceId"=?`), id, l.ConfigID, owner.UserID)
		if err != nil {
			return err
		}
	default:
		return errors.New("invalid API key mutation")
	}
	return tx.Commit()
}
func (s *Store) ListAPIKeys(ctx context.Context, owner ak.Owner, config string, now time.Time, o ak.PageOptions) (ak.Page, error) {
	page := ak.Page{Keys: []ak.Key{}, Limit: o.Limit, Offset: o.Offset}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return page, err
	}
	defer tx.Rollback()
	if err = s.apiKeyOwner(ctx, tx, owner, now); err != nil {
		return page, err
	}
	parameter, _ := s.deviceTokenParameters([]string{config})
	where := ` FROM "apikey" WHERE "referenceId"=` + parameter + ` AND "configId"=` + parameter
	args := []any{owner.UserID, config}
	if err = tx.QueryRowContext(ctx, s.bind(`SELECT COUNT(*)`+where), args...).Scan(&page.Total); err != nil {
		return page, err
	}
	sort := o.SortBy
	if sort == "" {
		sort = "createdAt"
	}
	switch sort {
	case "id", "name", "expiresAt", "createdAt", "updatedAt", "remaining", "lastRequest", "requestCount", "enabled":
	default:
		return page, &stonewrit.APIError{Status: 400, Code: "VALIDATION_ERROR", Message: "Unsupported sort field"}
	}
	dir := "ASC"
	switch o.SortDirection {
	case "asc", "":
	case "desc":
		dir = "DESC"
	default:
		return page, &stonewrit.APIError{Status: 400, Code: "VALIDATION_ERROR", Message: "Unsupported sort direction"}
	}
	q := `SELECT ` + apiKeyFields + where + ` ORDER BY "` + sort + `" ` + dir + `,"id" ASC LIMIT ? OFFSET ?`
	limit, off := page.Total, 0
	if o.Limit != nil {
		limit = *o.Limit
	}
	if o.Offset != nil {
		off = *o.Offset
	}
	rows, err := tx.QueryContext(ctx, s.bind(q), append(args, limit, off)...)
	if err != nil {
		return page, err
	}
	for rows.Next() {
		k, e := scanAPIKey(rows)
		if e != nil {
			rows.Close()
			return page, e
		}
		page.Keys = append(page.Keys, k)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return page, err
	}
	return page, tx.Commit()
}
func (s *Store) DeleteExpiredAPIKeys(ctx context.Context, config string, now time.Time) (int64, error) {
	p, _ := s.deviceTokenParameters([]string{config})
	res, err := s.db.ExecContext(ctx, s.bind(`DELETE FROM "apikey" WHERE "configId"=`+p+` AND "expiresAt"<=?`), config, s.date(now))
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}
