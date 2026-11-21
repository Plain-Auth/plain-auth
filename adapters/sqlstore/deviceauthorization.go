package sqlstore

import (
	"context"
	"database/sql"
	"errors"
	"time"

	authn "github.com/FineStack/finestack-auth"
)

var _ authn.DeviceAuthorizationStore = (*Store)(nil)

const deviceGrantFields = `"id","deviceCode","userCode","userId","clientId","scope","status","expiresAt","lastPolledAt","pollingInterval"`

func (s *Store) CheckDeviceSchema(ctx context.Context) error {
	rows, err := s.db.QueryContext(ctx, s.bind(`SELECT `+deviceGrantFields+` FROM "deviceCode" WHERE 1=0`))
	if err != nil {
		return err
	}
	return rows.Close()
}

func (s *Store) CreateDeviceGrant(ctx context.Context, g authn.DeviceGrant) (bool, error) {
	_, err := s.db.ExecContext(ctx, s.bind(`INSERT INTO "deviceCode" (`+deviceGrantFields+`) VALUES (?,?,?,NULLIF(?,''),?,NULLIF(?,''),?,?,NULL,?)`), g.ID, g.DeviceCode, g.UserCode, g.UserID, g.ClientID, g.Scope, g.Status, s.date(g.ExpiresAt), g.Interval.Milliseconds())
	if duplicateConstraint(err) {
		return false, nil
	}
	return err == nil, err
}

type deviceRow struct {
	authn.DeviceGrant
	lastPoll    sql.NullTime
	oauthClient sql.NullString
}

func getDeviceGrant(ctx context.Context, s *Store, tx *sql.Tx, byUser bool, code string) (deviceRow, error) {
	var row deviceRow
	var user, client, scope sql.NullString
	var interval sql.NullInt64
	field := `"deviceCode"`
	if byUser {
		field = `"userCode"`
	}
	// Read the optional OAuth client binding too when a deployment shares this
	// table with an authorization server. Its grants cannot issue local sessions.
	columnsSQL := "*"
	if s.dialect == "postgres" {
		// Keep a stable prepared-result shape if a running deployment adds
		// optional grant columns. Missing JSON keys read as NULL.
		columnsSQL = deviceGrantFields + `,to_jsonb(d)->>'oauthClientId' AS "oauthClientId"`
	}
	q := s.readForUpdate(`SELECT ` + columnsSQL + ` FROM "deviceCode" d WHERE ` + field + `=?`)
	rows, err := tx.QueryContext(ctx, q, code)
	if err != nil {
		return row, err
	}
	defer rows.Close()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return row, err
		}
		return row, sql.ErrNoRows
	}
	columns, err := rows.Columns()
	if err != nil {
		return row, err
	}
	fields := map[string]any{"id": &row.ID, "deviceCode": &row.DeviceCode, "userCode": &row.UserCode, "userId": &user, "clientId": &client, "scope": &scope, "status": &row.Status, "expiresAt": &row.ExpiresAt, "lastPolledAt": &row.lastPoll, "pollingInterval": &interval, "oauthClientId": &row.oauthClient}
	dest := make([]any, len(columns))
	for i, name := range columns {
		dest[i] = fields[name]
		if dest[i] == nil {
			dest[i] = new(any)
		}
	}
	err = rows.Scan(dest...)
	if err != nil {
		return row, err
	}
	// Some MySQL collations fold case or accents on indexed lookups.
	if byUser && row.UserCode != code || !byUser && row.DeviceCode != code {
		return row, sql.ErrNoRows
	}
	row.UserID, row.ClientID, row.Scope = user.String, client.String, scope.String
	row.Interval = time.Duration(interval.Int64) * time.Millisecond
	return row, nil
}

func (s *Store) ReviewDeviceGrant(ctx context.Context, in authn.DeviceReview) (authn.DeviceGrant, string, error) {
	var empty authn.DeviceGrant
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return empty, "", err
	}
	defer tx.Rollback()
	row, err := getDeviceGrant(ctx, s, tx, true, in.Code)
	if errors.Is(err, sql.ErrNoRows) && in.NormalizedCode != "" && in.NormalizedCode != in.Code {
		row, err = getDeviceGrant(ctx, s, tx, true, in.NormalizedCode)
	}
	if errors.Is(err, sql.ErrNoRows) {
		return empty, "invalid_user_code", nil
	}
	if err != nil {
		return empty, "", err
	}
	if row.oauthClient.Valid {
		return empty, "external_grant", nil
	}
	if !row.ExpiresAt.After(in.Now) {
		return empty, "expired_user_code", nil
	}
	if in.UserID != "" {
		err = s.lockActiveAccount(ctx, tx, in.UserID, in.SessionToken, in.Now)
		if errors.Is(err, authn.ErrNotFound) {
			return empty, "unauthorized", nil
		}
		if err != nil {
			return empty, "", err
		}
	}
	switch in.Action {
	case "review":
		if in.UserID != "" && row.UserID == "" && row.Status == "pending" {
			_, err = tx.ExecContext(ctx, s.bind(`UPDATE "deviceCode" SET "userId"=? WHERE "id"=?`), in.UserID, row.ID)
			row.UserID = in.UserID
		}
	case "approve", "deny":
		switch {
		case in.UserID == "":
			return empty, "unauthorized", nil
		case row.Status != "pending":
			return empty, "processed", nil
		case row.UserID == "":
			return empty, "unclaimed", nil
		case row.UserID != in.UserID:
			return empty, "forbidden", nil
		}
		row.Status = "approved"
		if in.Action == "deny" {
			row.Status = "denied"
		}
		_, err = tx.ExecContext(ctx, s.bind(`UPDATE "deviceCode" SET "status"=? WHERE "id"=?`), row.Status, row.ID)
	default:
		return empty, "", errors.New("sqlstore: unknown device grant decision")
	}
	if err != nil {
		return empty, "", err
	}
	return row.DeviceGrant, "", tx.Commit()
}

func (s *Store) PollDeviceGrant(ctx context.Context, code, clientID string, session authn.StoredSession) (string, string, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return "", "", err
	}
	defer tx.Rollback()
	row, err := getDeviceGrant(ctx, s, tx, false, code)
	if errors.Is(err, sql.ErrNoRows) {
		return "", "invalid_grant", nil
	}
	if err != nil {
		return "", "", err
	}
	if row.oauthClient.Valid {
		return "", "external_grant", nil
	}
	if row.ClientID != clientID {
		return "", "different_client", nil
	}
	now := session.CreatedAt
	outcome := ""
	switch {
	case !row.ExpiresAt.After(now):
		outcome = "expired_token"
	case row.lastPoll.Valid && now.Sub(row.lastPoll.Time) < row.Interval:
		return "", "slow_down", nil
	case row.Status == "pending":
		_, err = tx.ExecContext(ctx, s.bind(`UPDATE "deviceCode" SET "lastPolledAt"=? WHERE "id"=?`), s.date(now), row.ID)
		if err != nil {
			return "", "", err
		}
		return "", "authorization_pending", tx.Commit()
	case row.Status == "denied":
		outcome = "access_denied"
	case row.Status == "approved" && row.UserID != "":
		if err = s.lockAccount(ctx, tx, row.UserID); errors.Is(err, authn.ErrNotFound) {
			outcome = "invalid_grant"
		} else if err != nil {
			return "", "", err
		} else {
			session.UserID = row.UserID
			if err = s.insertSession(ctx, tx, session); err != nil {
				return "", "", err
			}
		}
	default:
		return "", "invalid_status", nil
	}
	_, err = tx.ExecContext(ctx, s.bind(`DELETE FROM "deviceCode" WHERE "id"=?`), row.ID)
	if err != nil {
		return "", "", err
	}
	return row.Scope, outcome, tx.Commit()
}
