package sqlstore

import (
	"context"
	"database/sql"
	"encoding/json"
	"slices"
	"time"
)

func (s *Store) deleteSessions(ctx context.Context, where string, args ...any) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := s.deleteSessionsTx(ctx, tx, where, args...); err != nil {
		return err
	}
	return tx.Commit()
}

// Lock the selected sessions before inspecting grants. A concurrent insert with
// a session foreign key must commit before this snapshot or lose its parent.
// Only delete the locked IDs, even if a new session now matches the predicate.
func (s *Store) deleteSessionsTx(ctx context.Context, tx *sql.Tx, where string, args ...any) (int64, error) {
	rows, err := tx.QueryContext(ctx, s.readForUpdate(`SELECT "id" FROM "session" WHERE `+where+` ORDER BY "id"`), args...)
	if err != nil {
		return 0, err
	}
	ids, err := scanStrings(rows)
	if err != nil || len(ids) == 0 {
		return 0, err
	}
	// Another process may have installed the provider since this store opened.
	installed, err := s.tableExists(ctx, tx, "oauthClient")
	if err != nil {
		return 0, err
	}
	now := time.Now().UTC()
	var deleted int64
	for batch := range slices.Chunk(ids, 400) {
		params, values := s.deviceTokenParameters(batch)
		if installed {
			if err := s.revokeSessionGrants(ctx, tx, params, values, now); err != nil {
				return 0, err
			}
		}
		result, err := tx.ExecContext(ctx, s.bind(`DELETE FROM "session" WHERE "id" IN (`+params+`)`), values...)
		if err != nil {
			return 0, err
		}
		n, err := result.RowsAffected()
		if err != nil {
			return 0, err
		}
		deleted += n
	}
	return deleted, nil
}

func (s *Store) revokeSessionGrants(ctx context.Context, tx *sql.Tx, params string, sessions []any, now time.Time) error {
	match := ` WHERE "sessionId" IN (` + params + `) AND "revoked" IS NULL`
	rows, err := tx.QueryContext(ctx, s.readForUpdate(`SELECT "id","scopes" FROM "oauthRefreshToken"`+match+` ORDER BY "id"`), sessions...)
	if err != nil {
		return err
	}
	defer rows.Close()
	var revoke []string
	for rows.Next() {
		var id string
		var raw []byte
		if err := rows.Scan(&id, &raw); err != nil {
			return err
		}
		var scopes []string
		if json.Unmarshal(raw, &scopes) != nil || !slices.Contains(scopes, "offline_access") {
			revoke = append(revoke, id)
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	for batch := range slices.Chunk(revoke, 400) {
		list, ids := s.deviceTokenParameters(batch)
		_, err := tx.ExecContext(ctx, s.bind(`UPDATE "oauthRefreshToken" SET "revoked"=? WHERE "id" IN (`+list+`)`), append([]any{s.date(now)}, ids...)...)
		if err != nil {
			return err
		}
	}
	_, err = tx.ExecContext(ctx, s.bind(`UPDATE "oauthAccessToken" SET "revoked"=?`+match), append([]any{s.date(now)}, sessions...)...)
	return err
}
