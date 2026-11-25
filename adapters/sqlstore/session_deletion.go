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

// deleteSessionsTx ends the sessions matching where: it deletes their rows,
// or with PreserveSessionInDatabase marks the live ones ended and keeps them.
func (s *Store) deleteSessionsTx(ctx context.Context, tx *sql.Tx, where string, args ...any) (int64, error) {
	return s.endSessionsTx(ctx, tx, s.sessionMirror().preserving(), where, args...)
}

// removeSessionsTx deletes the rows of the sessions matching where, ended
// ones included, even when ended sessions are preserved. Deleting a user
// uses it.
func (s *Store) removeSessionsTx(ctx context.Context, tx *sql.Tx, where string, args ...any) (int64, error) {
	return s.endSessionsTx(ctx, tx, false, where, args...)
}

// endedSessionExpiry is the expiresAt of a row kept after its session
// ended, with PreserveSessionInDatabase: a fixed time long past, so no
// clock, however far behind, compares the row as live. The row's updatedAt
// records the end. Writing the end time instead would let a request that
// read its clock before the end, and then waited for these row locks, or a
// replica whose clock lags, still see the row as live.
var endedSessionExpiry = time.Unix(86400, 0).UTC()

// sessionEnded reports a row kept after its session ended.
func sessionEnded(expiresAt time.Time) bool {
	return !expiresAt.After(endedSessionExpiry)
}

// Lock the selected sessions before inspecting grants. A concurrent insert with
// a session foreign key must commit before this snapshot or lose its parent.
// Only end the locked IDs, even if a new session now matches the predicate.
// With preserve, rows that already ended are left as they are; the choice
// reads no clock, so a session close to its natural expiry still ends.
func (s *Store) endSessionsTx(ctx context.Context, tx *sql.Tx, preserve bool, where string, args ...any) (int64, error) {
	query := `SELECT "id","token","expiresAt" FROM "session" WHERE ` + where
	if preserve {
		query = `SELECT "id","token","expiresAt" FROM "session" WHERE (` + where + `) AND "expiresAt">?`
		args = append(slices.Clip(args), s.date(endedSessionExpiry))
	}
	rows, err := tx.QueryContext(ctx, s.readForUpdate(query+` ORDER BY "id"`), args...)
	if err != nil {
		return 0, err
	}
	var ids, tokens []string
	for rows.Next() {
		var id, token string
		var expires time.Time
		if err := rows.Scan(&id, &token, &expires); err != nil {
			rows.Close()
			return 0, err
		}
		ids = append(ids, id)
		// An ended session's copy went when it ended.
		if !sessionEnded(expires) {
			tokens = append(tokens, token)
		}
	}
	if err := rows.Close(); err != nil {
		return 0, err
	}
	if err := rows.Err(); err != nil || len(ids) == 0 {
		return 0, err
	}
	// The locked sessions' copies go first: a failed delete keeps them all.
	if err := s.sessionMirror().forget(ctx, tokens); err != nil {
		return 0, err
	}
	// Another process may have installed the provider since this store opened.
	installed, err := s.tableExists(ctx, tx, "oauthClient")
	if err != nil {
		return 0, err
	}
	now := time.Now().UTC()
	var ended int64
	for batch := range slices.Chunk(ids, 400) {
		params, values := s.deviceTokenParameters(batch)
		if installed {
			if err := s.revokeSessionGrants(ctx, tx, params, values, now); err != nil {
				return 0, err
			}
		}
		var result sql.Result
		if preserve {
			result, err = tx.ExecContext(ctx, s.bind(`UPDATE "session" SET "expiresAt"=?,"updatedAt"=? WHERE "id" IN (`+params+`)`), append([]any{s.date(endedSessionExpiry), s.date(now)}, values...)...)
		} else {
			result, err = tx.ExecContext(ctx, s.bind(`DELETE FROM "session" WHERE "id" IN (`+params+`)`), values...)
		}
		if err != nil {
			return 0, err
		}
		n, err := result.RowsAffected()
		if err != nil {
			return 0, err
		}
		ended += n
	}
	return ended, nil
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
