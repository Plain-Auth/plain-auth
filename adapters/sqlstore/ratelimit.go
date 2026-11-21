package sqlstore

import (
	"context"
	"crypto/rand"
	"errors"
	"time"
)

// ConsumeRateLimit serializes each key independently across database clients.
// The insert establishes a row even when two application replicas see the
// first request at the same time. Existing rows retain their window.
func (s *Store) ConsumeRateLimit(ctx context.Context, key string, maximum int, window time.Duration, now time.Time) (time.Duration, error) {
	if key == "" || maximum <= 0 || window < time.Millisecond {
		return 0, errors.New("sqlstore: invalid rate limit")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	const insert = `INSERT INTO "rateLimit" ("id","key","count","lastRequest") VALUES (?,?,0,0)`
	open := insert + ` ON CONFLICT ("key") DO NOTHING`
	if s.dialect == "mysql" {
		open = insert + ` ON DUPLICATE KEY UPDATE "id"="id"`
	}
	if _, err = tx.ExecContext(ctx, s.bind(open), rand.Text(), key); err != nil {
		return 0, err
	}
	var count int
	var last int64
	if err = tx.QueryRowContext(ctx, s.readForUpdate(`SELECT "count","lastRequest" FROM "rateLimit" WHERE "key"=?`), key).Scan(&count, &last); err != nil {
		return 0, err
	}
	// Concurrent callers need not acquire the row lock in arrival order.
	at := max(last, now.UnixMilli())
	elapsed := time.Duration(at-last) * time.Millisecond
	if elapsed >= window {
		count = 0
	}
	if count >= maximum {
		return window - elapsed, nil
	}
	if _, err = tx.ExecContext(ctx, s.bind(`UPDATE "rateLimit" SET "count"=?, "lastRequest"=? WHERE "key"=?`), count+1, at, key); err != nil {
		return 0, err
	}
	return 0, tx.Commit()
}

// PruneRateLimits removes counters last used before the cutoff. Choose a
// retention period longer than the longest window enforced by any replica.
func (s *Store) PruneRateLimits(ctx context.Context, cutoff time.Time) (int64, error) {
	result, err := s.db.ExecContext(ctx, s.bind(`DELETE FROM "rateLimit" WHERE "lastRequest"<?`), cutoff.UnixMilli())
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}
